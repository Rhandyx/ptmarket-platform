//! Resolução do tenant a partir do `Host` (único sítio que cria `TenantId`), com cache em memória.
//!
//! `SELECT ... FROM tenants WHERE custom_domain = $1 AND is_active` na réplica. Cache: 60 s para
//! hosts conhecidos, 10 s para desconhecidos, no máximo 10 000 entradas (sem dependência nova:
//! `HashMap` + `Mutex`, nunca seguro durante um `await`). Os desconhecidos têm um teto próprio
//! (2 000): um flood de hosts aleatórios esvazia só esse lado e nunca expulsa os tenants. Um
//! tenant expirado fica guardado até `MAX_STALE` a mais ("stale"): só serve quando não se pode
//! consultar (cliente limitado, Redis ou BD em baixo, sem lugar no semáforo), para uma Câmara
//! válida atrás de um IP partilhado (CGNAT, borda) não ficar sem resposta.
//!
//! Fora da cache (um acerto nunca toca no Redis nem na BD):
//! 1. Travão por cliente (com `with_miss_limit`): um script Lua reserva atomicamente uma vaga em
//!    `host:miss:<ip>` (IPv4 inteiro ou IPv6 /64; `MAX_UNKNOWN_HOSTS`) e, em IPv6, também em
//!    `host:miss:<ip6>/48` (`MAX_UNKNOWN_HOSTS_48`), ANTES do SELECT; sem vaga → limitado (429),
//!    sem consulta. Uma rajada em paralelo nunca passa do limite. Se o host for um tenant válido
//!    (ou a BD falhar), a vaga é devolvida: um tenant válido nunca gasta o limite. Janela de 60 s
//!    desde a 1.ª reserva.
//! 2. Redis indisponível → 503 (decisão do owner: falha fechada) com um `warn` (no máximo um por
//!    10 s; sem o host, o IP nem o erro). Sem IP do cliente (servidor sem `ConnectInfo`; o binário
//!    tem-no sempre) não há contador.
//! 3. Semáforo global (`MAX_CONCURRENT_LOOKUPS`) para os SELECT; sem lugar → 503 com
//!    `Retry-After` curto, sem esperar.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, Uri};
use deadpool_redis::redis;
use secrecy::SecretString;
use sqlx::PgPool;
use tokio::sync::Semaphore;

use crate::{
    error::AppError,
    http::client_ip::{TrustedProxies, client_ip, ip_bucket, ip_bucket_48},
    tenancy::{
        TenantId,
        db::db_error,
        host::{effective_host, normalize_host},
    },
};

/// Validade de um host conhecido em cache.
pub const POSITIVE_TTL: Duration = Duration::from_secs(60);
/// Validade de um host desconhecido (ou tenant inativo) em cache.
pub const NEGATIVE_TTL: Duration = Duration::from_secs(10);
/// Quanto tempo, depois de expirar, um tenant ainda pode ser servido "stale" (só sem consulta).
pub const MAX_STALE: Duration = Duration::from_secs(3600);
/// Máximo de entradas em cache (conhecidos + desconhecidos).
pub const MAX_ENTRIES: usize = 10_000;
/// Parte do máximo reservada a desconhecidos.
pub const MAX_NEGATIVE: usize = 2_000;
const MAX_POSITIVE: usize = MAX_ENTRIES - MAX_NEGATIVE;
/// Hosts desconhecidos (fora da cache) por cliente (IPv4 ou IPv6 /64) e por janela.
pub const MAX_UNKNOWN_HOSTS: i64 = 30;
/// O mesmo, por IPv6 /48 (quem roda /64 dentro do seu /48): 10× o do /64.
pub const MAX_UNKNOWN_HOSTS_48: i64 = 10 * MAX_UNKNOWN_HOSTS;
/// Janela dos contadores de hosts desconhecidos (TTL da chave, desde a 1.ª reserva).
pub const UNKNOWN_HOSTS_WINDOW: Duration = Duration::from_secs(60);
/// SELECT de hosts fora da cache em simultâneo (todas as ligações); sem lugar → 503.
pub const MAX_CONCURRENT_LOOKUPS: usize = 16;
/// Prefixo das chaves Redis dos contadores (seguido de `ip_bucket`/`ip_bucket_48`).
const MISS_KEY: &str = "host:miss:";
/// Limite para cada operação no Redis neste caminho; passado isto, indisponível (503).
const MISS_REDIS_TIMEOUT: Duration = Duration::from_millis(250);
/// No máximo um `warn` de Redis indisponível por este intervalo (um flood não inunda os logs).
const MISS_WARN_EVERY: Duration = Duration::from_secs(10);

/// Reserva atómica. KEYS: contadores (1 ou 2) · ARGV: janela_ms, limite de cada chave.
/// `{1, 0}` = reservado (todas as chaves +1); `{0, ms}` = sem vaga (nada muda), `ms` até a chave
/// esgotada abrir.
const MISS_RESERVE_SCRIPT: &str = r"
local full = false
local wait = 0
for i, k in ipairs(KEYS) do
  local n = tonumber(redis.call('GET', k) or '0')
  if n >= tonumber(ARGV[i + 1]) then
    full = true
    local t = redis.call('PTTL', k)
    if t > wait then wait = t end
  end
end
if full then return {0, wait} end
for _, k in ipairs(KEYS) do
  redis.call('INCR', k)
  if redis.call('PTTL', k) < 0 then redis.call('PEXPIRE', k, ARGV[1]) end
end
return {1, 0}
";
/// Devolve uma vaga (host era um tenant válido, ou a BD falhou). KEYS: os mesmos contadores.
const MISS_RELEASE_SCRIPT: &str = r"
for _, k in ipairs(KEYS) do
  if redis.call('EXISTS', k) == 1 then
    if redis.call('DECR', k) <= 0 then redis.call('DEL', k) end
  end
end
return 1
";

/// `tenants.tenant_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantType {
    Municipal,
    NationalPortal,
    Niche,
}

impl TenantType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Municipal => "municipal",
            Self::NationalPortal => "national_portal",
            Self::Niche => "niche",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "municipal" => Ok(Self::Municipal),
            "national_portal" => Ok(Self::NationalPortal),
            "niche" => Ok(Self::Niche),
            _ => Err(AppError::Internal(anyhow::anyhow!(
                "tenants.tenant_type desconhecido"
            ))),
        }
    }
}

/// `tenants.country_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, utoipa::ToSchema)]
pub enum CountryCode {
    #[serde(rename = "PT")]
    Pt,
    #[serde(rename = "ES")]
    Es,
}

impl CountryCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pt => "PT",
            Self::Es => "ES",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self, AppError> {
        match s {
            "PT" => Ok(Self::Pt),
            "ES" => Ok(Self::Es),
            _ => Err(AppError::Internal(anyhow::anyhow!(
                "tenants.country_code desconhecido"
            ))),
        }
    }
}

/// Tenant resolvido pelo `Host`. Só o resolver o cria (fora do crate, só `for_tests`); como
/// extractor Axum recusa com 404 tudo o que não seja um tenant (ver `tenancy::http`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedTenant {
    id: TenantId,
    tenant_type: TenantType,
    country_code: CountryCode,
}

impl ResolvedTenant {
    pub fn id(&self) -> TenantId {
        self.id
    }

    pub fn tenant_type(&self) -> TenantType {
        self.tenant_type
    }

    pub fn country_code(&self) -> CountryCode {
        self.country_code
    }

    /// Só para testes de integração (`tests/`); não existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn for_tests(id: TenantId, tenant_type: TenantType, country_code: CountryCode) -> Self {
        Self {
            id,
            tenant_type,
            country_code,
        }
    }
}

/// O que o `Host` do pedido decidiu. Posto nas extensões do pedido pela layer de `tenancy::http`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedHost {
    /// Domínio de um tenant ativo.
    Tenant(ResolvedTenant),
    /// `PLATFORM_ADMIN_HOST` (sem tenant).
    Platform,
    /// Host inválido, repetido, desconhecido ou de tenant inativo (→ 404 genérico).
    Unknown,
    /// A BD não respondeu (→ 503; nada fica em cache).
    Unavailable,
}

/// O host não se pôde resolver sem consulta e a consulta não foi feita. Posta nas extensões do
/// pedido (com `ResolvedHost::Unknown`) pela layer de `tenancy::http`; os extractores recusam por
/// dentro da caixa negra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostThrottle {
    /// O cliente já esgotou os hosts desconhecidos desta janela → 429 + `Retry-After` (≥ 1 s).
    Limited { retry_after_s: u64 },
    /// Sem lugar no semáforo de consultas → 503 + `Retry-After` curto.
    Busy,
}

/// Cache dos dois lados, com o instante de cada entrada.
#[derive(Debug, Default)]
struct Cache {
    positive: HashMap<String, (Instant, ResolvedTenant)>,
    negative: HashMap<String, Instant>,
}

/// Resultado em cache: `Some(Some(t))` conhecido, `Some(None)` desconhecido, `None` sem entrada.
type Cached = Option<Option<ResolvedTenant>>;

impl Cache {
    /// Só entradas válidas. Um tenant expirado fica (stale) até `MAX_STALE` a mais.
    fn get(&mut self, host: &str, now: Instant) -> Cached {
        if let Some((at, t)) = self.positive.get(host).copied() {
            let age = now.saturating_duration_since(at);
            if age < POSITIVE_TTL {
                return Some(Some(t));
            }
            if age >= POSITIVE_TTL + MAX_STALE {
                self.positive.remove(host);
            }
        }
        if let Some(at) = self.negative.get(host).copied() {
            if now.saturating_duration_since(at) < NEGATIVE_TTL {
                return Some(None);
            }
            self.negative.remove(host);
        }
        None
    }

    /// Tenant expirado há menos de `MAX_STALE` (só para quando não se pode consultar).
    fn stale(&self, host: &str, now: Instant) -> Option<ResolvedTenant> {
        self.positive
            .get(host)
            .filter(|(at, _)| now.saturating_duration_since(*at) < POSITIVE_TTL + MAX_STALE)
            .map(|(_, t)| *t)
    }

    fn put(&mut self, host: String, value: Option<ResolvedTenant>, now: Instant) {
        match value {
            Some(t) => {
                self.negative.remove(&host);
                if self.positive.len() >= MAX_POSITIVE && !self.positive.contains_key(&host) {
                    // Cheio: saem primeiro as expiradas (também as stale).
                    self.positive
                        .retain(|_, (at, _)| now.saturating_duration_since(*at) < POSITIVE_TTL);
                    if self.positive.len() >= MAX_POSITIVE {
                        // Cheio de entradas válidas: não se guarda (a próxima vai à BD).
                        return;
                    }
                }
                self.positive.insert(host, (now, t));
            }
            None => {
                self.positive.remove(&host);
                if self.negative.len() >= MAX_NEGATIVE && !self.negative.contains_key(&host) {
                    self.negative
                        .retain(|_, at| now.saturating_duration_since(*at) < NEGATIVE_TTL);
                    if self.negative.len() >= MAX_NEGATIVE {
                        // Flood de hosts desconhecidos: esvazia só este lado.
                        self.negative.clear();
                    }
                }
                self.negative.insert(host, now);
            }
        }
    }

    fn len(&self) -> usize {
        self.positive.len() + self.negative.len()
    }
}

/// Resultado da procura de um host já normalizado.
enum Lookup {
    Found(Option<ResolvedTenant>),
    Throttled(HostThrottle),
    /// Redis ou BD em baixo e sem entrada stale → 503.
    Unavailable,
}

/// Reserva no Redis.
enum Reservation {
    Reserved,
    Full { retry_after_s: u64 },
    RedisDown,
}

/// Contadores de hosts desconhecidos por cliente (Redis).
struct MissLimiter {
    redis: deadpool_redis::Pool,
    trusted: TrustedProxies,
    /// Prefixo das chaves Redis: vazio em produção; só os testes o mudam (isolamento).
    ns: String,
    last_warn: Mutex<Option<Instant>>,
}

impl std::fmt::Debug for MissLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MissLimiter").finish_non_exhaustive()
    }
}

impl MissLimiter {
    /// (chave, limite) de cada contador do cliente: o IP (v4) ou /64, e em IPv6 também o /48.
    fn keys(&self, client: IpAddr) -> Vec<(String, i64)> {
        let mut keys = vec![(
            format!("{}{MISS_KEY}{}", self.ns, ip_bucket(Some(client))),
            MAX_UNKNOWN_HOSTS,
        )];
        if let Some(b48) = ip_bucket_48(client) {
            keys.push((format!("{}{MISS_KEY}{b48}", self.ns), MAX_UNKNOWN_HOSTS_48));
        }
        keys
    }

    async fn eval<T: redis::FromRedisValue>(&self, cmd: redis::Cmd) -> Option<T> {
        let fut = async {
            let mut conn = self.redis.get().await.ok()?;
            cmd.query_async::<T>(&mut conn).await.ok()
        };
        let out = tokio::time::timeout(MISS_REDIS_TIMEOUT, fut)
            .await
            .ok()
            .flatten();
        if out.is_none() {
            self.warn_unavailable();
        }
        out
    }

    /// Reserva atómica de uma vaga em todos os contadores do cliente, antes do SELECT.
    async fn reserve(&self, client: IpAddr) -> Reservation {
        let keys = self.keys(client);
        let window_ms = u64::try_from(UNKNOWN_HOSTS_WINDOW.as_millis()).unwrap_or(u64::MAX);
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(MISS_RESERVE_SCRIPT).arg(keys.len());
        for (k, _) in &keys {
            cmd.arg(k);
        }
        cmd.arg(window_ms);
        for (_, limit) in &keys {
            cmd.arg(*limit);
        }
        match self.eval::<(i64, i64)>(cmd).await {
            Some((1, _)) => Reservation::Reserved,
            Some((_, pttl_ms)) => Reservation::Full {
                retry_after_s: retry_after_s(pttl_ms),
            },
            None => Reservation::RedisDown,
        }
    }

    /// Devolve a vaga (o host era um tenant válido, ou a consulta não chegou a dar resposta).
    async fn release(&self, client: IpAddr) {
        let keys = self.keys(client);
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(MISS_RELEASE_SCRIPT).arg(keys.len());
        for (k, _) in &keys {
            cmd.arg(k);
        }
        let _: Option<i64> = self.eval(cmd).await;
    }

    /// Sem o host, o IP nem o erro (o erro do cliente Redis pode levar o endereço do servidor).
    fn warn_unavailable(&self) {
        let now = Instant::now();
        let mut last = self
            .last_warn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_some_and(|at| now.saturating_duration_since(at) < MISS_WARN_EVERY) {
            return;
        }
        *last = Some(now);
        drop(last);
        tracing::warn!(
            "limite de hosts desconhecidos: Redis indisponível; hosts fora da cache recusados (503)"
        );
    }
}

/// `Retry-After` a partir do tempo que falta na janela (arredondado para cima, ≥ 1; sem TTL
/// conhecido, a janela inteira).
fn retry_after_s(pttl_ms: i64) -> u64 {
    match u64::try_from(pttl_ms) {
        Ok(ms) if ms > 0 => ms.div_ceil(1000).max(1),
        _ => UNKNOWN_HOSTS_WINDOW.as_secs(),
    }
}

/// Resolve o `Host` de cada pedido. Vive no `AppState` (partilhado entre pedidos).
#[derive(Debug)]
pub struct HostResolver {
    db_replica: PgPool,
    platform_host: Option<String>,
    internal_token: Option<SecretString>,
    cache: Mutex<Cache>,
    limiter: Option<MissLimiter>,
    lookups: AtomicU64,
    lookup_slots: Semaphore,
}

impl HostResolver {
    /// `platform_host` já normalizado (validado em `Config`); `internal_token` com ≥ 32 bytes.
    pub fn new(
        db_replica: PgPool,
        platform_host: Option<String>,
        internal_token: Option<SecretString>,
    ) -> Self {
        Self {
            db_replica,
            platform_host: platform_host.and_then(|h| normalize_host(&h)),
            internal_token,
            cache: Mutex::new(Cache::default()),
            limiter: None,
            lookups: AtomicU64::new(0),
            lookup_slots: Semaphore::new(MAX_CONCURRENT_LOOKUPS),
        }
    }

    /// Liga o travão a hosts desconhecidos (contadores `host:miss:*` no Redis). `trusted`: os
    /// proxies de confiança, para o IP do cliente (os mesmos da caixa negra).
    #[must_use]
    pub fn with_miss_limit(self, redis: deadpool_redis::Pool, trusted: TrustedProxies) -> Self {
        self.miss_limit(redis, trusted, String::new())
    }

    /// Só para testes: o mesmo travão com um prefixo próprio nas chaves Redis. Não existe em
    /// `cargo build --release`.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn with_miss_limit_for_tests(
        self,
        redis: deadpool_redis::Pool,
        trusted: TrustedProxies,
        namespace: &str,
    ) -> Self {
        self.miss_limit(redis, trusted, namespace.to_owned())
    }

    fn miss_limit(
        mut self,
        redis: deadpool_redis::Pool,
        trusted: TrustedProxies,
        ns: String,
    ) -> Self {
        self.limiter = Some(MissLimiter {
            redis,
            trusted,
            ns,
            last_warn: Mutex::new(None),
        });
        self
    }

    /// Decide o host do pedido (só `Host`, ou `X-Forwarded-Host` com token interno válido).
    /// `peer`: o peer TCP (`ConnectInfo`), para o IP do cliente do travão. `Err` = a consulta não
    /// foi feita (limitado ou sem lugar).
    pub async fn resolve(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
        peer: Option<IpAddr>,
    ) -> Result<ResolvedHost, HostThrottle> {
        let Some(host) = effective_host(headers, uri, self.internal_token.as_ref()) else {
            return Ok(ResolvedHost::Unknown);
        };
        if self.platform_host.as_deref() == Some(host.as_str()) {
            return Ok(ResolvedHost::Platform);
        }
        let client = self
            .limiter
            .as_ref()
            .and_then(|l| client_ip(peer, headers, &l.trusted).map(|ip| (l, ip)));
        match self.lookup(host, client).await {
            Lookup::Found(Some(t)) => Ok(ResolvedHost::Tenant(t)),
            Lookup::Found(None) => Ok(ResolvedHost::Unknown),
            Lookup::Throttled(t) => Err(t),
            Lookup::Unavailable => Ok(ResolvedHost::Unavailable),
        }
    }

    /// Host já normalizado → tenant ativo (cache primeiro; fora da cache, reserva no travão do
    /// cliente, lugar no semáforo e só então o SELECT). Sem consulta possível: a entrada stale,
    /// se houver.
    async fn lookup(&self, host: String, client: Option<(&MissLimiter, IpAddr)>) -> Lookup {
        if let Some(hit) = self.cache().get(&host, Instant::now()) {
            return Lookup::Found(hit);
        }
        let stale_or = |fallback: Lookup| match self.cache().stale(&host, Instant::now()) {
            Some(t) => Lookup::Found(Some(t)),
            None => fallback,
        };
        if let Some((limiter, ip)) = client {
            match limiter.reserve(ip).await {
                Reservation::Reserved => {}
                Reservation::Full { retry_after_s } => {
                    return stale_or(Lookup::Throttled(HostThrottle::Limited { retry_after_s }));
                }
                Reservation::RedisDown => return stale_or(Lookup::Unavailable),
            }
        }
        let release = || async {
            if let Some((limiter, ip)) = client {
                limiter.release(ip).await;
            }
        };
        let Ok(_slot) = self.lookup_slots.try_acquire() else {
            release().await;
            return stale_or(Lookup::Throttled(HostThrottle::Busy));
        };
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let value = match self.select(&host).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = ?e, "resolução do host: BD indisponível");
                release().await;
                return stale_or(Lookup::Unavailable);
            }
        };
        self.cache().put(host, value, Instant::now());
        if value.is_some() {
            // Um tenant válido nunca gasta o limite.
            release().await;
        }
        Lookup::Found(value)
    }

    async fn select(&self, host: &str) -> Result<Option<ResolvedTenant>, AppError> {
        let row = sqlx::query!(
            "SELECT id, tenant_type, country_code FROM tenants
             WHERE custom_domain = $1 AND is_active",
            host
        )
        .fetch_optional(&self.db_replica)
        .await
        .map_err(db_error)?;
        match row {
            Some(r) => Ok(Some(ResolvedTenant {
                id: TenantId::new(r.id),
                tenant_type: TenantType::parse(&r.tenant_type)?,
                country_code: CountryCode::parse(&r.country_code)?,
            })),
            None => Ok(None),
        }
    }

    /// O `Mutex` nunca fica envenenado de forma útil (só operações de `HashMap`): recupera-se.
    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Entradas em cache, incluindo stale (para métricas e testes).
    pub fn cached_entries(&self) -> usize {
        self.cache().len()
    }

    /// Consultas `tenants` feitas desde o arranque (para métricas e testes).
    pub fn db_lookups(&self) -> u64 {
        self.lookups.load(Ordering::Relaxed)
    }

    /// Só para testes: envelhece todas as entradas em cache (ex.: `POSITIVE_TTL` → stale). Não
    /// existe em `cargo build --release`.
    #[cfg(feature = "test-support")]
    pub fn age_cache_for_tests(&self, by: Duration) {
        let mut c = self.cache();
        for (at, _) in c.positive.values_mut() {
            *at = at.checked_sub(by).unwrap_or(*at);
        }
        for at in c.negative.values_mut() {
            *at = at.checked_sub(by).unwrap_or(*at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn tenant() -> ResolvedTenant {
        ResolvedTenant {
            id: TenantId::new(Uuid::now_v7()),
            tenant_type: TenantType::Municipal,
            country_code: CountryCode::Pt,
        }
    }

    #[test]
    fn ttls() {
        let mut c = Cache::default();
        let t0 = Instant::now();
        let t = tenant();
        c.put("a.pt".into(), Some(t), t0);
        c.put("x.pt".into(), None, t0);
        assert_eq!(c.get("a.pt", t0 + Duration::from_secs(59)), Some(Some(t)));
        assert_eq!(c.get("x.pt", t0 + Duration::from_secs(9)), Some(None));
        assert_eq!(c.get("x.pt", t0 + NEGATIVE_TTL), None);
        // Expirado: não serve como acerto, mas fica stale até `MAX_STALE` a mais.
        assert_eq!(c.get("a.pt", t0 + POSITIVE_TTL), None);
        assert_eq!(c.stale("a.pt", t0 + POSITIVE_TTL), Some(t));
        assert_eq!(c.len(), 1);
        let gone = t0 + POSITIVE_TTL + MAX_STALE;
        assert_eq!(c.stale("a.pt", gone), None);
        assert_eq!(c.get("a.pt", gone), None);
        assert_eq!(c.len(), 0);
        // Um desconhecido nunca tem stale.
        assert_eq!(c.stale("x.pt", t0), None);
    }

    #[test]
    fn known_replaces_unknown_and_back() {
        let mut c = Cache::default();
        let t0 = Instant::now();
        c.put("a.pt".into(), None, t0);
        c.put("a.pt".into(), Some(tenant()), t0);
        assert_eq!(c.len(), 1);
        c.put("a.pt".into(), None, t0);
        assert_eq!(c.get("a.pt", t0), Some(None));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn flood_of_unknown_hosts_never_evicts_tenants_nor_exceeds_cap() {
        let mut c = Cache::default();
        let t0 = Instant::now();
        let t = tenant();
        c.put("a.pt".into(), Some(t), t0);
        for i in 0..(MAX_ENTRIES * 2) {
            c.put(format!("h{i}.pt"), None, t0);
            assert!(c.len() <= MAX_ENTRIES);
            assert!(c.negative.len() <= MAX_NEGATIVE);
        }
        assert_eq!(c.get("a.pt", t0), Some(Some(t)));
    }

    #[test]
    fn positive_side_is_capped() {
        let mut c = Cache::default();
        let t0 = Instant::now();
        for i in 0..(MAX_POSITIVE + 10) {
            c.put(format!("t{i}.pt"), Some(tenant()), t0);
        }
        assert_eq!(c.positive.len(), MAX_POSITIVE);
        // Expiradas saem para dar lugar a novas.
        let later = t0 + POSITIVE_TTL;
        c.put("novo.pt".into(), Some(tenant()), later);
        assert_eq!(c.positive.len(), 1);
        assert!(c.len() <= MAX_ENTRIES);
    }

    #[test]
    fn retry_after_rounds_up_and_never_zero() {
        assert_eq!(retry_after_s(59_001), 60);
        assert_eq!(retry_after_s(1), 1);
        assert_eq!(retry_after_s(1_000), 1);
        assert_eq!(retry_after_s(0), UNKNOWN_HOSTS_WINDOW.as_secs());
        assert_eq!(retry_after_s(-1), UNKNOWN_HOSTS_WINDOW.as_secs());
    }

    #[test]
    fn parse_known_values_only() {
        assert_eq!(
            TenantType::parse("national_portal").ok(),
            Some(TenantType::NationalPortal)
        );
        assert!(TenantType::parse("admin").is_err());
        assert_eq!(CountryCode::parse("ES").ok(), Some(CountryCode::Es));
        assert!(CountryCode::parse("pt").is_err());
        for t in [
            TenantType::Municipal,
            TenantType::NationalPortal,
            TenantType::Niche,
        ] {
            assert_eq!(TenantType::parse(t.as_str()).ok(), Some(t));
        }
    }
}
