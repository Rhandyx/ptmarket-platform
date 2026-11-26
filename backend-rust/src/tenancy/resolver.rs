//! Resolução do tenant a partir do `Host` (único sítio que cria `TenantId`), com cache em memória.
//!
//! `SELECT ... FROM tenants WHERE custom_domain = $1 AND is_active` na réplica. Cache: 60 s para
//! hosts conhecidos, 10 s para desconhecidos, no máximo 10 000 entradas (sem dependência nova:
//! `HashMap` + `Mutex`, nunca seguro durante um `await`). Os desconhecidos têm um teto próprio
//! (2 000): um flood de hosts aleatórios esvazia só esse lado e nunca expulsa os tenants.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, Uri};
use secrecy::SecretString;
use sqlx::PgPool;

use crate::{
    error::AppError,
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
/// Máximo de entradas em cache (conhecidos + desconhecidos).
pub const MAX_ENTRIES: usize = 10_000;
/// Parte do máximo reservada a desconhecidos.
pub const MAX_NEGATIVE: usize = 2_000;
const MAX_POSITIVE: usize = MAX_ENTRIES - MAX_NEGATIVE;

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

/// Cache dos dois lados, com o instante de cada entrada.
#[derive(Debug, Default)]
struct Cache {
    positive: HashMap<String, (Instant, ResolvedTenant)>,
    negative: HashMap<String, Instant>,
}

/// Resultado em cache: `Some(Some(t))` conhecido, `Some(None)` desconhecido, `None` sem entrada.
type Cached = Option<Option<ResolvedTenant>>;

impl Cache {
    fn get(&mut self, host: &str, now: Instant) -> Cached {
        if let Some((at, t)) = self.positive.get(host).copied() {
            if now.saturating_duration_since(at) < POSITIVE_TTL {
                return Some(Some(t));
            }
            self.positive.remove(host);
        }
        if let Some(at) = self.negative.get(host).copied() {
            if now.saturating_duration_since(at) < NEGATIVE_TTL {
                return Some(None);
            }
            self.negative.remove(host);
        }
        None
    }

    fn put(&mut self, host: String, value: Option<ResolvedTenant>, now: Instant) {
        match value {
            Some(t) => {
                self.negative.remove(&host);
                if self.positive.len() >= MAX_POSITIVE && !self.positive.contains_key(&host) {
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

/// Resolve o `Host` de cada pedido. Vive no `AppState` (partilhado entre pedidos).
#[derive(Debug)]
pub struct HostResolver {
    db_replica: PgPool,
    platform_host: Option<String>,
    internal_token: Option<SecretString>,
    cache: Mutex<Cache>,
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
        }
    }

    /// Decide o host do pedido (só `Host`, ou `X-Forwarded-Host` com token interno válido).
    pub async fn resolve(&self, headers: &HeaderMap, uri: &Uri) -> ResolvedHost {
        let Some(host) = effective_host(headers, uri, self.internal_token.as_ref()) else {
            return ResolvedHost::Unknown;
        };
        if self.platform_host.as_deref() == Some(host.as_str()) {
            return ResolvedHost::Platform;
        }
        match self.lookup(host).await {
            Ok(Some(t)) => ResolvedHost::Tenant(t),
            Ok(None) => ResolvedHost::Unknown,
            Err(e) => {
                tracing::error!(error = ?e, "resolução do host: BD indisponível");
                ResolvedHost::Unavailable
            }
        }
    }

    /// Host já normalizado → tenant ativo (cache primeiro).
    async fn lookup(&self, host: String) -> Result<Option<ResolvedTenant>, AppError> {
        if let Some(hit) = self.cache().get(&host, Instant::now()) {
            return Ok(hit);
        }
        let row = sqlx::query!(
            "SELECT id, tenant_type, country_code FROM tenants
             WHERE custom_domain = $1 AND is_active",
            host
        )
        .fetch_optional(&self.db_replica)
        .await
        .map_err(db_error)?;
        let value = match row {
            Some(r) => Some(ResolvedTenant {
                id: TenantId::new(r.id),
                tenant_type: TenantType::parse(&r.tenant_type)?,
                country_code: CountryCode::parse(&r.country_code)?,
            }),
            None => None,
        };
        self.cache().put(host, value, Instant::now());
        Ok(value)
    }

    /// O `Mutex` nunca fica envenenado de forma útil (só operações de `HashMap`): recupera-se.
    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Entradas em cache (para métricas e testes).
    pub fn cached_entries(&self) -> usize {
        self.cache().len()
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
        assert_eq!(c.get("a.pt", t0 + POSITIVE_TTL), None);
        assert_eq!(c.len(), 0);
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
