//! Middleware da caixa negra (spec 13 §1): um `audit_event` por pedido autenticado, por recusa e
//! por mutação (também anónima). Não há papel, flag, variável nem endpoint que o desligue.
//!
//! Ordem das layers: as que resolvem o ator (`Actor`), o tenant (`TenantId`) e a classe
//! (`AuditClass`) ficam POR FORA desta (nunca recusam; só põem extensões); os handlers e os
//! extractores que recusam (401/403) ficam por dentro. Com `Router::layer` corre depois do
//! roteamento: vê `MatchedPath` e os parâmetros da rota.
//!
//! Decisão depois do handler (por esta ordem):
//! 1. 401/403 ou `Denied` → síncrono `denied` (transação própria). Falhou → 503.
//! 2. 429 → o 1.º por (ator ou IP, rota) em cada janela de 60 s é síncrono (`rate_limit`); os
//!    seguintes só contam no Redis; no fim da janela sai 1 `security.rate_limit_summary` no Stream.
//!    Redis indisponível → 503.
//! 3. Mutação (método ≠ GET/HEAD/OPTIONS): se o `AuditCtx` já foi registado (evento de
//!    `audit::record` confirmado por COMMIT) → nada; senão síncrono (5xx = `error`). Também anónimas.
//! 4. Leitura (GET/HEAD/OPTIONS) autenticada + `ReadSync` (ou sem classe) → síncrono; falhou → 503
//!    sem o corpo.
//! 5. Leitura autenticada + `ReadAsync` → XADD; falhou → síncrono; falhou → 503.
//! 6. Leitura anónima (OPTIONS incluído) → nada.
//!
//! `x-request-id` e `CF-Connecting-IP` só contam se o peer TCP for um proxy de confiança; senão o
//! `request_id` é um UUIDv7 novo e o IP é o do peer.
//!
//! Exceção consciente à regra "um handler nunca publica no Redis": só este middleware, só no
//! stream `audit:stream` (contrato com o worker do cartão 08 e com `audit.audit_append_event`).

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::{ConnectInfo, FromRequestParts, MatchedPath, RawPathParams, Request, State},
    http::{HeaderMap, Method, StatusCode, header::USER_AGENT, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use deadpool_redis::redis;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    audit::{ActorType, AuditCtx, AuditEvent, Outcome, record},
    error::AppError,
    http::{
        client_ip::{TrustedProxies, client_ip},
        telemetry::redact,
    },
    tenancy::{TenantId, begin_tenant_tx, db::begin_platform_tx},
};

/// Stream da caixa negra (contrato com o cartão 08). Sem MAXLEN: só o worker apaga, depois do ACK.
pub const STREAM_KEY: &str = "audit:stream";
/// Janela do resumo de 429 (owner 25/11): no máximo 1 escrita síncrona por chave por janela.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Limite para a gravação síncrona; passado isto, 503.
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);
/// Limite para cada operação no Redis; passado isto, conta como indisponível.
const REDIS_TIMEOUT: Duration = Duration::from_secs(1);
/// Limites de tamanho do que vai para `changes`.
const MAX_QUERY_KEYS: usize = 32;
const MAX_KEY_CHARS: usize = 64;
const MAX_PARAM_CHARS: usize = 128;
/// Marcador da contagem no modelo do resumo (substituído no Redis, de forma atómica).
const COUNT_PLACEHOLDER: &str = "__RL_COUNT__";

/// Quem fez o pedido. Posto nas extensões pela layer de autenticação; ausente = anónimo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Actor {
    pub actor_type: ActorType,
    pub actor_id: Option<Uuid>,
    pub impersonator_id: Option<Uuid>,
}

/// Como se auditam as leituras de uma rota. Posto por router (layer `Extension` por fora desta);
/// ausente = `ReadSync` (falha fechado).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditClass {
    /// Leitura comum: evento no Redis Stream (entrega garantida pelo worker).
    ReadAsync,
    /// Leitura de admin/superadmin ou de dados pessoais: síncrona; se falhar, 503.
    ReadSync,
}

/// Marca de recusa posta pelo handler nas extensões da RESPOSTA (ex.: IDOR devolve 404 mas é
/// recusa). O motivo é uma constante do código, nunca dados do pedido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied(pub &'static str);

/// Dependências do middleware: BD primária (gravação síncrona), Redis (Stream e contadores de 429)
/// e os proxies de confiança.
#[derive(Clone)]
pub struct AuditLayerState {
    inner: Arc<Inner>,
}

struct Inner {
    db: sqlx::PgPool,
    redis: deadpool_redis::Pool,
    trusted: TrustedProxies,
    /// Prefixo das chaves Redis: vazio em produção; só os testes o mudam (isolamento).
    ns: String,
    window: Duration,
}

impl AuditLayerState {
    pub fn new(db: sqlx::PgPool, redis: deadpool_redis::Pool, trusted: TrustedProxies) -> Self {
        Self::build(db, redis, trusted, String::new(), RATE_LIMIT_WINDOW)
    }

    /// Só para testes: prefixo próprio nas chaves Redis e janela de 429 curta. Não existe em
    /// `cargo build --release` e não desliga nada.
    #[cfg(feature = "test-support")]
    pub fn for_tests(
        db: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        trusted: TrustedProxies,
        namespace: &str,
        window: Duration,
    ) -> Self {
        Self::build(db, redis, trusted, namespace.to_owned(), window)
    }

    fn build(
        db: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        trusted: TrustedProxies,
        ns: String,
        window: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                redis,
                trusted,
                ns,
                window,
            }),
        }
    }

    fn key(&self, k: &str) -> String {
        format!("{}{k}", self.inner.ns)
    }

    fn window_ms(&self) -> u64 {
        u64::try_from(self.inner.window.as_millis()).unwrap_or(u64::MAX)
    }

    /// Publica no Stream os resumos de 429 cujas janelas já fecharam (todas as instâncias, também
    /// as de processos que morreram). Devolve quantos saíram. Corre sozinho no fim de cada janela.
    pub async fn flush_due_rate_limit_summaries(&self) -> Result<i64, AppError> {
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(SWEEP_SCRIPT)
            .arg(2)
            .arg(self.key(PENDING_KEY))
            .arg(self.key(STREAM_KEY))
            .arg(now_ms());
        redis_query(self, cmd).await
    }
}

/// Aplica o middleware a um router de API (as rotas sem utilizador, ex. `/healthz`, ficam fora).
pub fn audited<S>(router: Router<S>, state: AuditLayerState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::middleware::from_fn_with_state(
        state,
        audit_middleware,
    ))
}

/// O `AuditCtx` do pedido é o que este middleware criou (partilha a marca `recorded`). Sem o
/// middleware não há contexto: 500 (falha fechado).
impl<S: Send + Sync> FromRequestParts<S> for AuditCtx {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<AuditCtx>().cloned().ok_or_else(|| {
            AppError::Internal(anyhow::anyhow!("AuditCtx em falta: rota sem audit_layer"))
        })
    }
}

/// O que o middleware guarda do pedido antes de o passar ao handler.
struct ReqInfo {
    method: Method,
    route: Option<String>,
    path_params: Map<String, Value>,
    query_keys: Vec<String>,
    tenant: Option<TenantId>,
    class: AuditClass,
    authenticated: bool,
}

async fn audit_middleware(State(st): State<AuditLayerState>, req: Request, next: Next) -> Response {
    let (mut parts, body) = req.into_parts();
    let (info, ctx) = inspect(&st, &mut parts).await;
    parts.extensions.insert(ctx.clone());
    let resp = next.run(Request::from_parts(parts, body)).await;
    decide(&st, &info, &ctx, resp).await
}

async fn inspect(st: &AuditLayerState, parts: &mut Parts) -> (ReqInfo, AuditCtx) {
    let actor = parts.extensions.get::<Actor>().copied();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = client_ip(peer, &parts.headers, &st.inner.trusted);
    let rid = request_id(&parts.headers, st.inner.trusted.trusts(peer));
    let ctx = build_ctx(actor, rid, ip, &parts.headers);
    let path_params = match RawPathParams::from_request_parts(parts, &()).await {
        Ok(p) => p
            .iter()
            .map(|(k, v)| (k.to_owned(), Value::String(truncate(v, MAX_PARAM_CHARS))))
            .collect(),
        Err(_) => Map::new(),
    };
    let info = ReqInfo {
        method: parts.method.clone(),
        route: parts
            .extensions
            .get::<MatchedPath>()
            .map(|m| m.as_str().to_owned()),
        path_params,
        query_keys: query_keys(parts.uri.query()),
        tenant: parts.extensions.get::<TenantId>().copied(),
        class: parts
            .extensions
            .get::<AuditClass>()
            .copied()
            .unwrap_or(AuditClass::ReadSync),
        authenticated: actor.is_some_and(|a| a.actor_type != ActorType::Anonymous),
    };
    (info, ctx)
}

fn build_ctx(
    actor: Option<Actor>,
    request_id: Uuid,
    ip: Option<IpAddr>,
    headers: &HeaderMap,
) -> AuditCtx {
    let ua = headers.get(USER_AGENT).map(|v| {
        let digest = Sha256::digest(v.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_slice());
        out
    });
    let (actor_type, actor_id, impersonator_id) = match actor {
        Some(a) => (a.actor_type, a.actor_id, a.impersonator_id),
        None => (ActorType::Anonymous, None, None),
    };
    AuditCtx::new(
        actor_type,
        actor_id,
        None,
        impersonator_id,
        request_id,
        ip,
        ua,
    )
}

/// `x-request-id` só se o peer for um proxy de confiança e o valor for um UUID; senão um UUIDv7
/// novo (um cliente direto não escolhe o `request_id` que fica na caixa negra).
fn request_id(headers: &HeaderMap, trusted_peer: bool) -> Uuid {
    if !trusted_peer {
        return Uuid::now_v7();
    }
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .unwrap_or_else(Uuid::now_v7)
}

/// GET, HEAD e OPTIONS são leituras; tudo o resto é mutação.
fn is_read(m: &Method) -> bool {
    *m == Method::GET || *m == Method::HEAD || *m == Method::OPTIONS
}

/// Só as chaves da query (nunca os valores), sem repetidos, com limites de número e tamanho.
fn query_keys(query: Option<&str>) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for pair in query.unwrap_or_default().split('&') {
        let key = pair.split('=').next().unwrap_or_default();
        if key.is_empty() {
            continue;
        }
        let key = truncate(key, MAX_KEY_CHARS);
        if !keys.contains(&key) {
            keys.push(key);
        }
        if keys.len() == MAX_QUERY_KEYS {
            break;
        }
    }
    keys
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn action(m: &Method) -> &'static str {
    match *m {
        Method::GET => "http.get",
        Method::HEAD => "http.head",
        Method::POST => "http.post",
        Method::PUT => "http.put",
        Method::PATCH => "http.patch",
        Method::DELETE => "http.delete",
        Method::OPTIONS => "http.options",
        Method::TRACE => "http.trace",
        Method::CONNECT => "http.connect",
        _ => "http.other",
    }
}

fn changes(info: &ReqInfo, status: StatusCode) -> Value {
    let mut v = json!({
        "status": status.as_u16(),
        "path_params": Value::Object(info.path_params.clone()),
        "query_keys": info.query_keys,
    });
    redact(&mut v);
    v
}

fn outcome_for(status: StatusCode) -> Outcome {
    if status.is_server_error() {
        Outcome::Error
    } else {
        Outcome::Success
    }
}

fn http_event(
    info: &ReqInfo,
    status: StatusCode,
    outcome: Outcome,
    reason: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        action: action(&info.method),
        target_type: Some("route"),
        target_id: info.route.clone(),
        outcome,
        reason: reason.map(str::to_owned),
        changes: Some(changes(info, status)),
        store_id: None,
    }
}

async fn decide(st: &AuditLayerState, info: &ReqInfo, ctx: &AuditCtx, resp: Response) -> Response {
    let status = resp.status();
    let denied = resp.extensions().get::<Denied>().copied();

    // 1. Recusa (a transação do handler fez rollback): transação própria.
    if denied.is_some() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        let reason = match denied {
            Some(Denied(r)) => r,
            None if status == StatusCode::UNAUTHORIZED => "unauthorized",
            None => "forbidden",
        };
        let ev = http_event(info, status, Outcome::Denied, Some(reason));
        return or_unavailable(write_sync(st, info, ctx, ev).await, resp);
    }

    // 2. Rate-limit: 1 escrita síncrona por chave por janela; o resto conta no Redis.
    if status == StatusCode::TOO_MANY_REQUESTS {
        return rate_limited(st, info, ctx, resp).await;
    }

    // 3. Mutações (também anónimas).
    if !is_read(&info.method) {
        if ctx.is_recorded() {
            return resp;
        }
        let ev = http_event(info, status, outcome_for(status), None);
        return or_unavailable(write_sync(st, info, ctx, ev).await, resp);
    }

    // 6. Leitura anónima: só logs/métricas.
    if !info.authenticated {
        return resp;
    }

    let ev = http_event(info, status, outcome_for(status), None);
    match info.class {
        // 4. Leitura sensível: síncrona.
        AuditClass::ReadSync => or_unavailable(write_sync(st, info, ctx, ev).await, resp),
        // 5. Leitura comum: Stream; se falhar, síncrona; se falhar, 503.
        AuditClass::ReadAsync => {
            let payload = stream_event(info, ctx, &ev, Uuid::now_v7(), &rfc3339(SystemTime::now()));
            match xadd(st, &payload).await {
                Ok(()) => resp,
                Err(e) => {
                    tracing::warn!(error = ?e, "auditoria: XADD falhou; a gravar de forma síncrona");
                    or_unavailable(write_sync(st, info, ctx, ev).await, resp)
                }
            }
        }
    }
}

/// Resposta original se a gravação passou; senão 503 (o corpo e os cabeçalhos originais não saem).
fn or_unavailable(res: Result<(), AppError>, resp: Response) -> Response {
    match res {
        Ok(()) => resp,
        Err(e) => {
            tracing::error!(error = ?e, "auditoria: evento não gravado; resposta 503");
            drop(resp);
            AppError::ServiceUnavailable.into_response()
        }
    }
}

/// Grava o evento numa transação própria com o ator do pedido (tenant se houver; senão plataforma).
async fn write_sync(
    st: &AuditLayerState,
    info: &ReqInfo,
    ctx: &AuditCtx,
    ev: AuditEvent,
) -> Result<(), AppError> {
    let db = &st.inner.db;
    let fut = async {
        match info.tenant {
            Some(t) => {
                let mut tx = begin_tenant_tx(db, t, ctx).await?;
                record(&mut tx, ev).await?;
                tx.commit().await
            }
            None => {
                let mut tx = begin_platform_tx(db, ctx).await?;
                record(&mut tx, ev).await?;
                tx.commit().await
            }
        }
    };
    tokio::time::timeout(WRITE_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::ServiceUnavailable)?
}

/// JSON do contrato do Stream (o mesmo de `audit.audit_append_event`); ausentes = null.
fn stream_event(
    info: &ReqInfo,
    ctx: &AuditCtx,
    ev: &AuditEvent,
    id: Uuid,
    occurred_at: &str,
) -> Value {
    let ua = ctx.user_agent_hash_hex();
    json!({
        "id": id.to_string(),
        "tenant_id": info.tenant.map(|t| t.as_uuid().to_string()),
        "store_id": ev.store_id.map(|s| s.to_string()),
        "actor_type": ctx.actor_type().as_str(),
        "actor_id": ctx.actor_id().map(|a| a.to_string()),
        "actor_label": ctx.actor_label(),
        "impersonator_id": ctx.impersonator_id().map(|a| a.to_string()),
        "action": ev.action,
        "target_type": ev.target_type,
        "target_id": ev.target_id,
        "outcome": ev.outcome.as_str(),
        "reason": ev.reason,
        "changes": ev.changes,
        "request_id": ctx.request_id().to_string(),
        "ip": ctx.ip().map(|i| i.to_string()),
        "user_agent_hash": if ua.is_empty() { None } else { Some(ua) },
        "occurred_at": occurred_at,
    })
}

async fn redis_query<T: redis::FromRedisValue>(
    st: &AuditLayerState,
    cmd: redis::Cmd,
) -> Result<T, AppError> {
    let fut = async {
        let mut conn = st
            .inner
            .redis
            .get()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("redis pool: {e}")))?;
        cmd.query_async::<T>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("redis: {e}")))
    };
    tokio::time::timeout(REDIS_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::ServiceUnavailable)?
}

async fn xadd(st: &AuditLayerState, payload: &Value) -> Result<(), AppError> {
    let mut cmd = redis::cmd("XADD");
    cmd.arg(st.key(STREAM_KEY))
        .arg("*")
        .arg("event")
        .arg(payload.to_string());
    redis_query::<String>(st, cmd).await.map(|_| ())
}

// ---------------------------------------------------------------------------------------------
// 429: 1.º por janela síncrono; os seguintes contam; 1 resumo por janela no Stream.
//
// Chaves (todas com o prefixo `ns`): `audit:rl:first:<k>` (abre a janela, expira com ela),
// `audit:rl:count:<k>` (hash: n = contagem, tpl = JSON do resumo), `audit:rl:pending` (zset das
// contagens por publicar, pontuação = fim da janela em ms). `<k>` = sha256(sujeito, rota): nem IPs
// nem ids ficam no nome das chaves. Tudo em scripts Lua: contar, fechar e publicar é atómico (nada
// se perde nem se duplica, mesmo com várias instâncias). Redis sem cluster (chaves derivadas no
// script).
// ---------------------------------------------------------------------------------------------

const PENDING_KEY: &str = "audit:rl:pending";

/// Fecha uma contagem: apaga-a, tira-a do zset e publica o resumo (se houver contagem).
/// Macro (e não `const`) para entrar no `concat!` dos dois scripts.
macro_rules! flush_fn {
    () => {
        r#"
local function flush(ck, pending, stream)
  local c = redis.call('HGET', ck, 'n')
  local t = redis.call('HGET', ck, 'tpl')
  redis.call('DEL', ck)
  redis.call('ZREM', pending, ck)
  if c and t then
    local i, j = string.find(t, '"__RL_COUNT__"', 1, true)
    if i then t = string.sub(t, 1, i - 1) .. c .. string.sub(t, j + 1) end
    redis.call('XADD', stream, '*', 'event', t)
    return 1
  end
  return 0
end
"#
    };
}

#[cfg(test)]
const FLUSH_FN: &str = flush_fn!();

/// KEYS: first, count, pending, stream · ARGV: window_ms, tpl, now_ms.
/// 0 = abriu a janela (o chamador grava síncrono); n ≥ 1 = n-ésimo 429 a mais nesta janela.
const HIT_SCRIPT: &str = concat!(
    flush_fn!(),
    r#"
if redis.call('SET', KEYS[1], ARGV[3], 'NX', 'PX', ARGV[1]) then
  flush(KEYS[2], KEYS[3], KEYS[4])
  return 0
end
local n = redis.call('HINCRBY', KEYS[2], 'n', 1)
if n == 1 then
  redis.call('HSET', KEYS[2], 'tpl', ARGV[2])
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 0 then ttl = 0 end
  redis.call('ZADD', KEYS[3], tonumber(ARGV[3]) + ttl, KEYS[2])
end
return n
"#
);

/// KEYS: pending, stream · ARGV: now_ms. Publica as contagens cujas janelas já fecharam.
const SWEEP_SCRIPT: &str = concat!(
    flush_fn!(),
    r#"
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, 500)
local n = 0
for _, ck in ipairs(due) do
  n = n + flush(ck, KEYS[1], KEYS[2])
end
return n
"#
);

fn rate_limit_key(info: &ReqInfo, ctx: &AuditCtx) -> String {
    let subject = match (info.authenticated, ctx.actor_id(), ctx.ip()) {
        (true, Some(id), _) => format!("a:{}:{id}", ctx.actor_type().as_str()),
        (_, _, Some(ip)) => format!("ip:{ip}"),
        _ => "none".to_owned(),
    };
    let route = info.route.as_deref().unwrap_or("-");
    let digest = Sha256::digest(format!("{subject}\n{route}").as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

async fn rate_limited(
    st: &AuditLayerState,
    info: &ReqInfo,
    ctx: &AuditCtx,
    resp: Response,
) -> Response {
    let status = resp.status();
    let k = rate_limit_key(info, ctx);
    let first = st.key(&format!("audit:rl:first:{k}"));
    let count = st.key(&format!("audit:rl:count:{k}"));

    let summary = AuditEvent {
        action: "security.rate_limit_summary",
        target_type: Some("route"),
        target_id: info.route.clone(),
        outcome: Outcome::Denied,
        reason: Some("rate_limit".to_owned()),
        changes: None,
        store_id: None,
    };
    let mut tpl = stream_event(
        info,
        ctx,
        &summary,
        Uuid::now_v7(),
        &rfc3339(SystemTime::now()),
    );
    tpl["changes"] = json!({
        "status": status.as_u16(),
        "window_seconds": st.inner.window.as_secs(),
        "count": COUNT_PLACEHOLDER,
    });

    let mut cmd = redis::cmd("EVAL");
    cmd.arg(HIT_SCRIPT)
        .arg(4)
        .arg(&first)
        .arg(&count)
        .arg(st.key(PENDING_KEY))
        .arg(st.key(STREAM_KEY))
        .arg(st.window_ms())
        .arg(tpl.to_string())
        .arg(now_ms());
    match redis_query::<i64>(st, cmd).await {
        Ok(0) => {
            let ev = http_event(info, status, Outcome::Denied, Some("rate_limit"));
            let res = write_sync(st, info, ctx, ev).await;
            if res.is_err() {
                // Reabre a janela: o próximo 429 volta a tentar a escrita síncrona.
                let mut del = redis::cmd("DEL");
                del.arg(&first);
                if let Err(e) = redis_query::<i64>(st, del).await {
                    tracing::warn!(error = ?e, "auditoria: não foi possível reabrir a janela de 429");
                }
            }
            or_unavailable(res, resp)
        }
        Ok(1) => {
            // 1.º 429 contado nesta janela: no fim dela sai o resumo.
            let st = st.clone();
            let wait = st.inner.window + Duration::from_millis(200);
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                if let Err(e) = st.flush_due_rate_limit_summaries().await {
                    tracing::warn!(error = ?e, "auditoria: resumos de 429 por publicar");
                }
            });
            resp
        }
        Ok(_) => resp,
        Err(e) => {
            tracing::error!(error = ?e, "auditoria: Redis indisponível para 429; resposta 503");
            drop(resp);
            AppError::ServiceUnavailable.into_response()
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// RFC 3339 em UTC com microssegundos (ex.: `2026-11-25T10:00:00.123456Z`).
fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or_default();
    let rem = secs % 86_400;
    let (y, m, day) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:06}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_micros()
    )
}

/// Dias desde 1970-01-01 → (ano, mês, dia) no calendário gregoriano (algoritmo de H. Hinnant).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        let at = |s: u64, micros: u64| UNIX_EPOCH + Duration::from_micros(s * 1_000_000 + micros);
        assert_eq!(rfc3339(at(0, 0)), "1970-01-01T00:00:00.000000Z");
        assert_eq!(rfc3339(at(951_782_400, 5)), "2000-02-29T00:00:00.000005Z");
        assert_eq!(
            rfc3339(at(1_795_609_845, 123_456)),
            "2026-11-25T12:30:45.123456Z"
        );
        assert_eq!(rfc3339(at(4_102_444_799, 0)), "2099-12-31T23:59:59.000000Z");
    }

    #[test]
    fn query_keys_never_values_bounded_and_unique() {
        let k = query_keys(Some("email=a%40b.pt&page=2&page=3&&=x&flag"));
        assert_eq!(k, vec!["email", "page", "flag"]);
        assert!(query_keys(None).is_empty());
        let many: String = (0..100).map(|i| format!("k{i}=v&")).collect();
        assert_eq!(query_keys(Some(&many)).len(), MAX_QUERY_KEYS);
        let long = "x".repeat(500);
        assert_eq!(query_keys(Some(&long))[0].len(), MAX_KEY_CHARS);
    }

    #[test]
    fn request_id_from_header_or_fresh() {
        let mut h = HeaderMap::new();
        let id = Uuid::now_v7();
        if let Ok(v) = id.to_string().parse() {
            h.insert("x-request-id", v);
        }
        assert_eq!(request_id(&h, true), id);
        let fresh = request_id(&h, false);
        assert_ne!(fresh, id, "peer não confiável não escolhe o request_id");
        assert_eq!(fresh.get_version_num(), 7);
        let mut bad = HeaderMap::new();
        bad.insert("x-request-id", axum::http::HeaderValue::from_static("nope"));
        assert_eq!(request_id(&bad, true).get_version_num(), 7);
    }

    #[test]
    fn reads_and_mutations() {
        assert!(is_read(&Method::GET) && is_read(&Method::HEAD) && is_read(&Method::OPTIONS));
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(!is_read(&m), "{m}");
        }
        assert!(!is_read(
            &Method::from_bytes(b"PURGE").unwrap_or(Method::POST)
        ));
    }

    #[test]
    fn scripts_share_the_same_flush() {
        assert!(HIT_SCRIPT.starts_with(FLUSH_FN));
        assert!(SWEEP_SCRIPT.starts_with(FLUSH_FN));
        assert!(FLUSH_FN.contains(COUNT_PLACEHOLDER));
    }

    #[test]
    fn method_actions_are_static() {
        assert_eq!(action(&Method::GET), "http.get");
        assert_eq!(action(&Method::DELETE), "http.delete");
        let custom = Method::from_bytes(b"PURGE").unwrap_or(Method::GET);
        assert_eq!(action(&custom), "http.other");
    }
}
