//! Middleware da caixa negra (spec 13 §1): um `audit_event` por pedido autenticado, por recusa e
//! por mutação (também anónima). Não há papel, flag, variável nem endpoint que o desligue.
//!
//! Ordem das layers: as que resolvem o ator (`Actor`), o tenant (`TenantId`) e a classe
//! (`AuditClass`) ficam POR FORA desta (nunca recusam; só põem extensões); os handlers e os
//! extractores que recusam (401/403) ficam por dentro. Com `Router::layer` corre depois do
//! roteamento: vê `MatchedPath` e os parâmetros da rota.
//!
//! Decisão depois do handler (por esta ordem):
//! 1. Recusa (401/403 ou `Denied`): ator autenticado → síncrono `denied` (transação própria),
//!    sempre; falhou → 503. Anónimo → contada por (IP, `auth_fail`).
//! 2. 429 → contado por (ator ou IP, rota) (`rate_limit`).
//! 3. Mutação (método ≠ GET/HEAD/OPTIONS): se o `AuditCtx` já foi registado (evento de
//!    `audit::record` confirmado por COMMIT) → nada; autenticada → síncrono (5xx = `error`);
//!    anónima → contada por (IP, `anon_mutation`, resultado).
//! 4. Leitura (GET/HEAD/OPTIONS) autenticada + `ReadSync` (ou sem classe) → síncrono; falhou → 503
//!    sem o corpo.
//! 5. Leitura autenticada + `ReadAsync` → XADD; falhou → síncrono; falhou → 503.
//! 6. Leitura anónima (OPTIONS incluído) → nada.
//!
//! "Contado": o 1.º por chave em cada janela de 60 s é síncrono; os seguintes só contam no Redis;
//! no fim da janela sai 1 resumo `security.<classe>_summary` no Stream com a contagem. Um flood
//! sem credenciais não serializa na cabeça da cadeia nem esgota a pool. Redis indisponível → 503.
//! O IP conta por endereço em IPv4 e por /64 em IPv6 (rodar endereços de um /64 não abre janelas).
//!
//! A decisão corre numa task própria (`tokio::spawn`) e o pedido espera pelo resultado: um timeout
//! ou o cliente a fechar a ligação não cancelam a gravação.
//!
//! O `request_id` da caixa negra é SEMPRE um UUIDv7 do servidor (a Cloudflare não apaga o
//! `x-request-id` do cliente): o que a `SetRequestIdLayer` gerou com `MakeRequestUuidV7`, depois de
//! `take_client_request_id` (a layer mais exterior) tirar o do cliente para `ClientRequestId` — é o
//! mesmo id nos logs (span `request`), na resposta (também no 408 da `TimeoutLayer`) e no evento.
//! Sem essas layers, o middleware gera o seu e lê o cabeçalho do cliente. O handler vê sempre esse
//! id no cabeçalho e na extensão `RequestId`. O `x-request-id` do cliente, só se for UUID, fica em
//! `changes.client_request_id`. `CF-Connecting-IP` só conta se o peer TCP
//! for um proxy de confiança; senão o IP é o do peer.
//!
//! Todo o texto do pedido que entra no evento (rota, parâmetros, chaves da query, motivo) é limpo:
//! NUL → U+FFFD (o jsonb recusa `\u0000`), no máximo 256 caracteres por valor e 16 parâmetros.
//!
//! Exceção consciente à regra "um handler nunca publica no Redis": só este middleware, só no
//! stream `audit:stream` (contrato com o worker do cartão 08 e com `audit.audit_append_event`).

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::{ConnectInfo, FromRequestParts, MatchedPath, RawPathParams, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header::USER_AGENT, request::Parts,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use deadpool_redis::redis;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tower_http::request_id::{MakeRequestId, RequestId};
use tracing::Instrument;
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
/// Limites de tamanho do texto do pedido que entra no evento.
const MAX_QUERY_KEYS: usize = 32;
const MAX_KEY_CHARS: usize = 64;
const MAX_PATH_PARAMS: usize = 16;
const MAX_TEXT_CHARS: usize = 256;
/// Cabeçalho do id do pedido (o do cliente entra; o do servidor sai).
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
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

/// Posta pela layer mais exterior (`take_client_request_id`, em `http::with_edge_layers`): o
/// `x-request-id` do cliente (só se for UUID), já retirado do pedido. A presença desta extensão diz
/// ao middleware que o `RequestId` do pedido foi gerado no servidor (`MakeRequestUuidV7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRequestId(Option<Uuid>);

impl ClientRequestId {
    pub fn get(&self) -> Option<Uuid> {
        self.0
    }
}

/// Layer mais exterior: tira o `x-request-id` do cliente para `ClientRequestId` e apaga o
/// cabeçalho, para a `SetRequestIdLayer` gerar sempre o id (o cliente nunca o escolhe).
pub async fn take_client_request_id(mut req: Request, next: Next) -> Response {
    let client = client_request_id(req.headers());
    req.headers_mut().remove(X_REQUEST_ID);
    req.extensions_mut().insert(ClientRequestId(client));
    next.run(req).await
}

/// `MakeRequestId` da `SetRequestIdLayer`: UUIDv7 novo em cada pedido.
#[derive(Debug, Clone, Copy, Default)]
pub struct MakeRequestUuidV7;

impl MakeRequestId for MakeRequestUuidV7 {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        HeaderValue::from_str(&Uuid::now_v7().to_string())
            .ok()
            .map(RequestId::new)
    }
}

/// O que o middleware guarda do pedido antes de o passar ao handler (texto já limpo).
struct ReqInfo {
    method: Method,
    route: Option<String>,
    path_params: Map<String, Value>,
    query_keys: Vec<String>,
    /// `x-request-id` do cliente, só se for um UUID (nunca é o `request_id` do evento).
    client_request_id: Option<Uuid>,
    tenant: Option<TenantId>,
    class: AuditClass,
    authenticated: bool,
}

/// `request_id` do evento e `x-request-id` do cliente. Com as layers de entrada
/// (`ClientRequestId` presente): o `RequestId` gerado pela `SetRequestIdLayer`. Sem elas (router
/// montado à mão): um UUIDv7 novo, e o cabeçalho do cliente lido aqui.
fn request_ids(req: &Request) -> (Uuid, bool, Option<Uuid>) {
    let Some(ClientRequestId(client)) = req.extensions().get::<ClientRequestId>().copied() else {
        return (Uuid::now_v7(), false, client_request_id(req.headers()));
    };
    let server = req
        .extensions()
        .get::<RequestId>()
        .and_then(|r| r.header_value().to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok());
    match server {
        Some(rid) => (rid, true, client),
        None => (Uuid::now_v7(), false, client),
    }
}

async fn audit_middleware(State(st): State<AuditLayerState>, req: Request, next: Next) -> Response {
    let (rid, from_edge, client_rid) = request_ids(&req);
    let rid_header = HeaderValue::from_str(&rid.to_string()).ok();
    // Com as layers de entrada o span `request` já leva o id; sem elas, um span próprio.
    let span = if from_edge {
        tracing::Span::none()
    } else {
        tracing::info_span!("audit", request_id = %rid)
    };
    async move {
        let (mut parts, body) = req.into_parts();
        let (info, ctx) = inspect(&st, &mut parts, rid, client_rid).await;
        // O handler (e quem o registe) vê o id do servidor, nunca o do cliente.
        parts.headers.remove(X_REQUEST_ID);
        if let Some(h) = &rid_header {
            parts.headers.insert(X_REQUEST_ID, h.clone());
            parts.extensions.insert(RequestId::new(h.clone()));
        }
        parts.extensions.insert(ctx.clone());
        let resp = next.run(Request::from_parts(parts, body)).await;
        // Task própria: o abort do cliente ou um timeout por fora não cancelam a gravação.
        let task = tokio::spawn(decide(st, info, ctx, resp).in_current_span());
        let mut resp = match task.await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = ?e, "auditoria: gravação sem resultado; resposta 503");
                AppError::ServiceUnavailable.into_response()
            }
        };
        if let Some(h) = rid_header {
            resp.headers_mut().insert(X_REQUEST_ID, h);
        }
        resp
    }
    .instrument(span)
    .await
}

async fn inspect(
    st: &AuditLayerState,
    parts: &mut Parts,
    rid: Uuid,
    client_rid: Option<Uuid>,
) -> (ReqInfo, AuditCtx) {
    let actor = parts.extensions.get::<Actor>().copied();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = client_ip(peer, &parts.headers, &st.inner.trusted);
    let mut ctx = build_ctx(actor, rid, ip, &parts.headers);
    // Sessão validada pela layer `authenticate` → `app.session_id` em todas as transações do pedido.
    if let Some(s) = parts.extensions.get::<crate::identity::http::SessionInfo>() {
        ctx = ctx.with_session_id(s.id.as_uuid());
    }
    let path_params = match RawPathParams::from_request_parts(parts, &()).await {
        Ok(p) => p
            .iter()
            .take(MAX_PATH_PARAMS)
            .map(|(k, v)| {
                (
                    clean(k, MAX_KEY_CHARS),
                    Value::String(clean(v, MAX_TEXT_CHARS)),
                )
            })
            .collect(),
        Err(_) => Map::new(),
    };
    let info = ReqInfo {
        method: parts.method.clone(),
        route: parts
            .extensions
            .get::<MatchedPath>()
            .map(|m| clean(m.as_str(), MAX_TEXT_CHARS)),
        path_params,
        query_keys: query_keys(parts.uri.query()),
        client_request_id: client_rid,
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

/// `x-request-id` do cliente (um só valor e só se for UUID). Só informativo: o `request_id` da
/// caixa negra é sempre gerado no servidor, venha o pedido de onde vier.
fn client_request_id(headers: &HeaderMap) -> Option<Uuid> {
    let mut values = headers.get_all(X_REQUEST_ID).iter();
    match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok().and_then(|s| Uuid::parse_str(s.trim()).ok()),
        _ => None,
    }
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
        let key = clean(key, MAX_KEY_CHARS);
        if !keys.contains(&key) {
            keys.push(key);
        }
        if keys.len() == MAX_QUERY_KEYS {
            break;
        }
    }
    keys
}

/// Texto do pedido para o evento: NUL → U+FFFD (o jsonb e o `text` recusam-no) e no máximo `max`
/// caracteres.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .take(max)
        .map(|c| {
            if c == '\0' {
                char::REPLACEMENT_CHARACTER
            } else {
                c
            }
        })
        .collect()
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
    // Depois da máscara: é um UUID canónico (a máscara de PAN podia estragá-lo).
    if let (Some(id), Value::Object(m)) = (info.client_request_id, &mut v) {
        m.insert(
            "client_request_id".to_owned(),
            Value::String(id.to_string()),
        );
    }
    v
}

/// 401, 403 ou `Denied` → `denied`; 5xx → `error`; o resto (404/400/409 sem `Denied` incluídos)
/// → `success` (a app marca o IDOR com `Denied`).
fn outcome_for(status: StatusCode, denied: Option<Denied>) -> Outcome {
    if denied.is_some() || status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        Outcome::Denied
    } else if status.is_server_error() {
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
        reason: reason.map(|r| clean(r, MAX_TEXT_CHARS)),
        changes: Some(changes(info, status)),
        store_id: None,
    }
}

async fn decide(st: AuditLayerState, info: ReqInfo, ctx: AuditCtx, resp: Response) -> Response {
    let status = resp.status();
    let denied = resp.extensions().get::<Denied>().copied();
    let outcome = outcome_for(status, denied);

    // 1. Recusa (a transação do handler fez rollback): transação própria. Autenticada = sempre
    //    síncrona; anónima = contada por IP (um flood sem credenciais não serializa na cadeia).
    if outcome == Outcome::Denied {
        let reason = match denied {
            Some(Denied(r)) => r,
            None if status == StatusCode::UNAUTHORIZED => "unauthorized",
            None => "forbidden",
        };
        let ev = http_event(&info, status, Outcome::Denied, Some(reason));
        if info.authenticated {
            return or_unavailable(write_sync(&st, info.tenant, &ctx, ev).await, resp);
        }
        let th = Throttle::flood(&st, &ctx, Flood::AuthFail, Outcome::Denied);
        return throttled(&st, info.tenant, &ctx, resp, th, ev).await;
    }

    // 2. Rate-limit: contado por (ator ou IP, rota).
    if status == StatusCode::TOO_MANY_REQUESTS {
        let ev = http_event(&info, status, Outcome::Denied, Some("rate_limit"));
        let th = Throttle::rate_limit(&st, &info, &ctx, status);
        return throttled(&st, info.tenant, &ctx, resp, th, ev).await;
    }

    // 3. Mutações: autenticadas síncronas; anónimas contadas por (IP, resultado).
    if !is_read(&info.method) {
        if ctx.is_recorded() {
            return resp;
        }
        let ev = http_event(&info, status, outcome, None);
        if info.authenticated {
            return or_unavailable(write_sync(&st, info.tenant, &ctx, ev).await, resp);
        }
        let th = Throttle::flood(&st, &ctx, Flood::AnonMutation, outcome);
        return throttled(&st, info.tenant, &ctx, resp, th, ev).await;
    }

    // 6. Leitura anónima: só logs/métricas.
    if !info.authenticated {
        return resp;
    }

    let ev = http_event(&info, status, outcome, None);
    match info.class {
        // 4. Leitura sensível: síncrona.
        AuditClass::ReadSync => or_unavailable(write_sync(&st, info.tenant, &ctx, ev).await, resp),
        // 5. Leitura comum: Stream; se falhar, síncrona; se falhar, 503.
        AuditClass::ReadAsync => {
            let payload = stream_event(
                info.tenant,
                &ctx,
                &ev,
                Uuid::now_v7(),
                &rfc3339(SystemTime::now()),
            );
            match xadd(&st, &payload).await {
                Ok(()) => resp,
                Err(e) => {
                    tracing::warn!(error = ?e, "auditoria: XADD falhou; a gravar de forma síncrona");
                    or_unavailable(write_sync(&st, info.tenant, &ctx, ev).await, resp)
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
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    ev: AuditEvent,
) -> Result<(), AppError> {
    let db = &st.inner.db;
    let fut = async {
        match tenant {
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
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    ev: &AuditEvent,
    id: Uuid,
    occurred_at: &str,
) -> Value {
    let ua = ctx.user_agent_hash_hex();
    json!({
        "id": id.to_string(),
        "tenant_id": tenant.map(|t| t.as_uuid().to_string()),
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
// Contagem (429, recusas e mutações anónimas): 1.º por janela síncrono; os seguintes contam; 1
// resumo por janela no Stream.
//
// Chaves (todas com o prefixo `ns`): `audit:rl:first:<k>` (abre a janela, expira com ela),
// `audit:rl:count:<k>` (hash: n = contagem, tpl = JSON do resumo), `audit:rl:pending` (zset das
// contagens por publicar, pontuação = fim da janela em ms). `<k>` = sha256(classe, sujeito, ...): nem IPs
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

/// Classes contadas por IP (sem credenciais): recusas e mutações anónimas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flood {
    AuthFail,
    AnonMutation,
}

impl Flood {
    fn as_str(self) -> &'static str {
        match self {
            Self::AuthFail => "auth_fail",
            Self::AnonMutation => "anon_mutation",
        }
    }

    fn summary_action(self) -> &'static str {
        match self {
            Self::AuthFail => "security.auth_fail_summary",
            Self::AnonMutation => "security.anon_mutation_summary",
        }
    }
}

/// Chave de contagem e modelo do resumo (JSON do Stream com `COUNT_PLACEHOLDER` na contagem).
struct Throttle {
    key: String,
    template: Value,
}

impl Throttle {
    /// 429: por (ator autenticado ou IP, rota). O resumo fica no tenant do pedido.
    fn rate_limit(
        st: &AuditLayerState,
        info: &ReqInfo,
        ctx: &AuditCtx,
        status: StatusCode,
    ) -> Self {
        let subject = match (info.authenticated, ctx.actor_id()) {
            (true, Some(id)) => format!("a:{}:{id}", ctx.actor_type().as_str()),
            _ => ip_subject(ctx.ip()),
        };
        let route = info.route.as_deref().unwrap_or("-");
        let summary = AuditEvent {
            action: "security.rate_limit_summary",
            target_type: Some("route"),
            target_id: info.route.clone(),
            outcome: Outcome::Denied,
            reason: Some("rate_limit".to_owned()),
            changes: Some(json!({
                "status": status.as_u16(),
                "window_seconds": st.inner.window.as_secs(),
                "count": COUNT_PLACEHOLDER,
            })),
            store_id: None,
        };
        Self {
            key: digest_key(&["rate_limit", &subject, route]),
            template: summary_template(info.tenant, ctx, &summary),
        }
    }

    /// Sem credenciais: por (IP normalizado, classe, resultado), em todas as rotas e tenants. O
    /// resumo é de plataforma (sem tenant): mistura pedidos de vários tenants.
    fn flood(st: &AuditLayerState, ctx: &AuditCtx, class: Flood, outcome: Outcome) -> Self {
        let summary = AuditEvent {
            action: class.summary_action(),
            target_type: None,
            target_id: None,
            outcome,
            reason: Some(class.as_str().to_owned()),
            changes: Some(json!({
                "class": class.as_str(),
                "window_seconds": st.inner.window.as_secs(),
                "count": COUNT_PLACEHOLDER,
            })),
            store_id: None,
        };
        Self {
            key: digest_key(&[class.as_str(), outcome.as_str(), &ip_subject(ctx.ip())]),
            template: summary_template(None, ctx, &summary),
        }
    }
}

fn summary_template(tenant: Option<TenantId>, ctx: &AuditCtx, summary: &AuditEvent) -> Value {
    stream_event(
        tenant,
        ctx,
        summary,
        Uuid::now_v7(),
        &rfc3339(SystemTime::now()),
    )
}

/// IP para as chaves de contagem: IPv4 inteiro; IPv6 pelo /64 (a unidade que um cliente recebe).
fn ip_subject(ip: Option<IpAddr>) -> String {
    match ip {
        Some(IpAddr::V4(v4)) => format!("ip:{v4}"),
        Some(IpAddr::V6(v6)) => {
            let net = Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX));
            format!("ip6:{net}/64")
        }
        None => "none".to_owned(),
    }
}

/// sha256 das partes (primeiros 16 bytes em hex): nem IPs nem ids ficam no nome das chaves.
fn digest_key(parts: &[&str]) -> String {
    let digest = Sha256::digest(parts.join("\n").as_bytes());
    digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// 1.º por chave em cada janela: `first` síncrono; os seguintes só contam; 1 resumo por janela.
async fn throttled(
    st: &AuditLayerState,
    tenant: Option<TenantId>,
    ctx: &AuditCtx,
    resp: Response,
    th: Throttle,
    first_event: AuditEvent,
) -> Response {
    let first = st.key(&format!("audit:rl:first:{}", th.key));
    let count = st.key(&format!("audit:rl:count:{}", th.key));

    let mut cmd = redis::cmd("EVAL");
    cmd.arg(HIT_SCRIPT)
        .arg(4)
        .arg(&first)
        .arg(&count)
        .arg(st.key(PENDING_KEY))
        .arg(st.key(STREAM_KEY))
        .arg(st.window_ms())
        .arg(th.template.to_string())
        .arg(now_ms());
    match redis_query::<i64>(st, cmd).await {
        Ok(0) => {
            let res = write_sync(st, tenant, ctx, first_event).await;
            if res.is_err() {
                // Reabre a janela: o próximo volta a tentar a escrita síncrona.
                let mut del = redis::cmd("DEL");
                del.arg(&first);
                if let Err(e) = redis_query::<i64>(st, del).await {
                    tracing::warn!(error = ?e, "auditoria: não foi possível reabrir a janela");
                }
            }
            or_unavailable(res, resp)
        }
        Ok(1) => {
            // 1.º contado nesta janela: no fim dela sai o resumo.
            let st = st.clone();
            let wait = st.inner.window + Duration::from_millis(200);
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                if let Err(e) = st.flush_due_rate_limit_summaries().await {
                    tracing::warn!(error = ?e, "auditoria: resumos por publicar");
                }
            });
            resp
        }
        Ok(_) => resp,
        Err(e) => {
            tracing::error!(error = ?e, "auditoria: Redis indisponível para a contagem; resposta 503");
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
    fn client_request_id_only_single_uuid() {
        let id = Uuid::now_v7();
        let mut h = HeaderMap::new();
        if let Ok(v) = id.to_string().parse() {
            h.insert(X_REQUEST_ID, v);
        }
        assert_eq!(client_request_id(&h), Some(id));
        let mut bad = HeaderMap::new();
        bad.insert(X_REQUEST_ID, HeaderValue::from_static("nope"));
        assert_eq!(client_request_id(&bad), None);
        h.append(X_REQUEST_ID, HeaderValue::from_static("x"));
        assert_eq!(client_request_id(&h), None, "dois valores = nenhum");
        assert_eq!(client_request_id(&HeaderMap::new()), None);
    }

    #[test]
    fn clean_replaces_nul_and_bounds_chars() {
        assert_eq!(clean("a\0b", 10), "a\u{FFFD}b");
        assert_eq!(clean(&"é".repeat(300), MAX_TEXT_CHARS).chars().count(), 256);
        assert_eq!(clean("abc", 2), "ab");
        let k = query_keys(Some("a%00b=1"));
        assert_eq!(k, vec!["a%00b"], "a query não é descodificada");
    }

    #[test]
    fn outcome_defaults() {
        assert_eq!(outcome_for(StatusCode::UNAUTHORIZED, None), Outcome::Denied);
        assert_eq!(outcome_for(StatusCode::FORBIDDEN, None), Outcome::Denied);
        assert_eq!(
            outcome_for(StatusCode::NOT_FOUND, Some(Denied("idor"))),
            Outcome::Denied
        );
        for s in [
            StatusCode::NOT_FOUND,
            StatusCode::BAD_REQUEST,
            StatusCode::CONFLICT,
            StatusCode::OK,
        ] {
            assert_eq!(outcome_for(s, None), Outcome::Success, "{s}");
        }
        assert_eq!(
            outcome_for(StatusCode::SERVICE_UNAVAILABLE, None),
            Outcome::Error
        );
    }

    #[test]
    fn ip_subject_ipv6_by_64() {
        let ip = |s: &str| s.parse::<IpAddr>().ok();
        assert_eq!(
            ip_subject(ip("2001:db8:1:2::1")),
            ip_subject(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"))
        );
        assert_ne!(
            ip_subject(ip("2001:db8:1:2::1")),
            ip_subject(ip("2001:db8:1:3::1"))
        );
        assert_eq!(ip_subject(ip("2001:db8:1:2::1")), "ip6:2001:db8:1:2::/64");
        assert_ne!(ip_subject(ip("192.0.2.1")), ip_subject(ip("192.0.2.2")));
        assert_eq!(ip_subject(None), "none");
    }

    #[test]
    fn keys_differ_by_class() {
        assert_ne!(
            digest_key(&["auth_fail", "denied", "ip:192.0.2.1"]),
            digest_key(&["anon_mutation", "denied", "ip:192.0.2.1"])
        );
        assert_eq!(digest_key(&["x"]).len(), 32);
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
