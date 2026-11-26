//! 2FA TOTP de backoffice (cartão 02/20; spec 12 §3, ASVS L3 em identity/admin).
//!
//! - RFC 6238: HMAC-SHA1, 6 dígitos, passo de 30 s, tolerância ±1 passo; segredo de 20 bytes do
//!   CSPRNG do SO, gravado cifrado (`crypto`, AAD = id do utilizador) em `users.totp_secret_enc`.
//! - Anti-repetição: o último passo aceite por utilizador fica no Redis (TTL 90 s); só entra um
//!   passo MAIOR do que o último (o mesmo código nunca entra duas vezes). Redis em baixo → 503.
//! - Travão: o do login (`throttle`, INCR antecipado), com chaves por UTILIZADOR (prefixo
//!   `mfa:<id>:`; a parte "IP" do travão fica por utilizador): a 5.ª falha arma espera exponencial
//!   (1 s, 2 s, 4 s… até 900 s) → 429 com `Retry-After`; nunca há bloqueio definitivo. Sem captcha.
//! - Endpoints (`RequireStaffPreMfa` + CSRF: o 2FA obrigatório do cartão 19 recusa tudo o resto
//!   antes disto):
//!   `POST /api/v1/staff/mfa/totp/enroll`  → segredo novo (TOTP ainda desligado);
//!   `POST /api/v1/staff/mfa/totp/confirm` → liga o TOTP, 10 códigos de recuperação novos (os
//!   anteriores são apagados), sessão rodada e elevada;
//!   `POST /api/v1/staff/mfa/verify`       → TOTP ou código de recuperação; sessão rodada e elevada.
//! - Caixa negra: `mfa.totp_enroll_started`, `mfa.totp_enabled`, `mfa.verify` (sucesso na transação da
//!   mudança; recusa numa transação própria). Nunca o código, o segredo nem os códigos de
//!   recuperação (nem nos logs).
//! - Desligar o TOTP: não existe aqui (obrigatório para super_admin/tenant_admin; os outros papéis
//!   ficam para o épico backoffice).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use deadpool_redis::redis;
use hmac::{Hmac, KeyInit, Mac};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    audit::{AuditCtx, AuditEvent, Outcome},
    config::Config,
    error::{AppError, FieldError},
    identity::{
        crypto::EncKey,
        elevate::{NoImpersonation, OwnTx},
        http::{CurrentSession, SessionInfo, Sessions, no_store},
        rbac::RequireStaffPreMfa,
        recovery::{self, RecoveryKey},
        session::{self, CookieKind, CookieValue, SessionKind, Subject},
        throttle::{self, Gate, Keys, Limits},
    },
    state::AppState,
    tenancy::{TenantId, db::db_error},
};

/// Passo TOTP (segundos).
pub const STEP_SECS: u64 = 30;
/// Dígitos do código.
pub const DIGITS: u32 = 6;
/// Bytes do segredo.
pub const SECRET_BYTES: usize = 20;
/// Passos aceites antes e depois do atual.
pub const SKEW_STEPS: u64 = 1;
/// Emissor mostrado na app de autenticação.
pub const ISSUER: &str = "PT Market";
/// Máximo de caracteres aceites no campo `code`.
pub const MAX_CODE_CHARS: usize = 32;
/// Vida da marca anti-repetição (cobre a janela de ±1 passo).
pub const REPLAY_TTL: Duration = Duration::from_secs(150);
const REDIS_TIMEOUT: Duration = Duration::from_millis(500);

/// Recusa por código errado (ou fora da janela).
pub const REASON_BAD_CODE: &str = "bad_code";
/// Recusa por código TOTP já usado (anti-repetição).
pub const REASON_REPLAYED: &str = "replayed";

// ---------------------------------------------------------------------------------------------
// RFC 4226 / 6238
// ---------------------------------------------------------------------------------------------

/// HOTP antes do módulo: os 31 bits da truncagem dinâmica (RFC 4226 §5.3).
pub fn hotp_raw(secret: &[u8], counter: u64) -> u32 {
    let Ok(mut mac) = <Hmac<Sha1> as KeyInit>::new_from_slice(secret) else {
        return 0; // HMAC aceita chaves de qualquer tamanho: inalcançável.
    };
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = usize::from(h[h.len() - 1] & 0x0f);
    u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]])
}

/// Código TOTP de 6 dígitos do passo `step`.
pub fn code(secret: &[u8], step: u64) -> u32 {
    hotp_raw(secret, step) % 10u32.pow(DIGITS)
}

/// Passo TOTP do instante `t`.
pub fn step_at(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / STEP_SECS)
        .unwrap_or(0)
}

/// Passo da janela [agora - 1, agora + 1] cujo código é `given` (comparação em tempo constante,
/// sempre os 3 passos). A mesma verificação no `confirm`/`verify` e no CLI `ptmarket-admin`.
pub fn matching_step(secret: &[u8], now: u64, given: u32) -> Option<u64> {
    let mut found = None;
    for step in now.saturating_sub(SKEW_STEPS)..=now.saturating_add(SKEW_STEPS) {
        if bool::from(code(secret, step).ct_eq(&given)) {
            found = Some(step);
        }
    }
    found
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 RFC 4648 em maiúsculas, sem padding (formato das apps de autenticação).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buf >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((buf << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Inverso de `base32_encode` (ignora `=`, aceita minúsculas). `None` se tiver outro carácter.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())?;
        buf = (buf << 5) | u32::try_from(v).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Percent-encoding (RFC 3986: só os não reservados passam).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// URI `otpauth://` (formato Key Uri das apps de autenticação).
pub fn otpauth_uri(account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        pct(ISSUER),
        pct(account),
        pct(ISSUER)
    )
}

// ---------------------------------------------------------------------------------------------
// Dependências
// ---------------------------------------------------------------------------------------------

/// Falhas SEGUIDAS (sem um sucesso pelo meio) a partir das quais a sessão pré-MFA é revogada
/// (`auth.logout`, reason `mfa_failures`): obriga a um login novo.
pub const MFA_REVOKE_AFTER: u64 = 10;
/// Motivo da revogação por falhas de 2FA.
pub const REASON_MFA_FAILURES: &str = "mfa_failures";

/// Limites do travão do 2FA: os do login, mas com memória de 24 h e espera máxima de 1 h (o
/// contador nunca expira antes da espera; nada é permanente: tudo expira sozinho).
pub fn mfa_limits() -> Limits {
    Limits {
        fail_ttl: Duration::from_secs(24 * 3600),
        backoff_cap: Duration::from_secs(3600),
        ..Limits::default()
    }
}

/// Dependências do 2FA: chaveiro dos segredos, subchave dos códigos de recuperação e limites.
#[derive(Clone, Debug)]
pub struct Totp {
    key: EncKey,
    recovery: RecoveryKey,
    limits: Limits,
}

impl Totp {
    pub fn new(key: EncKey) -> Result<Self, AppError> {
        Ok(Self {
            recovery: RecoveryKey::from_enc_key(&key)?,
            key,
            limits: mfa_limits(),
        })
    }

    /// `TOTP_ENC_KEY` (obrigatória em staging/production; dev → chave fixa) e as antigas de
    /// `TOTP_ENC_KEYS_OLD` (só decifram).
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let key = EncKey::from_base64(&cfg.totp_enc_key())
            .and_then(|k| k.with_old(&cfg.totp_enc_keys_old))
            .map_err(|_| anyhow::anyhow!("TOTP_ENC_KEY/TOTP_ENC_KEYS_OLD inválida"))?;
        Self::new(key).map_err(|_| anyhow::anyhow!("subchave de recuperação indisponível"))
    }

    /// Só para testes: limites do travão mais curtos.
    #[cfg(feature = "test-support")]
    pub fn with_limits_for_tests(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }
}

// ---------------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------------

/// Código TOTP (6 dígitos) ou, no `verify`, código de recuperação (10 caracteres).
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MfaCodeRequest {
    pub code: String,
}

impl std::fmt::Debug for MfaCodeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MfaCodeRequest { code: [REDACTED] }")
    }
}

/// Início da ativação do TOTP: mostrar o QR (`otpauth_uri`) ou o segredo para escrever à mão.
#[derive(Serialize, ToSchema)]
pub struct TotpEnrollResponse {
    pub otpauth_uri: String,
    pub secret_base32: String,
}

impl std::fmt::Debug for TotpEnrollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpEnrollResponse { otpauth_uri: [REDACTED], secret_base32: [REDACTED] }")
    }
}

/// TOTP ativo: códigos de recuperação mostrados UMA vez (guardar fora da app).
#[derive(Serialize, ToSchema)]
pub struct TotpConfirmResponse {
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for TotpConfirmResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpConfirmResponse { recovery_codes: [REDACTED] }")
    }
}

/// O que o utilizador escreveu.
enum GivenCode {
    Totp(u32),
    Recovery(String),
    Invalid,
}

fn validated(body: Result<Json<MfaCodeRequest>, JsonRejection>) -> Result<String, AppError> {
    let invalid = |message: &str| {
        AppError::Validation(vec![FieldError {
            field: "code".to_owned(),
            message: message.to_owned(),
        }])
    };
    let Ok(Json(req)) = body else {
        return Err(AppError::Validation(vec![FieldError {
            field: "body".to_owned(),
            message: "Corpo JSON inválido, com campos em falta ou desconhecidos.".to_owned(),
        }]));
    };
    let n = req.code.chars().count();
    if n == 0 || n > MAX_CODE_CHARS {
        return Err(invalid("Indique o código (até 32 caracteres)."));
    }
    Ok(req.code)
}

/// Código TOTP escrito pelo utilizador (6 dígitos, espaços ignorados); `None` se não tiver essa forma.
pub fn parse_totp(raw: &str) -> Option<u32> {
    match classify(raw) {
        GivenCode::Totp(c) => Some(c),
        _ => None,
    }
}

fn classify(raw: &str) -> GivenCode {
    let digits: String = raw.chars().filter(|c| *c != ' ').collect();
    if digits.len() == DIGITS as usize && digits.bytes().all(|b| b.is_ascii_digit()) {
        return digits.parse().map_or(GivenCode::Invalid, GivenCode::Totp);
    }
    recovery::normalize(raw).map_or(GivenCode::Invalid, GivenCode::Recovery)
}

// ---------------------------------------------------------------------------------------------
// Redis: travão e anti-repetição
// ---------------------------------------------------------------------------------------------

fn throttle_keys(ns: &str, user: Uuid) -> Keys {
    Keys::new(&format!("{ns}mfa:{user}:"), "user", None)
}

/// Conta a tentativa; espera em curso → 429. Redis em baixo → 503 (sem captcha que o substitua).
/// Devolve as falhas seguidas da conta, já com esta tentativa.
async fn gate(s: &Sessions, limits: &Limits, keys: &Keys) -> Result<u64, AppError> {
    let Some(snap) = throttle::begin(s.redis(), keys, limits).await else {
        return Err(AppError::ServiceUnavailable);
    };
    match throttle::decide(Some(snap), limits) {
        Gate::TooMany { retry_after_s } => {
            throttle::not_attempted(s.redis(), keys).await;
            Err(AppError::TooManyRequests { retry_after_s })
        }
        Gate::Proceed { .. } => Ok(snap.acct_failures),
    }
}

/// Só aceita `step` se for maior do que o último aceite (atómico).
const MARK_STEP_SCRIPT: &str = r#"
local last = tonumber(redis.call('GET', KEYS[1]) or '-1') or -1
local step = tonumber(ARGV[1])
if step <= last then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1
"#;

/// Marca `step` como o último passo TOTP aceite de `user` (chave `<ns>mfa:totp:last:<id>`, TTL
/// `REPLAY_TTL`). `false` = passo já usado (ou anterior). Também usada pelo CLI `ptmarket-admin`
/// para o código do enroll (ns vazio em produção). Redis em baixo → `ServiceUnavailable`.
pub async fn mark_step(
    redis: &deadpool_redis::Pool,
    ns: &str,
    user: Uuid,
    step: u64,
) -> Result<bool, AppError> {
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(MARK_STEP_SCRIPT)
        .arg(1)
        .arg(format!("{ns}mfa:totp:last:{user}"))
        .arg(step)
        .arg(u64::try_from(REPLAY_TTL.as_millis()).unwrap_or(150_000));
    let fut = async {
        let mut conn = redis.get().await.map_err(|e| {
            tracing::error!(error = %e, "2FA: Redis indisponível");
            AppError::ServiceUnavailable
        })?;
        cmd.query_async::<i64>(&mut conn).await.map_err(|e| {
            tracing::error!(error = %e, "2FA: comando Redis falhou");
            AppError::ServiceUnavailable
        })
    };
    let n = tokio::time::timeout(REDIS_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::ServiceUnavailable)??;
    Ok(n == 1)
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

/// Resultado de uma tentativa com código.
enum Attempt<T> {
    Passed(T),
    Failed(&'static str),
}

fn deps(cur: &CurrentSession) -> Result<Totp, AppError> {
    cur.sessions().totp().cloned().ok_or_else(|| {
        tracing::error!("2FA sem TOTP_ENC_KEY (Sessions::with_totp); 503");
        AppError::ServiceUnavailable
    })
}

/// Sessão do pedido (o extractor já exigiu uma sessão `user`); sessões de impersonação não fazem 2FA
/// (`NoImpersonation` já as recusou com `Denied("impersonation")`; isto é só a segunda barreira).
fn own_session(cur: &CurrentSession, ctx: &AuditCtx) -> Result<SessionInfo, AppError> {
    if ctx.impersonator_id().is_some() {
        return Err(AppError::Forbidden);
    }
    cur.info().ok_or(AppError::Unauthorized)
}

fn user_event(
    action: &'static str,
    user: Uuid,
    outcome: Outcome,
    reason: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        action,
        target_type: Some("user"),
        target_id: Some(user.to_string()),
        outcome,
        reason: reason.map(str::to_owned),
        changes: None,
        store_id: None,
    }
}

/// Um pedido com código (`confirm`/`verify`): dependências, sessão, utilizador e chaves do travão.
struct Call<'a> {
    st: &'a AppState,
    cur: &'a CurrentSession,
    ctx: &'a AuditCtx,
    totp: Totp,
    info: SessionInfo,
    user: Uuid,
    keys: Keys,
    /// Falhas seguidas, contando esta tentativa (se falhar).
    failures: u64,
}

impl<'a> Call<'a> {
    /// Valida o corpo (422 não conta no travão) e conta a tentativa (429 se em espera).
    async fn start(
        st: &'a AppState,
        cur: &'a CurrentSession,
        ctx: &'a AuditCtx,
        user: Uuid,
        body: Result<Json<MfaCodeRequest>, JsonRejection>,
    ) -> Result<(Self, String), AppError> {
        let totp = deps(cur)?;
        let info = own_session(cur, ctx)?;
        let raw = validated(body)?;
        let keys = throttle_keys(cur.sessions().ns(), user);
        let failures = gate(cur.sessions(), &totp.limits, &keys).await?;
        let call = Self {
            st,
            cur,
            ctx,
            totp,
            info,
            user,
            keys,
            failures,
        };
        Ok((call, raw))
    }

    fn tenant(&self) -> Option<TenantId> {
        self.info.tenant()
    }

    async fn begin(&self) -> Result<OwnTx, AppError> {
        OwnTx::begin(&self.st.db_primary, self.tenant(), self.ctx).await
    }

    /// `given` confere com o segredo cifrado `enc` na janela ±1 E o passo ainda não foi usado.
    async fn check_totp(&self, enc: &str, given: u32) -> Result<Option<&'static str>, AppError> {
        let secret = self.totp.key.decrypt(enc, self.user.as_bytes())?;
        let found = matching_step(&secret, step_at(SystemTime::now()), given);
        drop(secret);
        let Some(step) = found else {
            return Ok(Some(REASON_BAD_CODE));
        };
        if !mark_step(
            self.cur.sessions().redis(),
            self.cur.sessions().ns(),
            self.user,
            step,
        )
        .await?
        {
            return Ok(Some(REASON_REPLAYED));
        }
        Ok(None)
    }

    /// Fim da tentativa: sucesso → limpa a sessão antiga e as falhas; falha de código → conta no
    /// travão, `denied` (transação própria) e 401; outro erro → a tentativa não conta.
    async fn finish<T>(
        &self,
        action: &'static str,
        res: Result<Attempt<(T, CookieValue)>, AppError>,
    ) -> Result<(T, CookieValue), AppError> {
        let s = self.cur.sessions();
        match res {
            Ok(Attempt::Passed(v)) => {
                if let Err(e) = session::forget(s.redis(), s.ns(), self.info.id).await {
                    tracing::warn!(error = ?e, "2FA: inatividade da sessão antiga não apagada");
                }
                throttle::succeeded(s.redis(), &self.keys).await;
                Ok(v)
            }
            Ok(Attempt::Failed(reason)) => {
                throttle::failed(s.redis(), &self.keys, &self.totp.limits).await;
                let mut tx = self.begin().await?;
                tx.record(user_event(action, self.user, Outcome::Denied, Some(reason)))
                    .await?;
                // À 10.ª falha seguida: a sessão pré-MFA acaba (novo login obrigatório).
                let revoke = self.failures >= MFA_REVOKE_AFTER;
                let mut email = None;
                if revoke {
                    email = sqlx::query_scalar!("SELECT email FROM users WHERE id = $1", self.user)
                        .fetch_optional(tx.conn())
                        .await
                        .map_err(db_error)?;
                    tx.revoke(self.info.id).await?;
                    tx.record(AuditEvent {
                        action: "auth.logout",
                        target_type: Some("session"),
                        target_id: Some(self.info.id.as_uuid().to_string()),
                        outcome: Outcome::Success,
                        reason: Some(REASON_MFA_FAILURES.to_owned()),
                        changes: None,
                        store_id: None,
                    })
                    .await?;
                }
                tx.commit().await.map_err(|e| {
                    tracing::error!(error = ?e, "2FA: recusa não gravada; 503");
                    AppError::ServiceUnavailable
                })?;
                if revoke && let Err(e) = session::forget(s.redis(), s.ns(), self.info.id).await {
                    tracing::warn!(error = ?e, "2FA: inatividade da sessão revogada não apagada");
                }
                // O login seguinte desta conta exige captcha (mesmo com a password certa).
                if let (Some(email), Some(login)) = (email, s.login())
                    && let Err(e) = login.force_staff_captcha(s.redis(), s.ns(), &email).await
                {
                    tracing::error!(error = ?e, "2FA: captcha do próximo login não forçado");
                }
                Err(AppError::Unauthorized)
            }
            Err(e) => {
                throttle::not_attempted(s.redis(), &self.keys).await;
                Err(e)
            }
        }
    }

    /// Resposta com o cookie da sessão nova (`no-store`).
    fn respond(&self, mut resp: Response, value: &CookieValue) -> Result<Response, AppError> {
        let tenant = self.tenant();
        let kind = match tenant {
            Some(_) => CookieKind::Tenant,
            None => CookieKind::Platform,
        };
        let lifetime = SessionKind::of(Subject::User(self.user), tenant).max_lifetime();
        resp.headers_mut()
            .append(SET_COOKIE, session::set_cookie(kind, value, lifetime)?);
        Ok(no_store(resp))
    }

    async fn confirm_tx(&self, raw: &str) -> Result<Attempt<(Vec<String>, CookieValue)>, AppError> {
        let user = self.user;
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT totp_secret_enc, totp_enabled FROM users WHERE id = $1 FOR UPDATE",
            user
        )
        .fetch_optional(tx.conn())
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Err(AppError::Unauthorized);
        };
        let (false, Some(enc)) = (row.totp_enabled, row.totp_secret_enc) else {
            return Err(AppError::Conflict);
        };
        let GivenCode::Totp(given) = classify(raw) else {
            return Ok(Attempt::Failed(REASON_BAD_CODE));
        };
        if let Some(reason) = self.check_totp(&enc, given).await? {
            return Ok(Attempt::Failed(reason));
        }
        sqlx::query!(
            "UPDATE users SET totp_enabled = true, updated_at = now() WHERE id = $1",
            user
        )
        .execute(tx.conn())
        .await
        .map_err(db_error)?;
        let codes = recovery::replace(tx.conn(), &self.totp.recovery, user).await?;
        let (_, value) = tx
            .open_elevated(Some(self.info.id), user, self.tenant(), self.ctx)
            .await?;
        tx.record(user_event("mfa.totp_enabled", user, Outcome::Success, None))
            .await?;
        tx.commit().await?;
        Ok(Attempt::Passed((codes, value)))
    }

    async fn verify_tx(&self, raw: &str) -> Result<Attempt<((), CookieValue)>, AppError> {
        let user = self.user;
        let mut tx = self.begin().await?;
        let row = sqlx::query!(
            "SELECT totp_secret_enc, totp_enabled FROM users WHERE id = $1",
            user
        )
        .fetch_optional(tx.conn())
        .await
        .map_err(db_error)?;
        let Some(row) = row else {
            return Err(AppError::Unauthorized);
        };
        let (true, Some(enc)) = (row.totp_enabled, row.totp_secret_enc) else {
            return Err(AppError::Conflict);
        };
        let method = match classify(raw) {
            GivenCode::Totp(given) => {
                if let Some(reason) = self.check_totp(&enc, given).await? {
                    return Ok(Attempt::Failed(reason));
                }
                "totp"
            }
            GivenCode::Recovery(code) => {
                // 0 linhas ou 23514: a transação cai com o `drop` (ROLLBACK).
                if !recovery::consume(tx.conn(), &self.totp.recovery, user, &code).await? {
                    return Ok(Attempt::Failed(REASON_BAD_CODE));
                }
                "recovery_code"
            }
            GivenCode::Invalid => return Ok(Attempt::Failed(REASON_BAD_CODE)),
        };
        let (_, value) = tx
            .open_elevated(Some(self.info.id), user, self.tenant(), self.ctx)
            .await?;
        let mut ev = user_event("mfa.verify", user, Outcome::Success, None);
        ev.changes = Some(serde_json::json!({ "method": method }));
        tx.record(ev).await?;
        tx.commit().await?;
        Ok(Attempt::Passed(((), value)))
    }
}

/// Inicia a ativação do TOTP: segredo novo (20 bytes), gravado cifrado com `totp_enabled = false`.
/// Só enquanto o TOTP não estiver ativo (senão 409).
#[utoipa::path(
    post,
    path = "/api/v1/staff/mfa/totp/enroll",
    tag = "staff",
    params(("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")),
    responses(
        (status = 200, description = "Segredo novo (mostrado só agora); confirmar com `/confirm`", body = TotpEnrollResponse),
        (status = 401, description = "Sem sessão de backoffice"),
        (status = 403, description = "Sem papel neste host, token CSRF/Origin inválidos ou sessão de impersonação (`impersonation`)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 409, description = "O TOTP já está ativo"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn enroll(
    State(st): State<AppState>,
    RequireStaffPreMfa(staff): RequireStaffPreMfa,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    cur: CurrentSession,
) -> Result<Response, AppError> {
    let totp = deps(&cur)?;
    let info = own_session(&cur, &ctx)?;
    let user = staff.user_id;
    let mut tx = OwnTx::begin(&st.db_primary, info.tenant(), &ctx).await?;
    let row = sqlx::query!(
        "SELECT email, totp_enabled FROM users WHERE id = $1 FOR UPDATE",
        user
    )
    .fetch_optional(tx.conn())
    .await
    .map_err(db_error)?;
    let Some(row) = row else {
        return Err(AppError::Unauthorized);
    };
    if row.totp_enabled {
        return Err(AppError::Conflict);
    }
    let mut secret = Zeroizing::new([0u8; SECRET_BYTES]);
    OsRng
        .try_fill_bytes(secret.as_mut())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("CSPRNG do SO indisponível")))?;
    let enc = totp.key.encrypt(secret.as_ref(), user.as_bytes())?;
    sqlx::query!(
        "UPDATE users SET totp_secret_enc = $2, updated_at = now() WHERE id = $1",
        user,
        enc
    )
    .execute(tx.conn())
    .await
    .map_err(db_error)?;
    tx.record(user_event(
        "mfa.totp_enroll_started",
        user,
        Outcome::Success,
        None,
    ))
    .await?;
    tx.commit().await?;
    let secret_base32 = base32_encode(secret.as_ref());
    let body = TotpEnrollResponse {
        otpauth_uri: otpauth_uri(&row.email, &secret_base32),
        secret_base32,
    };
    Ok(no_store(Json(body).into_response()))
}

/// Confirma a ativação com um código TOTP: `totp_enabled = true`, 10 códigos de recuperação novos
/// Confirma a ativação com um código TOTP: `totp_enabled = true`, 10 códigos de recuperação novos
/// (os anteriores são apagados; mostrados UMA vez) e a sessão rodada já com o 2FA feito.
#[utoipa::path(
    post,
    path = "/api/v1/staff/mfa/totp/confirm",
    tag = "staff",
    request_body = MfaCodeRequest,
    params(("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")),
    responses(
        (status = 200, description = "TOTP ativo; sessão nova (Set-Cookie) com o 2FA feito; códigos de recuperação mostrados só agora", body = TotpConfirmResponse),
        (status = 401, description = "Sem sessão de backoffice, ou código errado/repetido"),
        (status = 403, description = "Sem papel neste host, token CSRF/Origin inválidos ou sessão de impersonação (`impersonation`)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 409, description = "TOTP já ativo ou ativação não iniciada"),
        (status = 422, description = "Dados inválidos"),
        (status = 429, description = "Demasiadas falhas; repetir depois de `Retry-After` segundos"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn confirm(
    State(st): State<AppState>,
    RequireStaffPreMfa(staff): RequireStaffPreMfa,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    cur: CurrentSession,
    body: Result<Json<MfaCodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let (call, raw) = Call::start(&st, &cur, &ctx, staff.user_id, body).await?;
    let res = call.confirm_tx(&raw).await;
    let (codes, value) = call.finish("mfa.totp_enabled", res).await?;
    let body = TotpConfirmResponse {
        recovery_codes: codes,
    };
    call.respond(Json(body).into_response(), &value)
}

/// Faz o 2FA da sessão com um código TOTP ou um código de recuperação (uso único): a sessão é
/// rodada e fica com `mfa_verified_at`.
#[utoipa::path(
    post,
    path = "/api/v1/staff/mfa/verify",
    tag = "staff",
    request_body = MfaCodeRequest,
    params(("X-CSRF-Token" = String, Header, description = "Token CSRF da sessão")),
    responses(
        (status = 204, description = "2FA feito; sessão nova (Set-Cookie)"),
        (status = 401, description = "Sem sessão de backoffice, ou código errado/repetido/já usado"),
        (status = 403, description = "Sem papel neste host, token CSRF/Origin inválidos ou sessão de impersonação (`impersonation`)"),
        (status = 404, description = "Host desconhecido ou tenant inativo"),
        (status = 409, description = "O TOTP não está ativo (ativar primeiro)"),
        (status = 422, description = "Dados inválidos"),
        (status = 429, description = "Demasiadas falhas; repetir depois de `Retry-After` segundos"),
        (status = 503, description = "Serviço temporariamente indisponível")
    )
)]
pub async fn verify(
    State(st): State<AppState>,
    RequireStaffPreMfa(staff): RequireStaffPreMfa,
    _ni: NoImpersonation,
    ctx: AuditCtx,
    cur: CurrentSession,
    body: Result<Json<MfaCodeRequest>, JsonRejection>,
) -> Result<Response, AppError> {
    let (call, raw) = Call::start(&st, &cur, &ctx, staff.user_id, body).await?;
    let res = call.verify_tx(&raw).await;
    let ((), value) = call.finish("mfa.verify", res).await?;
    call.respond(StatusCode::NO_CONTENT.into_response(), &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, apêndice B (SHA-1, 8 dígitos; segredo ASCII "12345678901234567890").
    #[test]
    fn rfc6238_vectors() {
        let k = b"12345678901234567890";
        for (t, want) in [
            (59u64, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(hotp_raw(k, t / STEP_SECS) % 100_000_000, want, "t={t}");
            assert_eq!(code(k, t / STEP_SECS), want % 1_000_000, "t={t}");
        }
    }

    #[test]
    fn window_is_plus_minus_one_step() {
        let k = b"12345678901234567890";
        let now = 1_000_000;
        assert_eq!(matching_step(k, now, code(k, now - 1)), Some(now - 1));
        assert_eq!(matching_step(k, now, code(k, now + 1)), Some(now + 1));
        let far = code(k, now + 2);
        if (now - 1..=now + 1).all(|s| code(k, s) != far) {
            assert_eq!(matching_step(k, now, far), None);
        }
    }

    #[test]
    fn base32_roundtrip_and_uri() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(
            base32_decode("mzxw6ytboi======").as_deref(),
            Some(&b"foobar"[..])
        );
        let s = [0xA5u8; SECRET_BYTES];
        assert_eq!(base32_encode(&s).len(), 32);
        assert_eq!(base32_decode(&base32_encode(&s)).as_deref(), Some(&s[..]));
        assert!(base32_decode("ABC1").is_none());
        assert_eq!(
            otpauth_uri("ana+1@x.pt", "ABC"),
            "otpauth://totp/PT%20Market:ana%2B1%40x.pt?secret=ABC&issuer=PT%20Market&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn classify_codes() {
        assert!(matches!(classify("012 345"), GivenCode::Totp(12_345)));
        assert!(matches!(classify("abcde-fghjk"), GivenCode::Recovery(c) if c == "ABCDEFGHJK"));
        assert!(matches!(classify("12345"), GivenCode::Invalid));
        assert!(matches!(classify("１２３４５６"), GivenCode::Invalid));
    }
}
