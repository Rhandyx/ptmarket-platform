//! Travão do login de clientes (cartão 02/18; spec 12 §2): contadores no Redis, nunca na BD.
//!
//! Identificador da conta: `account_hash` = HMAC-SHA256(`ACCOUNT_HASH_KEY`, email normalizado) em
//! hex (o mesmo na caixa negra e nas chaves Redis; sem a chave não se testa um email contra ele).
//! O IP conta inteiro em IPv4 e pelo /64 em IPv6 (`ip_bucket`), também em sha256. Chaves (prefixo
//! `ns` só nos testes):
//! - `login:rate:ip:<h>`: TODAS as tentativas do IP numa janela de 60 s; acima de 20 → 429.
//! - `login:rate:acct:<h>`: TODAS as tentativas do email em 15 min; acima de 10 → captcha (nunca
//!   429 só pelo email: seria DoS à conta alheia).
//! - `login:fail:acct:<h>` / `login:fail:ip:<h>`: incrementados ANTES de verificar (sem TOCTOU:
//!   pedidos em paralelo veem valores diferentes), TTL 15 min renovado em cada tentativa. Sucesso:
//!   DEL do da conta e DECR do do IP (nunca abaixo de 0). Captcha recusado: os dois são desfeitos
//!   (não houve tentativa de credenciais). Mais de 3 (conta OU IP), contando a atual → captcha.
//! - `login:lock:ip:<h>`: depois da n.ª falha do IP (n ≥ 5), espera de 2^(n-5) s (teto 900 s e nunca
//!   mais do que o TTL do contador), armada no mesmo script → 429 com `Retry-After`. O atraso por
//!   conta é o captcha (sem 429): falhas contra X a partir de outro IP nunca impedem X de entrar.
//!
//! Nunca há bloqueio definitivo: tudo expira sozinho. Redis indisponível → captcha em todos os
//! logins (degrada para o lado seguro: não abre nem tranca).

use std::{net::IpAddr, time::Duration};

use deadpool_redis::redis;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::{error::AppError, http::client_ip::ip_bucket};

/// Timeout de cada ida ao Redis.
const REDIS_TIMEOUT: Duration = Duration::from_millis(500);

/// Limites do travão. `Default` = produção; só os testes usam outros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Vida dos contadores de falhas (renovada em cada falha).
    pub fail_ttl: Duration,
    /// Falhas (conta ou IP) a partir das quais o captcha é obrigatório.
    pub captcha_after: u64,
    /// N.º da falha do IP a partir da qual há espera (2^(n - backoff_from) × `backoff_unit`).
    pub backoff_from: u64,
    pub backoff_unit: Duration,
    pub backoff_cap: Duration,
    /// Tentativas por IP por `ip_window` (acima → 429).
    pub ip_max: u64,
    pub ip_window: Duration,
    /// Tentativas por email por `email_window` (acima → captcha).
    pub email_max: u64,
    pub email_window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            fail_ttl: Duration::from_secs(15 * 60),
            captcha_after: 3,
            backoff_from: 5,
            backoff_unit: Duration::from_secs(1),
            backoff_cap: Duration::from_secs(900),
            ip_max: 20,
            ip_window: Duration::from_secs(60),
            email_max: 10,
            email_window: Duration::from_secs(15 * 60),
        }
    }
}

/// Contadores lidos no início da tentativa (já com esta tentativa contada em todos).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub ip_attempts: u64,
    /// ms até a janela do IP fechar.
    pub ip_window_left_ms: u64,
    pub email_attempts: u64,
    pub acct_failures: u64,
    pub ip_failures: u64,
    /// ms de espera do IP em curso (0 = nenhuma).
    pub ip_lock_left_ms: u64,
}

/// Decisão antes de tocar na BD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// 429 com `Retry-After` (segundos, ≥ 1).
    TooMany { retry_after_s: u64 },
    /// Segue; `captcha` = captcha obrigatório.
    Proceed { captcha: bool },
}

/// `ms` arredondados para cima em segundos, no mínimo 1.
fn ceil_secs(ms: u64) -> u64 {
    ms.div_ceil(1000).max(1)
}

/// Decisão pura sobre os contadores (`None` = Redis indisponível → captcha obrigatório).
pub fn decide(snap: Option<Snapshot>, l: &Limits) -> Gate {
    let Some(s) = snap else {
        return Gate::Proceed { captcha: true };
    };
    if s.ip_attempts > l.ip_max {
        return Gate::TooMany {
            retry_after_s: ceil_secs(s.ip_window_left_ms),
        };
    }
    if s.ip_lock_left_ms > 0 {
        return Gate::TooMany {
            retry_after_s: ceil_secs(s.ip_lock_left_ms),
        };
    }
    // Os contadores de falhas já contam esta tentativa: as `captcha_after` primeiras passam.
    Gate::Proceed {
        captcha: s.acct_failures > l.captcha_after
            || s.ip_failures > l.captcha_after
            || s.email_attempts > l.email_max,
    }
}

/// Espera depois da falha n.º `n` do IP (0 = nenhuma): 2^(n - from) × unidade, com teto em
/// `backoff_cap` e no TTL dos contadores (nunca mais longa do que a memória da falha).
pub fn backoff(n: u64, l: &Limits) -> Duration {
    if n < l.backoff_from {
        return Duration::ZERO;
    }
    let exp = u32::try_from((n - l.backoff_from).min(30)).unwrap_or(30);
    let d = l.backoff_unit.saturating_mul(2u32.saturating_pow(exp));
    d.min(l.backoff_cap).min(l.fail_ttl)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// sha256 em hex minúsculo.
fn sha256_hex(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

/// `ACCOUNT_HASH_KEY` (`Config::account_hash_key`). `Debug` não mostra o valor.
#[derive(Clone)]
pub struct AccountKey(SecretString);

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKey([REDACTED])")
    }
}

impl AccountKey {
    pub fn new(key: SecretString) -> Self {
        Self(key)
    }
}

/// Identificador da conta: HMAC-SHA256(chave, email JÁ normalizado) em hex minúsculo. Usado no
/// `target_id` da caixa negra (login e registo repetido) e nas chaves Redis do login; nunca o email.
pub fn account_hash(key: &AccountKey, normalized_email: &str) -> String {
    match <Hmac<Sha256> as KeyInit>::new_from_slice(key.0.expose_secret().as_bytes()) {
        Ok(mut mac) => {
            mac.update(normalized_email.as_bytes());
            hex(&mac.finalize().into_bytes())
        }
        // O HMAC aceita chaves de qualquer tamanho: inalcançável. Nunca devolve o email.
        Err(_) => sha256_hex(&format!("hmac-indisponivel:{normalized_email}")),
    }
}

/// Chaves Redis de uma tentativa (conta = email normalizado; IP pelo /64 em IPv6).
#[derive(Debug, Clone)]
pub struct Keys {
    rate_ip: String,
    rate_acct: String,
    fail_acct: String,
    fail_ip: String,
    lock_ip: String,
}

impl Keys {
    /// `account` = `account_hash` do email normalizado.
    pub fn new(ns: &str, account: &str, ip: Option<IpAddr>) -> Self {
        let a = account;
        let i = sha256_hex(&ip_bucket(ip));
        Self {
            rate_ip: format!("{ns}login:rate:ip:{i}"),
            rate_acct: format!("{ns}login:rate:acct:{a}"),
            fail_acct: format!("{ns}login:fail:acct:{a}"),
            fail_ip: format!("{ns}login:fail:ip:{i}"),
            lock_ip: format!("{ns}login:lock:ip:{i}"),
        }
    }
}

/// Conta a tentativa em TODOS os contadores (volume e falhas, estes com TTL renovado) e devolve-os
/// com a espera do IP (atómico: pedidos em paralelo veem valores distintos).
const BEGIN_SCRIPT: &str = r#"
local r = redis.call('INCR', KEYS[1])
if redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local e = redis.call('INCR', KEYS[2])
if redis.call('PTTL', KEYS[2]) < 0 then redis.call('PEXPIRE', KEYS[2], ARGV[2]) end
local fa = redis.call('INCR', KEYS[3])
redis.call('PEXPIRE', KEYS[3], ARGV[3])
local fi = redis.call('INCR', KEYS[4])
redis.call('PEXPIRE', KEYS[4], ARGV[3])
return {r, redis.call('PTTL', KEYS[1]), e, fa, fi, redis.call('PTTL', KEYS[5])}
"#;

/// Falha de credenciais (já contada em `begin`): arma a espera do IP com o valor ATUAL do contador,
/// no mesmo script. d = min(2^(n - from) × unidade, teto) em ms; teto = min(900 s, TTL).
const FAIL_SCRIPT: &str = r#"
local n = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
local from = tonumber(ARGV[1])
if n < from then return 0 end
local e = n - from
if e > 40 then e = 40 end
local d = tonumber(ARGV[2]) * (2 ^ e)
local cap = tonumber(ARGV[3])
if d > cap then d = cap end
d = math.floor(d)
if d < 1 then d = 1 end
redis.call('SET', KEYS[2], '1', 'PX', d)
return d
"#;

/// Desfaz a contagem de falhas desta tentativa: `ARGV[1]` = '1' apaga a da conta (sucesso) ou
/// '0' só a decrementa (captcha recusado); a do IP é decrementada. Nunca abaixo de 0.
const UNDO_SCRIPT: &str = r#"
local function dec(k)
  local v = tonumber(redis.call('GET', k) or '0') or 0
  if v <= 1 then redis.call('DEL', k) else redis.call('DECR', k) end
end
if ARGV[1] == '1' then redis.call('DEL', KEYS[1]) else dec(KEYS[1]) end
dec(KEYS[2])
return 1
"#;

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX).max(1)
}

fn non_negative(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

async fn query<T: redis::FromRedisValue>(
    pool: &deadpool_redis::Pool,
    cmd: redis::Cmd,
) -> Result<T, AppError> {
    let fut = async {
        let mut conn = pool
            .get()
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("login: Redis indisponível: {e}")))?;
        cmd.query_async::<T>(&mut conn)
            .await
            .map_err(|e| AppError::Internal(anyhow::anyhow!("login: comando Redis falhou: {e}")))
    };
    tokio::time::timeout(REDIS_TIMEOUT, fut)
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("login: Redis sem resposta")))?
}

/// Início da tentativa: conta-a e devolve os contadores. `None` se o Redis falhar (o chamador
/// exige captcha).
pub async fn begin(pool: &deadpool_redis::Pool, k: &Keys, l: &Limits) -> Option<Snapshot> {
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(BEGIN_SCRIPT)
        .arg(5)
        .arg(&k.rate_ip)
        .arg(&k.rate_acct)
        .arg(&k.fail_acct)
        .arg(&k.fail_ip)
        .arg(&k.lock_ip)
        .arg(ms(l.ip_window))
        .arg(ms(l.email_window))
        .arg(ms(l.fail_ttl));
    match query::<Vec<i64>>(pool, cmd).await {
        Ok(v) if v.len() == 6 => Some(Snapshot {
            ip_attempts: non_negative(v[0]),
            ip_window_left_ms: non_negative(v[1]),
            email_attempts: non_negative(v[2]),
            acct_failures: non_negative(v[3]),
            ip_failures: non_negative(v[4]),
            ip_lock_left_ms: non_negative(v[5]),
        }),
        Ok(_) => {
            tracing::warn!("login: resposta inesperada do Redis; captcha obrigatório");
            None
        }
        Err(e) => {
            tracing::warn!(error = ?e, "login: travão sem Redis; captcha obrigatório");
            None
        }
    }
}

/// Falha de credenciais (já contada em `begin`): arma, no mesmo script, a espera do IP a partir da
/// 5.ª. Erros do Redis só ficam no log (a tentativa seguinte, sem Redis, exige captcha).
pub async fn failed(pool: &deadpool_redis::Pool, k: &Keys, l: &Limits) {
    let cap = l.backoff_cap.min(l.fail_ttl);
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(FAIL_SCRIPT)
        .arg(2)
        .arg(&k.fail_ip)
        .arg(&k.lock_ip)
        .arg(l.backoff_from)
        .arg(ms(l.backoff_unit))
        .arg(ms(cap));
    if let Err(e) = query::<i64>(pool, cmd).await {
        tracing::warn!(error = ?e, "login: espera do IP não armada (Redis)");
    }
}

async fn undo(pool: &deadpool_redis::Pool, k: &Keys, clear_account: bool) {
    let mut cmd = redis::cmd("EVAL");
    cmd.arg(UNDO_SCRIPT)
        .arg(2)
        .arg(&k.fail_acct)
        .arg(&k.fail_ip)
        .arg(if clear_account { "1" } else { "0" });
    if let Err(e) = query::<i64>(pool, cmd).await {
        tracing::warn!(error = ?e, "login: contadores de falhas não corrigidos (Redis)");
    }
}

/// Sucesso: apaga as falhas da conta e desconta esta tentativa no IP.
pub async fn succeeded(pool: &deadpool_redis::Pool, k: &Keys) {
    undo(pool, k, true).await;
}

/// Captcha em falta ou errado: não houve tentativa de credenciais; desconta-a nos dois.
pub async fn not_attempted(pool: &deadpool_redis::Pool, k: &Keys) {
    undo(pool, k, false).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        Snapshot {
            ip_attempts: 1,
            ip_window_left_ms: 60_000,
            email_attempts: 1,
            ..Snapshot::default()
        }
    }

    #[test]
    fn redis_down_requires_captcha_and_never_blocks() {
        assert_eq!(
            decide(None, &Limits::default()),
            Gate::Proceed { captcha: true }
        );
    }

    #[test]
    fn captcha_after_three_failures_or_eleven_attempts_per_email() {
        let l = Limits::default();
        assert_eq!(decide(Some(snap()), &l), Gate::Proceed { captcha: false });
        // 3 falhas anteriores + esta = 3 passam; a 4.ª (contador 4) pede captcha.
        let third = Snapshot {
            acct_failures: 3,
            ip_failures: 3,
            ..snap()
        };
        assert_eq!(decide(Some(third), &l), Gate::Proceed { captcha: false });
        for s in [
            Snapshot {
                acct_failures: 4,
                ..snap()
            },
            Snapshot {
                ip_failures: 4,
                ..snap()
            },
            Snapshot {
                email_attempts: 11,
                ..snap()
            },
        ] {
            assert_eq!(decide(Some(s), &l), Gate::Proceed { captcha: true });
        }
        // Muitas falhas da CONTA nunca dão 429 (sem DoS à conta alheia): só captcha.
        let s = Snapshot {
            acct_failures: 500,
            email_attempts: 500,
            ..snap()
        };
        assert_eq!(decide(Some(s), &l), Gate::Proceed { captcha: true });
    }

    #[test]
    fn ip_volume_and_ip_wait_are_429_with_retry_after() {
        let l = Limits::default();
        let s = Snapshot {
            ip_attempts: 21,
            ip_window_left_ms: 1_200,
            ..snap()
        };
        assert_eq!(decide(Some(s), &l), Gate::TooMany { retry_after_s: 2 });
        let s = Snapshot {
            ip_lock_left_ms: 1,
            ..snap()
        };
        assert_eq!(decide(Some(s), &l), Gate::TooMany { retry_after_s: 1 });
    }

    #[test]
    fn backoff_is_exponential_from_the_fifth_and_capped() {
        let l = Limits::default();
        assert_eq!(backoff(4, &l), Duration::ZERO);
        assert_eq!(backoff(5, &l), Duration::from_secs(1));
        assert_eq!(backoff(6, &l), Duration::from_secs(2));
        assert_eq!(backoff(10, &l), Duration::from_secs(32));
        assert_eq!(backoff(15, &l), Duration::from_secs(900));
        assert_eq!(backoff(u64::MAX, &l), Duration::from_secs(900));
    }

    #[test]
    fn keys_never_hold_the_email_or_ip_in_clear() {
        let ip: IpAddr = "2001:db8:1:2:3:4:5:6"
            .parse()
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let key = AccountKey::new(SecretString::from("k".repeat(32)));
        let k = Keys::new("", &account_hash(&key, "ana@x.pt"), Some(ip));
        let all = format!("{k:?}");
        assert!(!all.contains("ana") && !all.contains("2001"));
        // O mesmo /64 → as mesmas chaves de IP.
        let other: IpAddr = "2001:db8:1:2:ffff::1"
            .parse()
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        assert_eq!(Keys::new("", "b", Some(other)).fail_ip, k.fail_ip);
    }

    #[test]
    fn account_hash_is_keyed_hmac() {
        // RFC 4231, caso 2: HMAC-SHA256("Jefe", "what do ya want for nothing?").
        let jefe = AccountKey::new(SecretString::from("Jefe"));
        assert_eq!(
            account_hash(&jefe, "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let a = AccountKey::new(SecretString::from("a".repeat(32)));
        let b = AccountKey::new(SecretString::from("b".repeat(32)));
        assert_ne!(account_hash(&a, "ana@x.pt"), account_hash(&b, "ana@x.pt"));
        assert_ne!(account_hash(&a, "ana@x.pt"), sha256_hex("ana@x.pt"));
        assert!(!format!("{a:?}").contains("aaaa"));
    }
}
