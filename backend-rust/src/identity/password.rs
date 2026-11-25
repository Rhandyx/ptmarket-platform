//! Passwords: validação, hash Argon2id (parâmetros OWASP) e verificação.
//!
//! Spec 12 §3 · ASVS 5.0 nível 3. A password e o hash completo nunca vão para
//! logs, erros nem eventos de auditoria.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use argon2::password_hash::{self, PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::error::{AppError, FieldError};

// --- Parâmetros (único sítio) ------------------------------------------------

/// Memória em KiB (19 MiB).
pub const ARGON2_M_COST_KIB: u32 = 19_456;
/// Iterações.
pub const ARGON2_T_COST: u32 = 2;
/// Paralelismo.
pub const ARGON2_P_COST: u32 = 1;
/// Bytes de saída.
pub const ARGON2_OUTPUT_LEN: usize = 32;
/// Bytes de sal (aleatório, CSPRNG do sistema operativo).
pub const ARGON2_SALT_LEN: usize = 16;
/// Versão Argon2 (0x13 = 19).
const ARGON2_VERSION: Version = Version::V0x13;
/// Comprimento mínimo/máximo em code points Unicode.
pub const PASSWORD_MIN_CHARS: usize = 8;
pub const PASSWORD_MAX_CHARS: usize = 128;
/// Máximo de hashes/verificações em simultâneo (anti-DoS).
const MAX_CONCURRENT_HASHES: usize = 4;
/// Espera máxima por uma vaga; depois disso → `AppError::Busy` (503 + `Retry-After`).
/// Evita fila sem limite (latência e cópias da password em memória à espera).
const HASH_PERMIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Hash fictício fixo (parâmetros atuais) usado quando a conta não existe ou só tem passkey,
/// para que o tempo de resposta não revele se a conta existe.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3RhdGljLWR1bW15LXNhbHQ$QurpBYlpbNTB57KlyipnK0ptdHQCQyYjt+QpMAGliMI";

static HASH_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES)));

// --- Tipo --------------------------------------------------------------------

/// Password em claro, validada. Sem `Display`/`Serialize`; `Debug` não mostra o valor;
/// apagada da memória ao sair de âmbito (`SecretString` faz zeroize).
pub struct Password(SecretString);

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Password([REDACTED])")
    }
}

impl Password {
    /// 8 a 128 code points Unicode; sem regras de composição; não corta nem normaliza.
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        let n = raw.chars().count();
        if !(PASSWORD_MIN_CHARS..=PASSWORD_MAX_CHARS).contains(&n) {
            return Err(AppError::Validation(vec![FieldError {
                field: "password".into(),
                message: format!(
                    "A password deve ter entre {PASSWORD_MIN_CHARS} e {PASSWORD_MAX_CHARS} caracteres."
                ),
            }]));
        }
        Ok(Self(SecretString::from(raw)))
    }

    /// Bytes recebidos, sem transformação. Só dentro de `identity`.
    pub(in crate::identity) fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }

    /// Cópia dos bytes que se apaga da memória ao ser largada (para `spawn_blocking`).
    fn zeroizing_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.expose_bytes().to_vec())
    }
}

/// Resultado de `verify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub ok: bool,
    /// O PHC guardado usa parâmetros mais fracos que os atuais: recalcular após login.
    pub needs_rehash: bool,
}

// --- Hash / verificação ------------------------------------------------------

fn internal() -> AppError {
    AppError::Internal(anyhow::anyhow!("falha no hash de password"))
}

fn current_params() -> Result<Params, AppError> {
    Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(ARGON2_OUTPUT_LEN),
    )
    .map_err(|_| internal())
}

fn hasher() -> Result<Argon2<'static>, AppError> {
    Ok(Argon2::new(
        Algorithm::Argon2id,
        ARGON2_VERSION,
        current_params()?,
    ))
}

/// Corre `f` numa thread de bloqueio, no máximo `MAX_CONCURRENT_HASHES` em simultâneo;
/// sem vaga em `HASH_PERMIT_TIMEOUT` → `AppError::Busy`.
async fn run_limited<T, F>(f: F) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_limited_with(&HASH_PERMITS, HASH_PERMIT_TIMEOUT, f).await
}

/// `run_limited` com semáforo e espera injetáveis (testes).
async fn run_limited_with<T, F>(
    permits: &Arc<Semaphore>,
    wait: Duration,
    f: F,
) -> Result<T, AppError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let permit = tokio::time::timeout(wait, Arc::clone(permits).acquire_owned())
        .await
        .map_err(|_| {
            tracing::warn!("fila de hashes de password cheia; pedido recusado (503)");
            AppError::Busy
        })?
        .map_err(|_| internal())?;
    tokio::task::spawn_blocking(move || {
        let out = f();
        drop(permit);
        out
    })
    .await
    .map_err(|_| internal())
}

/// Hash Argon2id em formato PHC (`$argon2id$v=19$m=19456,t=2,p=1$…`).
pub async fn hash(password: &Password) -> Result<String, AppError> {
    let bytes = password.zeroizing_bytes();
    run_limited(move || hash_blocking(&bytes)).await?
}

fn hash_blocking(bytes: &[u8]) -> Result<String, AppError> {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    getrandom_salt(&mut salt)?;
    let phc = hasher()?
        .hash_password_with_salt(bytes, &salt)
        .map_err(|_| internal())?;
    Ok(phc.to_string())
}

fn getrandom_salt(salt: &mut [u8; ARGON2_SALT_LEN]) -> Result<(), AppError> {
    // `try_generate_salt` usa `getrandom` (CSPRNG do SO, o mesmo que `OsRng`).
    let s = password_hash::try_generate_salt().map_err(|_| internal())?;
    if s.len() != ARGON2_SALT_LEN {
        return Err(internal());
    }
    salt.copy_from_slice(&s);
    Ok(())
}

/// Verifica a password contra o PHC guardado.
///
/// `phc = None` (conta inexistente ou só passkey) → verifica contra `DUMMY_PHC` e devolve
/// `ok=false`, com o mesmo custo de uma verificação real. PHC corrompido → `ok=false`.
pub async fn verify(password: &Password, phc: Option<&str>) -> Result<Verified, AppError> {
    let bytes = password.zeroizing_bytes();
    let phc = phc.map(str::to_owned);
    run_limited(move || verify_blocking(&bytes, phc.as_deref())).await?
}

fn verify_blocking(bytes: &[u8], phc: Option<&str>) -> Result<Verified, AppError> {
    let parsed = phc.and_then(|s| PasswordHash::new(s).ok());
    let Some(parsed) = parsed else {
        if phc.is_some() {
            tracing::warn!("hash de password guardado ilegível; verificação recusada");
        }
        burn_dummy(bytes)?;
        return Ok(Verified {
            ok: false,
            needs_rehash: false,
        });
    };
    let ok = hasher()?.verify_password(bytes, &parsed).is_ok();
    let weaker = is_weaker_than_current(&parsed);
    if weaker {
        // Hash antigo verifica mais depressa: completa o custo para o tempo não o revelar.
        burn_dummy(bytes)?;
    }
    Ok(Verified {
        ok,
        needs_rehash: ok && weaker,
    })
}

/// Gasta o mesmo tempo que uma verificação real; o resultado é ignorado.
fn burn_dummy(bytes: &[u8]) -> Result<(), AppError> {
    let dummy = PasswordHash::new(DUMMY_PHC).map_err(|_| internal())?;
    let _ = hasher()?.verify_password(bytes, &dummy);
    Ok(())
}

fn is_weaker_than_current(phc: &PasswordHash) -> bool {
    if phc.algorithm != argon2::ARGON2ID_IDENT || phc.version != Some(ARGON2_VERSION.into()) {
        return true;
    }
    let Ok(p) = Params::try_from(phc) else {
        return true;
    };
    let salt_len = phc.salt.as_ref().map_or(0, |s| s.len());
    let out_len = phc.hash.as_ref().map_or(0, |h| h.len());
    p.m_cost() < ARGON2_M_COST_KIB
        || p.t_cost() < ARGON2_T_COST
        || p.p_cost() < ARGON2_P_COST
        || salt_len < ARGON2_SALT_LEN
        || out_len < ARGON2_OUTPUT_LEN
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use argon2::CustomizedPasswordHasher;
    use std::time::{Duration, Instant};

    fn pw(s: &str) -> Password {
        Password::parse(s).unwrap()
    }

    const GOOD: &str = "correct horse battery";

    #[tokio::test]
    async fn hash_has_exact_phc_params() {
        let phc = hash(&pw(GOOD)).await.unwrap();
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{phc}");
        let parsed = PasswordHash::new(&phc).unwrap();
        assert_eq!(parsed.salt.unwrap().len(), ARGON2_SALT_LEN);
        assert_eq!(parsed.hash.unwrap().len(), ARGON2_OUTPUT_LEN);
        assert!(!phc.contains(GOOD));
    }

    #[tokio::test]
    async fn same_password_hashes_differ() {
        let p = pw(GOOD);
        let (a, b) = tokio::join!(hash(&p), hash(&p));
        assert_ne!(a.unwrap(), b.unwrap());
    }

    #[tokio::test]
    async fn verify_accepts_right_and_rejects_wrong() {
        let phc = hash(&pw(GOOD)).await.unwrap();
        let right = verify(&pw(GOOD), Some(&phc)).await.unwrap();
        assert_eq!(
            right,
            Verified {
                ok: true,
                needs_rehash: false
            }
        );
        let wrong = verify(&pw("correct horse battery!"), Some(&phc))
            .await
            .unwrap();
        assert!(!wrong.ok);
    }

    #[tokio::test]
    async fn corrupted_phc_is_rejected_without_panic() {
        for bad in [
            "",
            "garbage",
            "$argon2id$v=19$m=19456,t=2,p=1$",
            "$argon2id$v=19$m=abc,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaA",
            "$unknown$v=1$x$y",
        ] {
            let v = verify(&pw(GOOD), Some(bad)).await.unwrap();
            assert!(!v.ok, "{bad}");
        }
    }

    #[test]
    fn debug_does_not_leak_value() {
        let p = pw("s3cr3t-valor-unico");
        let d = format!("{p:?}");
        assert!(!d.contains("s3cr3t"), "{d}");
    }

    #[test]
    fn dummy_phc_uses_current_params() {
        let parsed = PasswordHash::new(DUMMY_PHC).unwrap();
        assert!(!is_weaker_than_current(&parsed));
    }

    #[tokio::test]
    async fn verify_none_is_false_and_takes_as_long_as_real() {
        let phc = hash(&pw(GOOD)).await.unwrap();
        // Aquecimento (primeira execução aloca memória/threads).
        let _ = verify(&pw(GOOD), Some(&phc)).await.unwrap();

        // Mínimo de 3 medições de cada lado: reduz ruído de testes em paralelo.
        let (mut real_dt, mut none_dt) = (Duration::MAX, Duration::MAX);
        let (mut real, mut none) = (None, None);
        for _ in 0..3 {
            let t = Instant::now();
            real = Some(verify(&pw("wrong password"), Some(&phc)).await.unwrap());
            real_dt = real_dt.min(t.elapsed());

            let t = Instant::now();
            none = Some(verify(&pw("wrong password"), None).await.unwrap());
            none_dt = none_dt.min(t.elapsed());
        }
        let (real, none) = (real.unwrap(), none.unwrap());

        assert!(!real.ok);
        assert_eq!(
            none,
            Verified {
                ok: false,
                needs_rehash: false
            }
        );
        // Tolerância larga: o fictício custa pelo menos ~1/4 e no máximo ~4x de uma real.
        assert!(
            none_dt * 4 >= real_dt && none_dt <= real_dt * 4,
            "real={real_dt:?} none={none_dt:?}"
        );
    }

    #[tokio::test]
    async fn weaker_phc_verifies_and_needs_rehash() {
        let weak =
            Params::new(4096, ARGON2_T_COST, ARGON2_P_COST, Some(ARGON2_OUTPUT_LEN)).unwrap();
        let phc = Argon2::default()
            .hash_password_customized(GOOD.as_bytes(), b"0123456789abcdef", None, None, weak)
            .unwrap()
            .to_string();
        assert!(phc.contains("m=4096"));
        let v = verify(&pw(GOOD), Some(&phc)).await.unwrap();
        assert_eq!(
            v,
            Verified {
                ok: true,
                needs_rehash: true
            }
        );
        // Password errada contra hash fraco: recusa e não pede rehash.
        let wrong = verify(&pw("wrong password"), Some(&phc)).await.unwrap();
        assert_eq!(
            wrong,
            Verified {
                ok: false,
                needs_rehash: false
            }
        );
    }

    #[tokio::test]
    async fn full_queue_returns_busy_after_timeout() {
        // Semáforo próprio: não interfere com os outros testes em paralelo.
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_HASHES));
        let held: Vec<_> = (0..MAX_CONCURRENT_HASHES)
            .map(|_| Arc::clone(&sem).try_acquire_owned().unwrap())
            .collect();
        let r = run_limited_with(&sem, Duration::from_millis(20), || 1u8).await;
        assert!(matches!(r, Err(AppError::Busy)), "{r:?}");

        drop(held);
        let r = run_limited_with(&sem, Duration::from_millis(20), || 1u8).await;
        assert_eq!(r.unwrap(), 1);
    }

    #[test]
    fn length_limits_in_code_points() {
        assert!(matches!(
            Password::parse("1234567"),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            Password::parse(&"a".repeat(129)),
            Err(AppError::Validation(_))
        ));
        assert!(Password::parse("12345678").is_ok());
        assert!(Password::parse(&"a".repeat(128)).is_ok());
        // 8 emojis = 8 code points (32 bytes); 128 emojis aceites.
        assert!(Password::parse(&"🔐".repeat(8)).is_ok());
        assert!(Password::parse(&"🔐".repeat(128)).is_ok());
        assert!(Password::parse(&"🔐".repeat(7)).is_err());
        // Espaços aceites e não cortados.
        let p = Password::parse("  com espaços  ").unwrap();
        assert_eq!(p.expose_bytes(), "  com espaços  ".as_bytes());
    }

    #[test]
    fn validation_error_does_not_echo_password() {
        let Err(AppError::Validation(f)) = Password::parse("short") else {
            panic!("esperado Validation");
        };
        assert!(f.iter().all(|e| !e.message.contains("short")));
    }
}
