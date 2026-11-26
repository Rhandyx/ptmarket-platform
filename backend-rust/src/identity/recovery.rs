//! Códigos de recuperação do 2FA (cartão 02/20; BD 0019 + 0021).
//!
//! - 10 códigos de 10 caracteres de um alfabeto sem ambíguos (sem 0/O, 1/I/L): CSPRNG do SO com
//!   rejeição (distribuição uniforme), ≈ 49 bits cada.
//! - Na BD só `HMAC-SHA256(k_rec, user_id (16 bytes) || código normalizado)` (32 bytes); `k_rec` =
//!   subchave HKDF-SHA256 da `TOTP_ENC_KEY` com info `ptmarket/recovery-v1` (uma fuga da BD não
//!   permite testar códigos sem a chave; o mesmo código noutra conta dá outro hash). A verificação
//!   aceita também os hashes feitos com as chaves antigas (`TOTP_ENC_KEYS_OLD`): rodar a chave não
//!   invalida os códigos. Em claro só na resposta do `confirm`, uma vez.
//! - Cada `replace` apaga os anteriores do utilizador e grava 10 novos (nunca reutiliza hashes).
//! - Consumo atómico: `UPDATE … SET used_at = now() WHERE id = $1 AND used_at IS NULL` só vale se
//!   afetar 1 linha; 0 linhas ou 23514 (trigger `user_recovery_codes_use_once`, 0021) = recusado.

use hmac::{Hmac, KeyInit, Mac};
use rand::{TryRngCore, rngs::OsRng};
use sha2::Sha256;
use sqlx::PgConnection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{error::AppError, identity::crypto::EncKey, tenancy::db::db_error};

/// `info` HKDF da subchave dos códigos de recuperação.
pub const RECOVERY_KEY_INFO: &[u8] = b"ptmarket/recovery-v1";

/// Subchaves `k_rec` (a da chave atual primeiro, depois as das antigas). `Debug` sem conteúdo.
#[derive(Clone)]
pub struct RecoveryKey(Vec<Zeroizing<[u8; 32]>>);

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}

impl RecoveryKey {
    /// Deriva `k_rec` de cada chave do chaveiro da `TOTP_ENC_KEY`.
    pub fn from_enc_key(key: &EncKey) -> Result<Self, AppError> {
        Ok(Self(key.subkeys(RECOVERY_KEY_INFO)?))
    }

    fn current(&self) -> Result<&[u8; 32], AppError> {
        self.0
            .first()
            .map(|k| &**k)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("RecoveryKey vazia")))
    }
}

/// Códigos gerados de cada vez.
pub const CODES: usize = 10;
/// Caracteres por código.
pub const CODE_CHARS: usize = 10;
/// Alfabeto sem caracteres ambíguos (31 símbolos).
pub const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
/// Maior múltiplo de 31 que cabe num byte: bytes ≥ isto são rejeitados (sem enviesamento).
const REJECT_FROM: u8 = 248;

/// Um código novo (CSPRNG do SO).
fn new_code() -> Result<String, AppError> {
    let mut out = String::with_capacity(CODE_CHARS);
    let mut buf = Zeroizing::new([0u8; 32]);
    while out.len() < CODE_CHARS {
        OsRng
            .try_fill_bytes(buf.as_mut())
            .map_err(|_| AppError::Internal(anyhow::anyhow!("CSPRNG do SO indisponível")))?;
        for &b in buf.iter().filter(|&&b| b < REJECT_FROM) {
            if out.len() == CODE_CHARS {
                break;
            }
            let i = usize::from(b) % ALPHABET.len();
            out.push(char::from(ALPHABET[i]));
        }
    }
    Ok(out)
}

/// Normaliza o que o utilizador escreveu (sem espaços/hífenes, maiúsculas). `None` se não tiver a
/// forma de um código de recuperação.
pub fn normalize(raw: &str) -> Option<String> {
    let s: String = raw
        .chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (s.len() == CODE_CHARS && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

fn hmac(k: &[u8; 32], user: Uuid, normalized: &str) -> [u8; 32] {
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(k) else {
        return [0u8; 32]; // HMAC aceita chaves de qualquer tamanho: inalcançável.
    };
    mac.update(user.as_bytes());
    mac.update(normalized.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

/// Hash guardado de um código: `HMAC-SHA256(k_rec, user_id || código normalizado)` com a chave
/// ATUAL. O código é normalizado aqui (espaços/hífenes/minúsculas); sem forma de código, entra tal e
/// qual (nunca confere com um gerado).
pub fn hash_code(key: &RecoveryKey, user: Uuid, code: &str) -> Result<[u8; 32], AppError> {
    let n = normalize(code).unwrap_or_else(|| code.to_owned());
    Ok(hmac(key.current()?, user, &n))
}

/// Hashes possíveis do código (chave atual e antigas), para a verificação.
fn candidate_hashes(key: &RecoveryKey, user: Uuid, normalized: &str) -> Vec<Vec<u8>> {
    key.0
        .iter()
        .map(|k| hmac(k, user, normalized).to_vec())
        .collect()
}

/// `n` códigos novos, distintos entre si (CSPRNG do SO). O mesmo gerador na API e no CLI.
pub fn new_codes(n: usize) -> Result<Vec<String>, AppError> {
    let mut codes = Vec::with_capacity(n);
    while codes.len() < n {
        let c = new_code()?;
        // Repetido no mesmo lote (probabilidade desprezável): gera outro.
        if !codes.contains(&c) {
            codes.push(c);
        }
    }
    Ok(codes)
}

/// Apaga os códigos anteriores de `user` e grava 10 novos (na transação do chamador, com o próprio
/// como ator: RLS `own_*`). Devolve-os em claro (só para a resposta).
pub(crate) async fn replace(
    conn: &mut PgConnection,
    key: &RecoveryKey,
    user: Uuid,
) -> Result<Vec<String>, AppError> {
    sqlx::query!("DELETE FROM user_recovery_codes WHERE user_id = $1", user)
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;
    let codes = new_codes(CODES)?;
    for c in &codes {
        sqlx::query!(
            "INSERT INTO user_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)",
            Uuid::now_v7(),
            user,
            &hash_code(key, user, c)?[..]
        )
        .execute(&mut *conn)
        .await
        .map_err(db_error)?;
    }
    Ok(codes)
}

/// Consome o código `normalized` de `user`. `Ok(false)` = não existe, já usado, ou perdeu a corrida
/// (0 linhas ou 23514): a transação deve ser desfeita.
pub(crate) async fn consume(
    conn: &mut PgConnection,
    key: &RecoveryKey,
    user: Uuid,
    normalized: &str,
) -> Result<bool, AppError> {
    let id = sqlx::query_scalar!(
        "SELECT id FROM user_recovery_codes
         WHERE user_id = $1 AND code_hash = ANY($2) AND used_at IS NULL
         LIMIT 1",
        user,
        &candidate_hashes(key, user, normalized)[..]
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;
    let Some(id) = id else {
        return Ok(false);
    };
    let r = sqlx::query!(
        "UPDATE user_recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL",
        id
    )
    .execute(&mut *conn)
    .await;
    match r {
        Ok(r) => Ok(r.rows_affected() == 1),
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23514") => Ok(false),
        Err(e) => Err(db_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unambiguous_and_normalized() -> Result<(), AppError> {
        for _ in 0..200 {
            let c = new_code()?;
            assert_eq!(c.len(), CODE_CHARS);
            assert!(!c.contains(['0', 'O', '1', 'I', 'L']), "{c}");
            assert_eq!(normalize(&c).as_deref(), Some(c.as_str()));
            let spaced = format!("{}-{} ", &c[..5], c[5..].to_ascii_lowercase());
            assert_eq!(normalize(&spaced).as_deref(), Some(c.as_str()));
        }
        assert_eq!(ALPHABET.len(), 31);
        assert_eq!(usize::from(REJECT_FROM), 31 * 8);
        assert!(normalize("123456").is_none());
        assert!(normalize("ABCDEFGHJO").is_none(), "O fora do alfabeto");
        Ok(())
    }

    #[test]
    fn hash_is_keyed_and_bound_to_user() -> Result<(), AppError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use secrecy::SecretString;
        let enc = |b: u8| EncKey::from_base64(&SecretString::from(STANDARD.encode([b; 32])));
        let (Ok(k1), Ok(k2)) = (enc(1), enc(2)) else {
            unreachable!("chaves de teste");
        };
        let r1 = RecoveryKey::from_enc_key(&k1)?;
        let r2 = RecoveryKey::from_enc_key(&k2)?;
        let (u, v) = (Uuid::now_v7(), Uuid::now_v7());
        let h = hash_code(&r1, u, "ABCDE-fghjk")?;
        assert_eq!(h, hash_code(&r1, u, "ABCDEFGHJK")?, "normalizado");
        assert_ne!(h, hash_code(&r1, v, "ABCDEFGHJK")?, "outro utilizador");
        assert_ne!(h, hash_code(&r2, u, "ABCDEFGHJK")?, "outra chave");
        assert_ne!(h, hash_code(&r1, u, "ABCDEFGHJM")?);
        let sha: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"ABCDEFGHJK").into();
        assert_ne!(h, sha, "nunca o sha256 simples");
        // Depois de rodar a chave, o hash antigo continua candidato.
        let rotated = match k2.with_old(&[SecretString::from(STANDARD.encode([1u8; 32]))]) {
            Ok(k) => RecoveryKey::from_enc_key(&k)?,
            Err(e) => unreachable!("{e}"),
        };
        assert!(candidate_hashes(&rotated, u, "ABCDEFGHJK").contains(&h.to_vec()));
        assert_eq!(
            hash_code(&rotated, u, "ABCDEFGHJK")?,
            hash_code(&r2, u, "ABCDEFGHJK")?
        );
        Ok(())
    }
}
