//! Cifra de segredos em repouso (cartão 02/20; spec 12 §3): AES-256-GCM com a chave fora da BD.
//!
//! - Chave atual: `TOTP_ENC_KEY` (32 bytes em base64 padrão; ex.: `openssl rand -base64 32`). Chaves
//!   antigas opcionais (`TOTP_ENC_KEYS_OLD`, separadas por vírgula) servem SÓ para decifrar
//!   (rotação: cifra-se sempre com a atual).
//! - Formato gravado: `"v1:" + kid + ":" + base64(nonce de 12 bytes || ciphertext || tag de 16 bytes)`;
//!   `kid` = 8 hex do sha256 da chave (identifica a chave, não a revela). `kid` desconhecido → erro.
//!   Nonce aleatório (CSPRNG do SO) por valor.
//! - AAD = os 16 bytes do id do dono do valor: um valor copiado para outra linha não decifra.
//! - Subchaves (HKDF-SHA256 da chave atual, `info` por uso): ex.: `ptmarket/recovery-v1`.
//! - Os erros nunca levam o valor, a chave nem o texto em claro.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use rand::{TryRngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::AppError;

/// Bytes da chave (AES-256).
pub const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const VERSION: &str = "v1";

/// Chave de base64 inválida (sem o valor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("chave inválida: esperados 32 bytes em base64 padrão, sem espaços")]
pub struct InvalidKey;

/// Decodifica a chave (base64 padrão com padding) e exige exatamente 32 bytes.
pub fn decode_key(b64: &str) -> Result<Zeroizing<Vec<u8>>, InvalidKey> {
    if b64.trim() != b64 {
        return Err(InvalidKey);
    }
    let raw = Zeroizing::new(STANDARD.decode(b64).map_err(|_| InvalidKey)?);
    if raw.len() != KEY_BYTES {
        return Err(InvalidKey);
    }
    Ok(raw)
}

/// 8 hex do sha256 da chave.
fn kid_of(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Uma chave com o seu `kid`.
#[derive(Clone)]
struct Slot {
    kid: String,
    cipher: Aes256Gcm,
    /// Material da chave (só para derivar subchaves).
    ikm: Zeroizing<Vec<u8>>,
}

impl Slot {
    fn new(raw: &[u8]) -> Result<Self, InvalidKey> {
        Ok(Self {
            kid: kid_of(raw),
            cipher: Aes256Gcm::new_from_slice(raw).map_err(|_| InvalidKey)?,
            ikm: Zeroizing::new(raw.to_vec()),
        })
    }

    fn subkey(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
        let mut okm = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, &self.ikm)
            .expand(info, okm.as_mut())
            .map_err(|_| AppError::Internal(anyhow::anyhow!("HKDF falhou")))?;
        Ok(okm)
    }
}

/// Chaveiro AES-256-GCM: a atual (cifra e decifra) + antigas (só decifram). Apagado da memória ao
/// largar; `Debug` sem conteúdo.
#[derive(Clone)]
pub struct EncKey {
    current: Slot,
    old: Vec<Slot>,
}

impl std::fmt::Debug for EncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncKey([REDACTED])")
    }
}

impl EncKey {
    /// A partir de `TOTP_ENC_KEY` (base64 de 32 bytes).
    pub fn from_base64(key: &SecretString) -> Result<Self, InvalidKey> {
        let raw = decode_key(key.expose_secret())?;
        Ok(Self {
            current: Slot::new(&raw)?,
            old: Vec::new(),
        })
    }

    /// Junta chaves antigas (`TOTP_ENC_KEYS_OLD`), só para decifrar.
    pub fn with_old(mut self, old: &[SecretString]) -> Result<Self, InvalidKey> {
        for k in old {
            let raw = decode_key(k.expose_secret())?;
            self.old.push(Slot::new(&raw)?);
        }
        Ok(self)
    }

    /// `kid` da chave atual.
    pub fn kid(&self) -> &str {
        &self.current.kid
    }

    /// Subchave de 32 bytes da chave ATUAL (HKDF-SHA256, sem sal, com `info`).
    pub fn subkey(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
        self.current.subkey(info)
    }

    /// A mesma subchave para a atual e depois cada antiga (verificar valores feitos antes de uma
    /// rotação).
    pub fn subkeys(&self, info: &[u8]) -> Result<Vec<Zeroizing<[u8; 32]>>, AppError> {
        std::iter::once(&self.current)
            .chain(self.old.iter())
            .map(|s| s.subkey(info))
            .collect()
    }

    /// Cifra `plaintext` ligado a `aad` (o id do dono), sempre com a chave atual.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<String, AppError> {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("CSPRNG do SO indisponível")))?;
        let ct = self
            .current
            .cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AppError::Internal(anyhow::anyhow!("cifra AES-GCM falhou")))?;
        let mut out = Vec::with_capacity(NONCE_BYTES + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(format!(
            "{VERSION}:{}:{}",
            self.current.kid,
            STANDARD.encode(out)
        ))
    }

    /// Decifra um valor `v1:<kid>:…` com a chave desse `kid` (atual ou antiga) e o mesmo `aad`.
    /// Formato errado, `kid` desconhecido, outro `aad` ou valor adulterado → erro (sem pormenores).
    pub fn decrypt(&self, value: &str, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let fail = || AppError::Internal(anyhow::anyhow!("valor cifrado ilegível"));
        let mut parts = value.splitn(3, ':');
        let (Some(VERSION), Some(kid), Some(b64)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(fail());
        };
        let slot = std::iter::once(&self.current)
            .chain(self.old.iter())
            .find(|s| s.kid == kid)
            .ok_or_else(fail)?;
        let raw = STANDARD.decode(b64).map_err(|_| fail())?;
        if raw.len() < NONCE_BYTES + TAG_BYTES {
            return Err(fail());
        }
        let (nonce, ct) = raw.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| fail())?;
        slot.cipher
            .decrypt(&nonce.into(), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| fail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(byte: u8) -> SecretString {
        SecretString::from(STANDARD.encode([byte; KEY_BYTES]))
    }

    fn key(byte: u8) -> EncKey {
        match EncKey::from_base64(&b64(byte)) {
            Ok(k) => k,
            Err(e) => unreachable!("{e}"),
        }
    }

    #[test]
    fn roundtrip_binds_aad_key_and_nonce() -> Result<(), AppError> {
        let k = key(7);
        let a = k.encrypt(b"segredo", b"user-a")?;
        let b = k.encrypt(b"segredo", b"user-a")?;
        assert!(a.starts_with(&format!("v1:{}:", k.kid())) && a != b);
        assert_eq!(k.kid().len(), 8);
        assert!(!a.contains("segredo"));
        assert_eq!(k.decrypt(&a, b"user-a")?.as_slice(), b"segredo");
        assert!(k.decrypt(&a, b"user-b").is_err(), "AAD de outro utilizador");
        assert!(
            key(8).decrypt(&a, b"user-a").is_err(),
            "outra chave (kid desconhecido)"
        );
        let mut tampered = a.clone();
        tampered.pop();
        tampered.push(if a.ends_with('A') { 'B' } else { 'A' });
        assert!(k.decrypt(&tampered, b"user-a").is_err());
        // kid trocado pelo de outra chave: recusado mesmo com o resto intacto.
        let other_kid = a.replacen(k.kid(), key(8).kid(), 1);
        assert!(k.decrypt(&other_kid, b"user-a").is_err());
        assert!(k.decrypt("v2:00000000:AAAA", b"user-a").is_err());
        assert!(k.decrypt("v1:AAAA", b"user-a").is_err());
        Ok(())
    }

    #[test]
    fn rotation_old_keys_only_decrypt() -> Result<(), AppError> {
        let old = key(1);
        let v = old.encrypt(b"segredo", b"u")?;
        let new = match key(2).with_old(&[b64(1)]) {
            Ok(k) => k,
            Err(e) => unreachable!("{e}"),
        };
        assert_eq!(new.decrypt(&v, b"u")?.as_slice(), b"segredo");
        assert!(
            new.encrypt(b"x", b"u")?
                .starts_with(&format!("v1:{}:", key(2).kid()))
        );
        assert!(key(2).decrypt(&v, b"u").is_err());
        Ok(())
    }

    #[test]
    fn subkeys_depend_on_info_and_key() -> Result<(), AppError> {
        let a = key(1).subkey(b"ptmarket/recovery-v1")?;
        assert_eq!(*a, *key(1).subkey(b"ptmarket/recovery-v1")?);
        assert_ne!(*a, *key(1).subkey(b"outro")?);
        assert_ne!(*a, *key(2).subkey(b"ptmarket/recovery-v1")?);
        assert_ne!(&a[..], &[1u8; 32][..]);
        Ok(())
    }

    #[test]
    fn key_must_be_32_bytes_base64() {
        assert!(decode_key(&STANDARD.encode([1u8; 32])).is_ok());
        assert!(decode_key(&STANDARD.encode([1u8; 31])).is_err());
        assert!(decode_key(&STANDARD.encode([1u8; 33])).is_err());
        assert!(decode_key("não é base64").is_err());
        assert!(decode_key(&format!(" {}", STANDARD.encode([1u8; 32]))).is_err());
        assert_eq!(format!("{:?}", key(1)), "EncKey([REDACTED])");
    }
}
