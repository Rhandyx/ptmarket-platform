//! Configuração a partir do ambiente. Segredos em `SecretString`; nunca impressos.

use std::net::SocketAddr;

use ipnet::IpNet;
use secrecy::{ExposeSecret, SecretString};

use crate::tenancy::host::normalize_host;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
/// Prefixo mínimo aceite em `TRUSTED_PROXY_CIDRS`.
const MIN_PROXY_PREFIX_V4: u8 = 8;
const MIN_PROXY_PREFIX_V6: u8 = 16;
/// Tamanho mínimo de `INTERNAL_PROXY_TOKEN`.
pub const MIN_INTERNAL_TOKEN_BYTES: usize = 32;
/// Tamanho mínimo de `CSRF_KEY`.
pub const MIN_CSRF_KEY_BYTES: usize = crate::identity::csrf::MIN_KEY_BYTES;

/// Erro de configuração legível; nunca contém valores de segredos.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("variável de ambiente em falta: {0}")]
    Missing(&'static str),
    #[error("variável de ambiente inválida: {0} ({1})")]
    Invalid(&'static str, &'static str),
}

#[derive(Debug)]
pub struct Config {
    pub database_primary_url: SecretString,
    pub database_replica_url: SecretString,
    pub redis_url: SecretString,
    pub bind_addr: SocketAddr,
    /// `TRUSTED_PROXY_CIDRS` (separadas por vírgula): só destes peers se aceita `CF-Connecting-IP`.
    /// Ausente ou vazia = nunca confiar. Prefixos IPv4 < /8 e IPv6 < /16 são recusados (seria
    /// confiar em boa parte da Internet).
    pub trusted_proxy_cidrs: Vec<IpNet>,
    /// `PLATFORM_ADMIN_HOST` (ex.: `admin.ptmarket.pt`), já normalizado: o host das rotas de
    /// plataforma (sem tenant). Ausente = nenhum host é de plataforma.
    pub platform_admin_host: Option<String>,
    /// `INTERNAL_PROXY_TOKEN` (≥ 32 bytes): só com ele o SSR do Next pode mandar
    /// `X-Forwarded-Host`. Ausente = `X-Forwarded-Host` sempre ignorado.
    pub internal_proxy_token: Option<SecretString>,
    /// `CSRF_KEY` (≥ 32 bytes; ex.: `openssl rand -hex 32`): chave HMAC dos tokens CSRF das
    /// sessões. Igual em todas as instâncias; mudá-la invalida os tokens em uso. Validada se
    /// presente; obrigatória para servir sessões (`Config::require_csrf_key`).
    pub csrf_key: Option<SecretString>,
}

fn platform_host(raw: Option<String>) -> Result<Option<String>, ConfigError> {
    const KEY: &str = "PLATFORM_ADMIN_HOST";
    match raw.filter(|v| !v.trim().is_empty()) {
        None => Ok(None),
        Some(v) => normalize_host(v.trim())
            .map(Some)
            .ok_or(ConfigError::Invalid(
                KEY,
                "esperado nome de domínio, ex.: admin.ptmarket.pt",
            )),
    }
}

fn internal_token(raw: Option<String>) -> Result<Option<SecretString>, ConfigError> {
    const KEY: &str = "INTERNAL_PROXY_TOKEN";
    let Some(v) = raw.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let token = SecretString::from(v);
    let t = token.expose_secret();
    if t.len() < MIN_INTERNAL_TOKEN_BYTES || t.trim() != t {
        return Err(ConfigError::Invalid(
            KEY,
            "mínimo 32 bytes, sem espaços nas pontas",
        ));
    }
    if axum::http::HeaderValue::from_str(t).is_err() {
        return Err(ConfigError::Invalid(KEY, "só caracteres visíveis"));
    }
    Ok(Some(token))
}

const CSRF_KEY: &str = "CSRF_KEY";

fn csrf_key(raw: Option<String>) -> Result<Option<SecretString>, ConfigError> {
    let Some(v) = raw.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let key = SecretString::from(v);
    let k = key.expose_secret();
    if k.len() < MIN_CSRF_KEY_BYTES || k.trim() != k {
        return Err(ConfigError::Invalid(
            CSRF_KEY,
            "mínimo 32 bytes, sem espaços nas pontas",
        ));
    }
    Ok(Some(key))
}

fn trusted_proxies(raw: Option<String>) -> Result<Vec<IpNet>, ConfigError> {
    const KEY: &str = "TRUSTED_PROXY_CIDRS";
    let raw = raw.unwrap_or_default();
    let mut nets = Vec::new();
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let net: IpNet = item
            .parse()
            .map_err(|_| ConfigError::Invalid(KEY, "esperado CIDR, ex.: 173.245.48.0/20"))?;
        let min = match net {
            IpNet::V4(_) => MIN_PROXY_PREFIX_V4,
            IpNet::V6(_) => MIN_PROXY_PREFIX_V6,
        };
        if net.prefix_len() < min {
            return Err(ConfigError::Invalid(
                KEY,
                "rede demasiado larga: o prefixo mínimo é /8 em IPv4 e /16 em IPv6",
            ));
        }
        nets.push(net.trunc());
    }
    Ok(nets)
}

fn secret(
    get: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    schemes: &[&str],
) -> Result<SecretString, ConfigError> {
    let v = get(key)
        .filter(|v| !v.trim().is_empty())
        .ok_or(ConfigError::Missing(key))?;
    if !schemes.iter().any(|s| v.starts_with(s)) {
        return Err(ConfigError::Invalid(key, "esquema de URL não suportado"));
    }
    Ok(SecretString::from(v))
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// `CSRF_KEY` para servir sessões (`http::router_with_sessions`); ausente → erro de arranque.
    pub fn require_csrf_key(&self) -> Result<SecretString, ConfigError> {
        self.csrf_key.clone().ok_or(ConfigError::Missing(CSRF_KEY))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let pg = ["postgres://", "postgresql://"];
        let bind = get("BIND_ADDR")
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BIND.to_owned());
        Ok(Self {
            database_primary_url: secret(&get, "DATABASE_PRIMARY_URL", &pg)?,
            database_replica_url: secret(&get, "DATABASE_REPLICA_URL", &pg)?,
            redis_url: secret(&get, "REDIS_URL", &["redis://", "rediss://"])?,
            bind_addr: bind
                .parse()
                .map_err(|_| ConfigError::Invalid("BIND_ADDR", "esperado endereço:porta"))?,
            trusted_proxy_cidrs: trusted_proxies(get("TRUSTED_PROXY_CIDRS"))?,
            platform_admin_host: platform_host(get("PLATFORM_ADMIN_HOST"))?,
            internal_proxy_token: internal_token(get("INTERNAL_PROXY_TOKEN"))?,
            csrf_key: csrf_key(get("CSRF_KEY"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }

    const OK: [(&str, &str); 4] = [
        ("DATABASE_PRIMARY_URL", "postgres://u:segredo1@h/db"),
        ("DATABASE_REPLICA_URL", "postgres://u:segredo1@h/db"),
        ("REDIS_URL", "redis://h:6379"),
        ("CSRF_KEY", "chave-csrf-segredo-com-32-bytes-ok"),
    ];

    #[test]
    fn valid_with_default_bind() {
        let c = Config::from_lookup(env(&OK));
        assert!(c.is_ok());
        if let Ok(c) = c {
            assert_eq!(c.bind_addr.to_string(), DEFAULT_BIND);
            assert_eq!(c.redis_url.expose_secret(), "redis://h:6379");
        }
    }

    #[test]
    fn missing_is_readable_error() {
        let e = Config::from_lookup(env(&[])).err().map(|e| e.to_string());
        assert_eq!(
            e.as_deref(),
            Some("variável de ambiente em falta: DATABASE_PRIMARY_URL")
        );
    }

    #[test]
    fn invalid_scheme_and_bind_do_not_leak_secret() {
        let mut v = OK.to_vec();
        v[0] = ("DATABASE_PRIMARY_URL", "mysql://u:segredo1@h/db");
        let e = Config::from_lookup(env(&v)).err().map(|e| e.to_string());
        assert!(e.as_deref().is_some_and(|s| !s.contains("segredo1")));

        let mut v = OK.to_vec();
        v.push(("BIND_ADDR", "nope"));
        assert!(Config::from_lookup(env(&v)).is_err());
    }

    #[test]
    fn trusted_proxy_cidrs_optional_and_validated() {
        let c = Config::from_lookup(env(&OK));
        assert!(c.is_ok_and(|c| c.trusted_proxy_cidrs.is_empty()));

        let mut v = OK.to_vec();
        v.push(("TRUSTED_PROXY_CIDRS", " 173.245.48.0/20, 2400:cb00::/32 ,"));
        let c = Config::from_lookup(env(&v));
        assert!(c.is_ok_and(|c| c.trusted_proxy_cidrs.len() == 2));

        for bad in [
            "nope",
            "10.0.0.1",
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0/1",
            "10.0.0.0/7",
            "2400::/15",
            "10.0.0.0/8, 0.0.0.0/1",
        ] {
            let mut v = OK.to_vec();
            v.push(("TRUSTED_PROXY_CIDRS", bad));
            assert!(Config::from_lookup(env(&v)).is_err(), "{bad}");
        }
        let mut v = OK.to_vec();
        v.push(("TRUSTED_PROXY_CIDRS", "0.0.0.0/1"));
        let e = Config::from_lookup(env(&v)).err().map(|e| e.to_string());
        assert_eq!(
            e.as_deref(),
            Some(
                "variável de ambiente inválida: TRUSTED_PROXY_CIDRS (rede demasiado larga: o \
                 prefixo mínimo é /8 em IPv4 e /16 em IPv6)"
            )
        );
        for edge in ["10.0.0.0/8", "2400::/16"] {
            let mut v = OK.to_vec();
            v.push(("TRUSTED_PROXY_CIDRS", edge));
            assert!(Config::from_lookup(env(&v)).is_ok(), "{edge}");
        }
    }

    #[test]
    fn debug_hides_secrets() {
        let token = "segredo-interno-".repeat(3);
        let mut v = OK.to_vec();
        v.push(("INTERNAL_PROXY_TOKEN", token.as_str()));
        let c = Config::from_lookup(env(&v));
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("segredo1") && !dbg.contains("segredo-interno"));
        assert!(!dbg.contains("chave-csrf"));
    }

    #[test]
    fn csrf_key_required_and_min_32_bytes() {
        let v: Vec<_> = OK
            .iter()
            .copied()
            .filter(|(k, _)| *k != "CSRF_KEY")
            .collect();
        let c = Config::from_lookup(env(&v));
        assert!(c.as_ref().is_ok_and(|c| c.csrf_key.is_none()));
        let e = c
            .ok()
            .and_then(|c| c.require_csrf_key().err())
            .map(|e| e.to_string());
        assert_eq!(
            e.as_deref(),
            Some("variável de ambiente em falta: CSRF_KEY")
        );
        let full = Config::from_lookup(env(&OK));
        assert!(full.is_ok_and(|c| c.require_csrf_key().is_ok()));
        let short = "c".repeat(31);
        let ok = "c".repeat(32);
        let spaced = format!("{} ", "c".repeat(40));
        for (val, good) in [(&short, false), (&ok, true), (&spaced, false)] {
            let mut v = v.clone();
            v.push(("CSRF_KEY", val.as_str()));
            let c = Config::from_lookup(env(&v));
            assert_eq!(c.is_ok(), good, "{}", val.len());
            if let Err(e) = c {
                assert!(!e.to_string().contains("cccc"));
            }
        }
    }

    #[test]
    fn platform_host_optional_and_normalized() {
        assert!(Config::from_lookup(env(&OK)).is_ok_and(|c| c.platform_admin_host.is_none()));
        let mut v = OK.to_vec();
        v.push(("PLATFORM_ADMIN_HOST", "Admin.PTMarket.pt."));
        let c = Config::from_lookup(env(&v));
        assert!(c.is_ok_and(|c| c.platform_admin_host.as_deref() == Some("admin.ptmarket.pt")));
        for bad in [
            "127.0.0.1",
            "admin ptmarket.pt",
            "https://admin.ptmarket.pt",
        ] {
            let mut v = OK.to_vec();
            v.push(("PLATFORM_ADMIN_HOST", bad));
            assert!(Config::from_lookup(env(&v)).is_err(), "{bad}");
        }
    }

    #[test]
    fn internal_token_optional_and_min_32_bytes() {
        assert!(Config::from_lookup(env(&OK)).is_ok_and(|c| c.internal_proxy_token.is_none()));
        let short = "a".repeat(31);
        let ok = "a".repeat(32);
        let spaced = format!(" {}", "a".repeat(40));
        let ctrl = format!("{}\n", "a".repeat(40));
        for (val, good) in [
            (&short, false),
            (&ok, true),
            (&spaced, false),
            (&ctrl, false),
        ] {
            let mut v = OK.to_vec();
            v.push(("INTERNAL_PROXY_TOKEN", val.as_str()));
            let c = Config::from_lookup(env(&v));
            assert_eq!(c.is_ok(), good, "{}", val.len());
            if let Err(e) = c {
                assert!(!e.to_string().contains("aaaa"));
            }
        }
    }
}
