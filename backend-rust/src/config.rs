//! Configuração a partir do ambiente. Segredos em `SecretString`; nunca impressos.

use std::net::SocketAddr;

use ipnet::IpNet;
use secrecy::SecretString;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
/// Prefixo mínimo aceite em `TRUSTED_PROXY_CIDRS`.
const MIN_PROXY_PREFIX_V4: u8 = 8;
const MIN_PROXY_PREFIX_V6: u8 = 16;

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

    const OK: [(&str, &str); 3] = [
        ("DATABASE_PRIMARY_URL", "postgres://u:segredo1@h/db"),
        ("DATABASE_REPLICA_URL", "postgres://u:segredo1@h/db"),
        ("REDIS_URL", "redis://h:6379"),
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
        let c = Config::from_lookup(env(&OK));
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("segredo1"));
    }
}
