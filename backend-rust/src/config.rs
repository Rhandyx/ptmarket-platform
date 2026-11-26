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

/// `APP_ENV`: ambiente de execução (obrigatório, valor exato).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnv {
    Development,
    Test,
    Staging,
    Production,
}

impl AppEnv {
    /// Staging e produção exigem toda a configuração de segurança.
    pub fn is_strict(self) -> bool {
        matches!(self, Self::Staging | Self::Production)
    }

    fn parse(raw: Option<String>) -> Result<Self, ConfigError> {
        const KEY: &str = "APP_ENV";
        match raw.as_deref() {
            None | Some("") => Err(ConfigError::Missing(KEY)),
            Some("development") => Ok(Self::Development),
            Some("test") => Ok(Self::Test),
            Some("staging") => Ok(Self::Staging),
            Some("production") => Ok(Self::Production),
            Some(_) => Err(ConfigError::Invalid(
                KEY,
                "development | test | staging | production",
            )),
        }
    }
}

/// Chaves de teste da Cloudflare (aprovam/recusam sempre): prefixos 1x, 2x, 3x.
const TURNSTILE_TEST_PREFIXES: [&str; 3] = [
    "1x0000000000000000000000000000000",
    "2x0000000000000000000000000000000",
    "3x0000000000000000000000000000000",
];

#[derive(Debug)]
pub struct Config {
    pub app_env: AppEnv,
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
    /// `TURNSTILE_SECRET` (chave secreta do Cloudflare Turnstile; `siteverify` no registo). Sem ela
    /// o registo de clientes não é servido (`Config::require_turnstile_secret`).
    pub turnstile_secret: Option<SecretString>,
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

const TURNSTILE_SECRET: &str = "TURNSTILE_SECRET";

fn turnstile_secret(raw: Option<String>) -> Result<Option<SecretString>, ConfigError> {
    let Some(v) = raw.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let secret = SecretString::from(v);
    let s = secret.expose_secret();
    if s.trim() != s || s.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            TURNSTILE_SECRET,
            "sem espaços nas pontas nem caracteres de controlo",
        ));
    }
    Ok(Some(secret))
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

    /// `TURNSTILE_SECRET` para servir o registo de clientes; ausente → erro de arranque.
    pub fn require_turnstile_secret(&self) -> Result<SecretString, ConfigError> {
        self.turnstile_secret
            .clone()
            .ok_or(ConfigError::Missing(TURNSTILE_SECRET))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let app_env = AppEnv::parse(get("APP_ENV"))?;
        let pg = ["postgres://", "postgresql://"];
        let bind = get("BIND_ADDR")
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_BIND.to_owned());
        let cfg = Self {
            app_env,
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
            turnstile_secret: turnstile_secret(get(TURNSTILE_SECRET))?,
        };
        if app_env.is_strict() {
            cfg.check_strict()?;
        }
        Ok(cfg)
    }

    /// Regras de staging/produção: o que em dev é opcional passa a obrigatório.
    fn check_strict(&self) -> Result<(), ConfigError> {
        if self.trusted_proxy_cidrs.is_empty() {
            return Err(ConfigError::Invalid(
                "TRUSTED_PROXY_CIDRS",
                "obrigatória em staging/production (sem ela todos os clientes contam como um só IP)",
            ));
        }
        if self.internal_proxy_token.is_none() {
            return Err(ConfigError::Invalid(
                "INTERNAL_PROXY_TOKEN",
                "obrigatória em staging/production",
            ));
        }
        if self.csrf_key.is_none() {
            return Err(ConfigError::Invalid(
                CSRF_KEY,
                "obrigatória em staging/production",
            ));
        }
        if self.platform_admin_host.is_none() {
            return Err(ConfigError::Invalid(
                "PLATFORM_ADMIN_HOST",
                "obrigatória em staging/production",
            ));
        }
        match &self.turnstile_secret {
            None => Err(ConfigError::Invalid(
                TURNSTILE_SECRET,
                "obrigatória em staging/production",
            )),
            Some(s)
                if TURNSTILE_TEST_PREFIXES
                    .iter()
                    .any(|p| s.expose_secret().starts_with(p)) =>
            {
                Err(ConfigError::Invalid(
                    TURNSTILE_SECRET,
                    "chave de teste da Cloudflare não é aceite em staging/production",
                ))
            }
            Some(_) => Ok(()),
        }
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

    const OK: [(&str, &str); 5] = [
        ("APP_ENV", "development"),
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
        let e = Config::from_lookup(env(&[("APP_ENV", "test")]))
            .err()
            .map(|e| e.to_string());
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
    fn turnstile_secret_optional_validated_and_hidden() {
        let c = Config::from_lookup(env(&OK));
        assert!(c.as_ref().is_ok_and(|c| c.turnstile_secret.is_none()));
        let e = c
            .ok()
            .and_then(|c| c.require_turnstile_secret().err())
            .map(|e| e.to_string());
        assert_eq!(
            e.as_deref(),
            Some("variável de ambiente em falta: TURNSTILE_SECRET")
        );
        let mut v = OK.to_vec();
        v.push(("TURNSTILE_SECRET", "0x4AAAsegredo-turnstile"));
        let c = Config::from_lookup(env(&v));
        assert!(
            c.as_ref()
                .is_ok_and(|c| c.require_turnstile_secret().is_ok())
        );
        assert!(!format!("{c:?}").contains("segredo-turnstile"));
        for bad in [" 0x4AAAsegredo", "0x4AAA\nsegredo"] {
            let mut v = OK.to_vec();
            v.push(("TURNSTILE_SECRET", bad));
            let e = Config::from_lookup(env(&v)).err().map(|e| e.to_string());
            assert!(
                e.as_deref().is_some_and(|s| !s.contains("segredo")),
                "{bad:?}"
            );
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

    const PROD: [(&str, &str); 10] = [
        ("APP_ENV", "production"),
        ("DATABASE_PRIMARY_URL", "postgres://u:segredo1@h/db"),
        ("DATABASE_REPLICA_URL", "postgres://u:segredo1@h/db"),
        ("REDIS_URL", "redis://h:6379"),
        ("CSRF_KEY", "chave-csrf-segredo-com-32-bytes-ok"),
        ("TRUSTED_PROXY_CIDRS", "173.245.48.0/20"),
        (
            "INTERNAL_PROXY_TOKEN",
            "token-interno-segredo-com-32-bytes-ok",
        ),
        ("PLATFORM_ADMIN_HOST", "admin.ptmarket.pt"),
        ("TURNSTILE_SECRET", "0x4AAAsegredo-turnstile"),
        ("BIND_ADDR", "0.0.0.0:8080"),
    ];

    fn err_of(v: &[(&str, &str)]) -> Option<String> {
        Config::from_lookup(env(v)).err().map(|e| e.to_string())
    }

    #[test]
    fn app_env_required_and_exact() {
        let v: Vec<_> = OK
            .iter()
            .copied()
            .filter(|(k, _)| *k != "APP_ENV")
            .collect();
        assert_eq!(
            err_of(&v).as_deref(),
            Some("variável de ambiente em falta: APP_ENV")
        );
        for bad in ["prod", "Production", " production", "dev"] {
            let mut v = v.clone();
            v.push(("APP_ENV", bad));
            let e = err_of(&v);
            assert!(
                e.as_deref().is_some_and(|s| s.contains("APP_ENV")
                    && s.contains("development | test | staging | production")),
                "{bad}"
            );
        }
        for good in ["development", "test"] {
            let mut v = v.clone();
            v.push(("APP_ENV", good));
            assert!(Config::from_lookup(env(&v)).is_ok_and(|c| !c.app_env.is_strict()));
        }
    }

    #[test]
    fn strict_complete_ok_and_each_missing_named() {
        for e in ["production", "staging"] {
            let mut v = PROD.to_vec();
            v[0] = ("APP_ENV", e);
            assert!(
                Config::from_lookup(env(&v)).is_ok_and(|c| c.app_env.is_strict()),
                "{e}"
            );
        }
        for key in [
            "TRUSTED_PROXY_CIDRS",
            "INTERNAL_PROXY_TOKEN",
            "CSRF_KEY",
            "PLATFORM_ADMIN_HOST",
            "TURNSTILE_SECRET",
        ] {
            let v: Vec<_> = PROD.iter().copied().filter(|(k, _)| *k != key).collect();
            let e = err_of(&v);
            assert!(e.as_deref().is_some_and(|s| s.contains(key)), "{key}");
            let mut v2 = v.clone();
            v2.push((key, ""));
            assert!(err_of(&v2).is_some_and(|s| s.contains(key)), "{key} vazio");
        }
    }

    #[test]
    fn strict_rejects_turnstile_test_keys_without_leaking() {
        for k in [
            "1x00000000000000000000000000000000AA",
            "2x0000000000000000000000000000000AA",
            "3x0000000000000000000000000000000AA",
        ] {
            let mut v = PROD.to_vec();
            v.push(("TURNSTILE_SECRET", k));
            let e = err_of(&v);
            assert!(
                e.as_deref()
                    .is_some_and(|s| s.contains("TURNSTILE_SECRET") && !s.contains(k)),
                "{k}"
            );
        }
        // Em development a chave de teste continua aceite.
        let mut v = OK.to_vec();
        v.push(("TURNSTILE_SECRET", "1x0000000000000000000000000000000AA"));
        assert!(Config::from_lookup(env(&v)).is_ok());
    }

    #[test]
    fn strict_errors_do_not_leak_values() {
        for key in ["CSRF_KEY", "TRUSTED_PROXY_CIDRS", "TURNSTILE_SECRET"] {
            let v: Vec<_> = PROD.iter().copied().filter(|(k, _)| *k != key).collect();
            let e = err_of(&v).unwrap_or_default();
            for secret in [
                "chave-csrf",
                "segredo1",
                "postgres://",
                "redis://",
                "segredo-turnstile",
            ] {
                assert!(!e.contains(secret), "{key}: {secret}");
            }
        }
    }
}
