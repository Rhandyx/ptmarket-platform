//! CSRF (spec 12 §3, cartão 02/16): token = base64url(HMAC-SHA256(CSRF_KEY, session_id)) e
//! verificação da `Origin`, além do `SameSite` do cookie.
//!
//! Todo o pedido que não seja GET/HEAD/OPTIONS com sessão válida exige `X-CSRF-Token` (ou o
//! campo `_csrf` num formulário `application/x-www-form-urlencoded`) igual ao da sessão, comparado
//! em tempo constante, E `Origin` com o host EFETIVO do pedido (o mesmo `effective_host` que decide
//! o tenant: `Host`, ou `X-Forwarded-Host` com `X-Internal-Token` válido). Falha → 403 +
//! `Denied("csrf")`.
//!
//! - Esquema: `https` obrigatório; `http` só se o host efetivo for `localhost`, `*.localhost` ou
//!   `127.0.0.1` (dev).
//! - SSR do Next (`X-Internal-Token` válido): pode vir sem `Origin` (o servidor não a tem); o token
//!   CSRF continua obrigatório. Com `Origin`, compara-se na mesma.
//! - Registo e login ANÓNIMOS (`/api/v1/auth/register`, `/api/v1/auth/login`): `Origin`
//!   obrigatória (mesmas regras; o SSR com token interno pode vir sem ela). Falha → 403 +
//!   `Denied("csrf")`. O logout anónimo (204 sem efeito) fica de fora.
//! - `capture_host` corre POR FORA de `resolve_host` (que apaga o `X-Internal-Token`) e guarda o
//!   host efetivo e a marca de proxy interno em `RequestHost`.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, Method,
        header::{CONTENT_TYPE, ORIGIN},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    audit::Denied,
    error::AppError,
    http::MAX_BODY_BYTES,
    identity::{
        http::{SessionInfo, Sessions},
        session::SessionId,
    },
    tenancy::host::{X_INTERNAL_TOKEN, effective_host, normalize_host},
};

/// Cabeçalho com o token (o mesmo nome que o cliente TS envia).
pub const X_CSRF_TOKEN: HeaderName = HeaderName::from_static("x-csrf-token");
/// Campo dos formulários HTML.
pub const FORM_FIELD: &str = "_csrf";
/// Motivo gravado na caixa negra.
pub const DENIED_CSRF: Denied = Denied("csrf");
/// Tamanho mínimo de `CSRF_KEY`.
pub const MIN_KEY_BYTES: usize = 32;

/// Chave HMAC dos tokens CSRF (`CSRF_KEY`, ≥ 32 bytes, validada em `Config`).
#[derive(Clone)]
pub struct CsrfKey(SecretString);

impl std::fmt::Debug for CsrfKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CsrfKey([redacted])")
    }
}

impl CsrfKey {
    pub fn new(key: SecretString) -> Self {
        Self(key)
    }

    /// Token CSRF da sessão `id` (43 caracteres base64url).
    pub fn token(&self, id: SessionId) -> Result<String, AppError> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.0.expose_secret().as_bytes())
            .map_err(|_| AppError::Internal(anyhow::anyhow!("CSRF_KEY inválida")))?;
        mac.update(id.as_uuid().as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }

    /// `provided` é o token da sessão `id` (tempo constante).
    pub fn verify(&self, id: SessionId, provided: &str) -> bool {
        match self.token(id) {
            Ok(expected) => bool::from(expected.as_bytes().ct_eq(provided.as_bytes())),
            Err(_) => false,
        }
    }
}

fn is_safe(m: &Method) -> bool {
    *m == Method::GET || *m == Method::HEAD || *m == Method::OPTIONS
}

/// Valor único e legível de um cabeçalho; ausente, repetido ou ilegível → `None`.
fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut it = headers.get_all(name).iter();
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

/// Host efetivo do pedido e se veio do proxy interno (SSR) com token válido. Posto por
/// `capture_host`; ausente = falha fechado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHost {
    pub host: Option<String>,
    pub internal: bool,
}

/// Compara o token interno em tempo constante (sha256 dos dois lados: nem o comprimento fuga).
fn internal_token_valid(headers: &HeaderMap, expected: Option<&SecretString>) -> bool {
    let (Some(expected), Some(provided)) = (expected, single(headers, &X_INTERNAL_TOKEN)) else {
        return false;
    };
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.expose_secret().as_bytes());
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// Layer (`from_fn_with_state`) POR FORA de `resolve_host`: guarda `RequestHost`. Nunca recusa.
pub async fn capture_host(State(s): State<Sessions>, mut req: Request, next: Next) -> Response {
    let token = s.internal_token();
    let host = effective_host(req.headers(), req.uri(), token);
    let internal = internal_token_valid(req.headers(), token);
    req.extensions_mut().insert(RequestHost { host, internal });
    next.run(req).await
}

/// Hosts de desenvolvimento (aceitam `http`).
fn is_dev_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost")
}

/// `Origin` aceitável para o host efetivo `rh`. Ausente: só no SSR com token interno válido.
/// `null`, repetida, com caminho/credenciais, outro esquema ou outro host → `false`.
pub fn origin_ok(headers: &HeaderMap, rh: &RequestHost) -> bool {
    let Some(host) = rh.host.as_deref() else {
        return false;
    };
    if !headers.contains_key(ORIGIN) {
        return rh.internal;
    }
    let Some(origin) = single(headers, &ORIGIN) else {
        return false;
    };
    let authority = match origin.split_once("://") {
        Some(("https", a)) => a,
        Some(("http", a)) if is_dev_host(host) => a,
        _ => return false,
    };
    if authority.contains(['/', '@', '?', '#']) {
        return false;
    }
    normalize_host(authority).is_some_and(|o| o == host)
}

fn is_form(headers: &HeaderMap) -> bool {
    single(headers, &CONTENT_TYPE).is_some_and(|ct| {
        ct.split(';').next().is_some_and(|m| {
            m.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    })
}

/// Valor do campo `_csrf` (o token é base64url: nunca precisa de percent-encoding). Repetido → `None`.
fn form_token(body: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(body).ok()?;
    let mut found = None;
    for pair in text.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == FORM_FIELD {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

fn deny() -> Response {
    (axum::Extension(DENIED_CSRF), AppError::Forbidden).into_response()
}

/// Rotas de autenticação anónimas que criam estado: exigem `Origin` válida mesmo sem sessão (login
/// CSRF / registo forçado a partir de outro site). O logout anónimo não muda nada (204 idempotente)
/// e fica de fora.
pub const ANONYMOUS_ORIGIN_PATHS: [&str; 2] = ["/api/v1/auth/register", "/api/v1/auth/login"];

/// Layer (`from_fn_with_state`) POR DENTRO da caixa negra: a recusa (403 + `Denied("csrf")`) fica
/// gravada. Mutações com sessão válida (`SessionInfo`): `Origin` + token. Registo e login anónimos
/// (`ANONYMOUS_ORIGIN_PATHS`): só `Origin` (não há sessão para o token). Restantes anónimas: passam.
pub async fn csrf_guard(State(s): State<Sessions>, req: Request, next: Next) -> Response {
    if is_safe(req.method()) {
        return next.run(req).await;
    }
    let origin = req
        .extensions()
        .get::<RequestHost>()
        .is_some_and(|rh| origin_ok(req.headers(), rh));
    let Some(info) = req.extensions().get::<SessionInfo>().copied() else {
        if ANONYMOUS_ORIGIN_PATHS.contains(&req.uri().path()) && !origin {
            return deny();
        }
        return next.run(req).await;
    };
    if !origin {
        return deny();
    }
    if req.headers().contains_key(X_CSRF_TOKEN) {
        let ok = single(req.headers(), &X_CSRF_TOKEN).is_some_and(|t| s.csrf().verify(info.id, t));
        return if ok { next.run(req).await } else { deny() };
    }
    if !is_form(req.headers()) {
        return deny();
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return deny();
    };
    if !form_token(&bytes).is_some_and(|t| s.csrf().verify(info.id, t)) {
        return deny();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use uuid::Uuid;

    fn key() -> CsrfKey {
        CsrfKey::new(SecretString::from("k".repeat(32)))
    }

    #[test]
    fn token_is_per_session_and_constant_time_verified() {
        let k = key();
        let a = SessionId::for_tests(Uuid::now_v7());
        let b = SessionId::for_tests(Uuid::now_v7());
        let ta = k.token(a).unwrap_or_default();
        assert_eq!(ta.len(), 43);
        assert!(k.verify(a, &ta));
        assert!(!k.verify(b, &ta));
        assert!(!k.verify(a, ""));
        assert!(!k.verify(a, &ta[..42]));
        let other = CsrfKey::new(SecretString::from("z".repeat(32)));
        assert!(!other.verify(a, &ta));
        assert!(!format!("{k:?}").contains("kkkk"));
    }

    fn headers(pairs: &[(HeaderName, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(k.clone(), HeaderValue::from_static(v));
        }
        h
    }

    fn rh(host: &str, internal: bool) -> RequestHost {
        RequestHost {
            host: Some(host.to_owned()),
            internal,
        }
    }

    #[test]
    fn origin_rules() {
        let prod = rh("a.pt", false);
        assert!(origin_ok(&headers(&[(ORIGIN, "https://A.pt:443")]), &prod));
        for bad in [
            headers(&[]),
            headers(&[(ORIGIN, "null")]),
            headers(&[(ORIGIN, "http://a.pt")]),
            headers(&[(ORIGIN, "https://b.pt")]),
            headers(&[(ORIGIN, "https://a.pt.b.pt")]),
            headers(&[(ORIGIN, "https://x@a.pt")]),
            headers(&[(ORIGIN, "ftp://a.pt")]),
            headers(&[(ORIGIN, "https://a.pt"), (ORIGIN, "https://a.pt")]),
        ] {
            assert!(!origin_ok(&bad, &prod), "{bad:?}");
        }
        // SSR com token interno: sem Origin passa; com Origin errada não.
        let ssr = rh("a.pt", true);
        assert!(origin_ok(&headers(&[]), &ssr));
        assert!(!origin_ok(&headers(&[(ORIGIN, "https://b.pt")]), &ssr));
        // Dev: http só em localhost / *.localhost.
        let dev = rh("camara.localhost", false);
        assert!(origin_ok(
            &headers(&[(ORIGIN, "http://camara.localhost:3000")]),
            &dev
        ));
        assert!(origin_ok(
            &headers(&[(ORIGIN, "https://camara.localhost")]),
            &dev
        ));
        assert!(!origin_ok(
            &headers(&[(ORIGIN, "http://outra.localhost")]),
            &dev
        ));
        let none = RequestHost {
            host: None,
            internal: true,
        };
        assert!(!origin_ok(&headers(&[]), &none));
    }

    #[test]
    fn internal_token_constant_time() {
        let t = SecretString::from("t".repeat(40));
        let tok = |vals: &[&str]| {
            let mut h = HeaderMap::new();
            for v in vals {
                if let Ok(v) = HeaderValue::from_str(v) {
                    h.append(X_INTERNAL_TOKEN, v);
                }
            }
            h
        };
        let ok = "t".repeat(40);
        assert!(internal_token_valid(&tok(&[&ok]), Some(&t)));
        assert!(!internal_token_valid(&tok(&["t"]), Some(&t)));
        assert!(!internal_token_valid(&tok(&[&ok]), None));
        assert!(!internal_token_valid(&tok(&[&ok, &ok]), Some(&t)));
    }

    #[test]
    fn form_field_parsing() {
        assert_eq!(form_token(b"a=1&_csrf=abc&b=2"), Some("abc"));
        assert_eq!(form_token(b"a=1"), None);
        assert_eq!(form_token(b"_csrf=a&_csrf=b"), None);
        assert!(is_form(&headers(&[(
            CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8"
        )])));
        assert!(!is_form(&headers(&[(CONTENT_TYPE, "application/json")])));
    }
}
