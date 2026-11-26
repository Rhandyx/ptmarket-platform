//! Normalização do `Host` e escolha do cabeçalho que conta (funções puras).
//!
//! O tenant vem SÓ do `Host` (ou, pelo SSR do Next na rede interna, do `X-Forwarded-Host` com
//! `X-Internal-Token` válido). Nunca de query, corpo, cookie ou outro cabeçalho.

use std::net::Ipv4Addr;

use axum::http::{HeaderMap, HeaderName, Uri, header::HOST};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Cabeçalho do SSR do Next com o host público pedido pelo browser.
pub const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
/// Segredo partilhado entre o SSR do Next e a API (rede interna).
pub const X_INTERNAL_TOKEN: HeaderName = HeaderName::from_static("x-internal-token");

/// Comprimento máximo de um nome DNS (sem o ponto final).
pub const MAX_HOST_LEN: usize = 253;
/// Comprimento máximo de cada etiqueta DNS.
pub const MAX_LABEL_LEN: usize = 63;

/// Normaliza um `Host`: minúsculas; tira `:porta` e um ponto final; só `[a-z0-9.-]`, no máximo
/// 253 caracteres, cada etiqueta com 1–63. Recusa (`None`) vazio, IP literal (IPv4, também as
/// formas numéricas curtas/hex que os browsers aceitam; IPv6 cai no conjunto de caracteres) e
/// qualquer outro caractere. IDN chega em punycode (`xn--`) e fica como está.
pub fn normalize_host(raw: &str) -> Option<String> {
    let host = match raw.rsplit_once(':') {
        Some((h, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            h
        }
        None => raw,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_HOST_LEN {
        return None;
    }
    let host = host.to_ascii_lowercase();
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return None;
    }
    if host
        .split('.')
        .any(|l| l.is_empty() || l.len() > MAX_LABEL_LEN)
    {
        return None;
    }
    if is_ip_literal(&host) {
        return None;
    }
    Some(host)
}

/// IPv4 literal ou "parece IPv4" para um browser (última etiqueta numérica, decimal ou `0x`).
/// Nenhum TLD real é numérico.
fn is_ip_literal(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    let last = host.rsplit('.').next().unwrap_or_default();
    let hex = last
        .strip_prefix("0x")
        .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    hex || last.bytes().all(|b| b.is_ascii_digit())
}

/// Valor único de um cabeçalho (texto visível). Ausente → `Ok(None)`; repetido ou ilegível → `Err`.
fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Result<Option<&'a str>, ()> {
    let mut it = headers.get_all(name).iter();
    let Some(first) = it.next() else {
        return Ok(None);
    };
    if it.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// Compara o token em tempo constante (SHA-256 dos dois lados: nem o comprimento fuga).
fn token_matches(provided: &str, expected: &SecretString) -> bool {
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.expose_secret().as_bytes());
    bool::from(a.as_slice().ct_eq(b.as_slice()))
}

/// Host normalizado que decide o tenant, ou `None` (→ 404).
///
/// - `Host` repetido, ilegível ou inválido → `None`. Sem `Host` (HTTP/2) usa-se a autoridade do
///   URI; com os dois, têm de coincidir.
/// - `X-Forwarded-Host` só conta com UM `X-Internal-Token` igual a `internal_token`; sem isso é
///   ignorado (vale o `Host`). Com token válido, tem de ser único e válido.
pub fn effective_host(
    headers: &HeaderMap,
    uri: &Uri,
    internal_token: Option<&SecretString>,
) -> Option<String> {
    let trusted = match (internal_token, single(headers, &X_INTERNAL_TOKEN)) {
        (Some(expected), Ok(Some(provided))) => token_matches(provided, expected),
        _ => false,
    };
    if trusted {
        match single(headers, &X_FORWARDED_HOST) {
            Ok(Some(fwd)) => return normalize_host(fwd),
            // Repetido ou ilegível com token válido: recusa (não se escolhe um dos valores).
            Err(()) => return None,
            Ok(None) => {}
        }
    }
    request_host(headers, uri)
}

/// `Host` do pedido (ou a autoridade do URI em HTTP/2); com os dois, têm de coincidir.
fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    let host_hdr = single(headers, &HOST).ok()?;
    let authority = uri.authority().map(|a| a.as_str());
    match (host_hdr, authority) {
        (Some(h), Some(a)) => {
            let h = normalize_host(h)?;
            (normalize_host(a)? == h).then_some(h)
        }
        (Some(h), None) => normalize_host(h),
        (None, Some(a)) => normalize_host(a),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use proptest::prelude::*;

    fn headers(pairs: &[(HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            if let Ok(v) = HeaderValue::from_str(v) {
                h.append(k.clone(), v);
            }
        }
        h
    }

    fn token() -> SecretString {
        SecretString::from("t".repeat(40))
    }

    fn uri() -> Uri {
        Uri::from_static("/api/v1/tenant")
    }

    #[test]
    fn examples() {
        let ok = [
            ("Loja.Lisboa.PT", "loja.lisboa.pt"),
            ("loja.lisboa.pt:8443", "loja.lisboa.pt"),
            ("loja.lisboa.pt.", "loja.lisboa.pt"),
            ("LOJA.lisboa.pt.:443", "loja.lisboa.pt"),
            ("xn--lj-xka.pt", "xn--lj-xka.pt"),
            ("localhost", "localhost"),
            ("a1.b-2.c3", "a1.b-2.c3"),
        ];
        for (raw, want) in ok {
            assert_eq!(normalize_host(raw).as_deref(), Some(want), "{raw}");
        }
        let bad = [
            "",
            ".",
            ":80",
            "loja..pt",
            ".loja.pt",
            "loja.pt..",
            "loja.pt:",
            "loja.pt:abc",
            "loja.pt:123456",
            "loja_pt.pt",
            "lója.pt",
            "loja.pt/x",
            "loja.pt,outra.pt",
            "loja pt",
            "127.0.0.1",
            "127.0.0.1:8080",
            "10.1",
            "loja.0x7f",
            "loja.123",
            "[::1]",
            "[::1]:8080",
            "::1",
        ];
        for raw in bad {
            assert_eq!(normalize_host(raw), None, "{raw:?}");
        }
        let long_label = format!("{}.pt", "a".repeat(64));
        assert_eq!(normalize_host(&long_label), None);
        let max_label = format!("{}.pt", "a".repeat(63));
        assert!(normalize_host(&max_label).is_some());
        let too_long = format!("{}.pt", vec!["a".repeat(60); 5].join("."));
        assert!(too_long.len() > MAX_HOST_LEN);
        assert_eq!(normalize_host(&too_long), None);
    }

    #[test]
    fn duplicate_or_missing_host_is_none() {
        let h = headers(&[(HOST, "a.pt"), (HOST, "a.pt")]);
        assert_eq!(effective_host(&h, &uri(), None), None);
        assert_eq!(effective_host(&HeaderMap::new(), &uri(), None), None);
        let h = headers(&[(HOST, "a.pt")]);
        assert_eq!(effective_host(&h, &uri(), None).as_deref(), Some("a.pt"));
    }

    #[test]
    fn authority_must_match_host() {
        let abs = Uri::from_static("https://b.pt/api/v1/tenant");
        let h = headers(&[(HOST, "a.pt")]);
        assert_eq!(effective_host(&h, &abs, None), None);
        let h = headers(&[(HOST, "B.pt:443")]);
        assert_eq!(effective_host(&h, &abs, None).as_deref(), Some("b.pt"));
        assert_eq!(
            effective_host(&HeaderMap::new(), &abs, None).as_deref(),
            Some("b.pt")
        );
    }

    #[test]
    fn forwarded_host_needs_valid_token() {
        let t = token();
        let base = [(HOST, "a.pt"), (X_FORWARDED_HOST, "b.pt")];
        // Sem token configurado, sem token no pedido, token errado, token repetido: ignora.
        assert_eq!(
            effective_host(&headers(&base), &uri(), None).as_deref(),
            Some("a.pt")
        );
        assert_eq!(
            effective_host(&headers(&base), &uri(), Some(&t)).as_deref(),
            Some("a.pt")
        );
        let wrong = "u".repeat(40);
        let mut with_wrong = base.to_vec();
        with_wrong.push((X_INTERNAL_TOKEN, wrong.as_str()));
        assert_eq!(
            effective_host(&headers(&with_wrong), &uri(), Some(&t)).as_deref(),
            Some("a.pt")
        );
        let good = "t".repeat(40);
        let prefix = "t".repeat(39);
        let mut with_prefix = base.to_vec();
        with_prefix.push((X_INTERNAL_TOKEN, prefix.as_str()));
        assert_eq!(
            effective_host(&headers(&with_prefix), &uri(), Some(&t)).as_deref(),
            Some("a.pt")
        );
        let mut twice = base.to_vec();
        twice.push((X_INTERNAL_TOKEN, good.as_str()));
        twice.push((X_INTERNAL_TOKEN, good.as_str()));
        assert_eq!(
            effective_host(&headers(&twice), &uri(), Some(&t)).as_deref(),
            Some("a.pt")
        );
        // Token certo: vale o X-Forwarded-Host (normalizado).
        let mut ok = vec![(HOST, "a.pt"), (X_FORWARDED_HOST, "B.PT:3000")];
        ok.push((X_INTERNAL_TOKEN, good.as_str()));
        assert_eq!(
            effective_host(&headers(&ok), &uri(), Some(&t)).as_deref(),
            Some("b.pt")
        );
        // Token certo sem X-Forwarded-Host: vale o Host.
        let only_token = [(HOST, "a.pt"), (X_INTERNAL_TOKEN, good.as_str())];
        assert_eq!(
            effective_host(&headers(&only_token), &uri(), Some(&t)).as_deref(),
            Some("a.pt")
        );
        // Token certo com X-Forwarded-Host repetido ou inválido: recusa (nunca cai no Host).
        let dup = [
            (HOST, "a.pt"),
            (X_FORWARDED_HOST, "b.pt"),
            (X_FORWARDED_HOST, "c.pt"),
            (X_INTERNAL_TOKEN, good.as_str()),
        ];
        assert_eq!(effective_host(&headers(&dup), &uri(), Some(&t)), None);
        let invalid = [
            (HOST, "a.pt"),
            (X_FORWARDED_HOST, "b.pt, c.pt"),
            (X_INTERNAL_TOKEN, good.as_str()),
        ];
        assert_eq!(effective_host(&headers(&invalid), &uri(), Some(&t)), None);
    }

    fn label() -> impl Strategy<Value = String> {
        "[a-zA-Z][a-zA-Z0-9-]{0,20}"
    }

    fn host() -> impl Strategy<Value = String> {
        prop::collection::vec(label(), 1..5).prop_map(|v| v.join("."))
    }

    proptest! {
        #[test]
        fn output_is_canonical(raw in "\\PC{0,300}") {
            if let Some(h) = normalize_host(&raw) {
                prop_assert!(h.len() <= MAX_HOST_LEN);
                prop_assert!(h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'));
                prop_assert!(h.split('.').all(|l| !l.is_empty() && l.len() <= MAX_LABEL_LEN));
                prop_assert!(h.parse::<std::net::IpAddr>().is_err());
                prop_assert_eq!(normalize_host(&h), Some(h.clone()));
            }
        }

        #[test]
        fn case_port_and_trailing_dot_are_equivalent(h in host(), port in 0u16..=65535, dot in any::<bool>()) {
            let base = normalize_host(&h);
            prop_assert_eq!(base.clone(), Some(h.to_ascii_lowercase()));
            let decorated = format!("{}{}:{port}", h.to_ascii_uppercase(), if dot { "." } else { "" });
            prop_assert_eq!(normalize_host(&decorated), base);
        }

        #[test]
        fn ipv4_literals_are_refused(a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>(), port in proptest::option::of(0u16..=65535)) {
            let ip = format!("{a}.{b}.{c}.{d}");
            let raw = match port { Some(p) => format!("{ip}:{p}"), None => ip };
            prop_assert_eq!(normalize_host(&raw), None);
        }
    }
}
