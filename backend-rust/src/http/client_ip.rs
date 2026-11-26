//! IP do cliente para a caixa negra (spec 13 §1).
//!
//! `CF-Connecting-IP` só conta quando o peer TCP está numa das redes de `TRUSTED_PROXY_CIDRS`
//! (lista vazia = nunca confiar). Em todos os outros casos vale o peer; sem peer, não há IP.

use std::{net::IpAddr, sync::Arc};

use axum::http::HeaderMap;
use ipnet::IpNet;

/// Cabeçalho posto pela Cloudflare com o IP original do cliente.
pub const CF_CONNECTING_IP: &str = "cf-connecting-ip";

/// Redes dos proxies em que se confia (Cloudflare). Vazio = nunca confiar em cabeçalhos.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Arc<[IpNet]>);

impl TrustedProxies {
    /// Nunca confia em `CF-Connecting-IP`.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn new(nets: Vec<IpNet>) -> Self {
        Self(nets.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|n| n.contains(&ip))
    }

    /// O peer TCP é um proxy de confiança (só então contam cabeçalhos postos por ele, como
    /// `CF-Connecting-IP`). Sem peer = não. O `x-request-id` nunca conta (cartão 07b).
    pub fn trusts(&self, peer: Option<IpAddr>) -> bool {
        peer.is_some_and(|p| self.contains(p.to_canonical()))
    }
}

/// IP do cliente: `CF-Connecting-IP` se o peer for um proxy de confiança e o cabeçalho for um
/// IP válido (um só valor); senão o peer. IPv4 mapeado em IPv6 volta a IPv4.
pub fn client_ip(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> Option<IpAddr> {
    let peer = peer.map(|p| p.to_canonical())?;
    if !trusted.contains(peer) {
        return Some(peer);
    }
    let mut values = headers.get_all(CF_CONNECTING_IP).iter();
    let forwarded = match (values.next(), values.next()) {
        (Some(v), None) => v
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<IpAddr>().ok()),
        _ => None,
    };
    Some(forwarded.map_or(peer, |ip| ip.to_canonical()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    fn cf(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(CF_CONNECTING_IP, v);
        }
        h
    }

    fn trusted() -> TrustedProxies {
        TrustedProxies::new(
            ["10.0.0.0/8", "2400:cb00::/32"]
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
        )
    }

    #[test]
    fn untrusted_or_empty_list_uses_peer() {
        let h = cf("203.0.113.50");
        assert_eq!(
            client_ip(ip("198.51.100.9"), &h, &trusted()),
            ip("198.51.100.9")
        );
        assert_eq!(
            client_ip(ip("10.1.2.3"), &h, &TrustedProxies::none()),
            ip("10.1.2.3")
        );
        assert_eq!(client_ip(None, &h, &trusted()), None);
    }

    #[test]
    fn trusted_peer_uses_header_only_if_valid_single_ip() {
        let t = trusted();
        assert_eq!(
            client_ip(ip("10.1.2.3"), &cf("203.0.113.50"), &t),
            ip("203.0.113.50")
        );
        assert_eq!(
            client_ip(ip("2400:cb00::1"), &cf("2001:db8::5"), &t),
            ip("2001:db8::5")
        );
        assert_eq!(
            client_ip(ip("10.1.2.3"), &cf("nope, 1.2.3.4"), &t),
            ip("10.1.2.3")
        );
        assert_eq!(
            client_ip(ip("10.1.2.3"), &HeaderMap::new(), &t),
            ip("10.1.2.3")
        );
        let mut two = cf("203.0.113.50");
        two.append(CF_CONNECTING_IP, HeaderValue::from_static("203.0.113.51"));
        assert_eq!(client_ip(ip("10.1.2.3"), &two, &t), ip("10.1.2.3"));
    }

    #[test]
    fn trusts_only_listed_peers() {
        let t = trusted();
        assert!(t.trusts(ip("10.1.2.3")) && t.trusts(ip("::ffff:10.1.2.3")));
        assert!(!t.trusts(ip("198.51.100.9")) && !t.trusts(None));
        assert!(!TrustedProxies::none().trusts(ip("10.1.2.3")));
    }

    #[test]
    fn ipv4_mapped_peer_is_canonical() {
        assert_eq!(
            client_ip(ip("::ffff:10.1.2.3"), &cf("203.0.113.50"), &trusted()),
            ip("203.0.113.50")
        );
        assert_eq!(
            client_ip(ip("::ffff:198.51.100.9"), &HeaderMap::new(), &trusted()),
            ip("198.51.100.9")
        );
    }
}
