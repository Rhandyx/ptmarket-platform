//! Verificação de passwords vazadas (HIBP, k-anonymity) no registo.
//!
//! Só saem os 5 primeiros hex do SHA-1; o sufixo compara-se localmente. Falhas de terceiros
//! nunca bloqueiam o registo (devolvem `false` com aviso). A password, o SHA-1 completo e o
//! prefixo nunca vão para logs.

use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

use super::password::Password;
use crate::error::AppError;

const HIBP_BASE_URL: &str = "https://api.pwnedpasswords.com";
/// Timeout total do pedido (ligação + resposta).
pub const HIBP_TIMEOUT: Duration = Duration::from_secs(2);
/// User-Agent genérico: sem nome do projeto nem dados do utilizador.
const HIBP_USER_AGENT: &str = "pwned-range-client/1.0";
/// Limite do corpo da resposta (a resposta real com padding tem dezenas de KiB).
const MAX_BODY_BYTES: usize = 1024 * 1024;
const PREFIX_LEN: usize = 5;

#[async_trait]
pub trait BreachChecker: Send + Sync {
    /// `true` se a password aparece em fugas conhecidas. Falha do serviço → `false`.
    async fn is_breached(&self, p: &Password) -> bool;
}

/// Para testes e ambientes sem rede: nunca considera a password vazada.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullBreachChecker;

#[async_trait]
impl BreachChecker for NullBreachChecker {
    async fn is_breached(&self, _p: &Password) -> bool {
        false
    }
}

/// Cliente HIBP "range" (k-anonymity).
#[derive(Debug, Clone)]
pub struct HibpRange {
    client: reqwest::Client,
    base_url: String,
}

impl HibpRange {
    pub fn new() -> Result<Self, AppError> {
        Self::build(HIBP_BASE_URL.to_owned(), HIBP_TIMEOUT)
    }

    fn build(base_url: String, timeout: Duration) -> Result<Self, AppError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(HIBP_USER_AGENT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("falha ao criar cliente HIBP")))?;
        Ok(Self { client, base_url })
    }

    async fn fetch_range(&self, prefix: &str) -> Result<Zeroizing<String>, String> {
        let url = format!("{}/range/{prefix}", self.base_url);
        let mut resp = self
            .client
            .get(url)
            .header("Add-Padding", "true")
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err(format!("estado HTTP {}", resp.status().as_u16()));
        }
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| e.without_url().to_string())?
        {
            if body.len() + chunk.len() > MAX_BODY_BYTES {
                return Err("resposta demasiado grande".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| "resposta não é UTF-8".to_owned())
    }
}

impl HibpRange {
    /// Versão estrita (CLI de operação, cartão 02/20c): `Ok(true)` vazada, `Ok(false)` não vazada,
    /// `Err(ServiceUnavailable)` se o serviço falhar (o chamador aborta; nunca "passa" sem
    /// verificação).
    pub async fn check_strict(&self, p: &Password) -> Result<bool, AppError> {
        let hex = sha1_upper_hex(p.expose_bytes());
        let (Some(prefix), Some(suffix)) = (hex.get(..PREFIX_LEN), hex.get(PREFIX_LEN..)) else {
            return Err(AppError::Internal(anyhow::anyhow!("SHA-1 inesperado")));
        };
        match self.fetch_range(prefix).await {
            Ok(body) => Ok(range_contains(&body, suffix)),
            Err(reason) => {
                tracing::warn!(%reason, "verificação HIBP indisponível (modo estrito)");
                Err(AppError::ServiceUnavailable)
            }
        }
    }
}

/// SHA-1 em hex maiúsculo (40 caracteres), apagado da memória ao largar.
fn sha1_upper_hex(bytes: &[u8]) -> Zeroizing<String> {
    let digest = Sha1::digest(bytes);
    let mut hex = Zeroizing::new(String::with_capacity(40));
    for b in digest.iter() {
        let _ = write!(hex, "{b:02X}");
    }
    hex
}

/// Procura `suffix` nas linhas `SUFIXO:CONTAGEM`; entradas de padding têm contagem 0.
fn range_contains(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        let Some((s, count)) = line.trim().split_once(':') else {
            return false;
        };
        s.eq_ignore_ascii_case(suffix) && count.trim().parse::<u64>().is_ok_and(|c| c > 0)
    })
}

#[async_trait]
impl BreachChecker for HibpRange {
    async fn is_breached(&self, p: &Password) -> bool {
        let hex = sha1_upper_hex(p.expose_bytes());
        let (Some(prefix), Some(suffix)) = (hex.get(..PREFIX_LEN), hex.get(PREFIX_LEN..)) else {
            return false;
        };
        match self.fetch_range(prefix).await {
            Ok(body) => range_contains(&body, suffix),
            Err(reason) => {
                tracing::warn!(%reason, "verificação HIBP indisponível; registo segue sem ela");
                false
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// Servidor HTTP local de uma ligação: devolve o pedido recebido pelo canal.
    /// `body = None` → aceita e nunca responde (para o teste de timeout).
    fn local_server(body: Option<String>) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            let _ = tx.send(String::from_utf8_lossy(&req).into_owned());
            match body {
                Some(b) => {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                        b.len()
                    );
                    sock.write_all(resp.as_bytes()).unwrap();
                }
                None => std::thread::sleep(Duration::from_secs(3)),
            }
        });
        (format!("http://{addr}"), rx)
    }

    const PW: &str = "password123";

    fn split(pw: &str) -> (String, String) {
        let hex = sha1_upper_hex(pw.as_bytes());
        (hex[..5].to_owned(), hex[5..].to_owned())
    }

    #[test]
    fn sha1_matches_known_vector() {
        // SHA-1("password") conhecido.
        assert_eq!(
            sha1_upper_hex(b"password").as_str(),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        );
    }

    #[tokio::test]
    async fn only_prefix_is_sent_and_present_suffix_is_breached() {
        let (prefix, suffix) = split(PW);
        let body = format!("0000000000000000000000000000000000A:0\r\n{suffix}:42\r\n");
        let (base, rx) = local_server(Some(body));
        let checker = HibpRange::build(base, HIBP_TIMEOUT).unwrap();

        assert!(checker.is_breached(&Password::parse(PW).unwrap()).await);

        let req = rx.recv().unwrap();
        let first = req.lines().next().unwrap();
        assert_eq!(first, format!("GET /range/{prefix} HTTP/1.1"));
        assert!(!req.contains(&suffix), "sufixo saiu no pedido");
        assert!(!req.contains(PW), "password saiu no pedido");
        let lower = req.to_ascii_lowercase();
        assert!(lower.contains("add-padding: true"));
        assert!(lower.contains(&format!("user-agent: {HIBP_USER_AGENT}")));
    }

    #[tokio::test]
    async fn absent_or_padding_suffix_is_not_breached() {
        let (_, suffix) = split(PW);
        // O sufixo só aparece como padding (contagem 0).
        let body = format!("{suffix}:0\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\r\n");
        let (base, _rx) = local_server(Some(body));
        let checker = HibpRange::build(base, HIBP_TIMEOUT).unwrap();
        assert!(!checker.is_breached(&Password::parse(PW).unwrap()).await);
    }

    #[tokio::test]
    async fn timeout_is_not_breached() {
        let (base, _rx) = local_server(None);
        let checker = HibpRange::build(base, Duration::from_millis(200)).unwrap();
        let t = std::time::Instant::now();
        assert!(!checker.is_breached(&Password::parse(PW).unwrap()).await);
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn null_checker_is_never_breached() {
        assert!(
            !NullBreachChecker
                .is_breached(&Password::parse(PW).unwrap())
                .await
        );
    }

    #[test]
    fn production_constants() {
        assert_eq!(HIBP_TIMEOUT, Duration::from_secs(2));
        assert!(HIBP_BASE_URL.starts_with("https://"));
        assert!(HibpRange::new().is_ok());
    }
}
