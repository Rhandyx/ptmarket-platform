//! Captcha do registo (spec 12 §2): o token Turnstile é verificado SEMPRE no servidor
//! (`siteverify`), nunca só no browser. Falha fechado: timeout, erro de rede, estado HTTP ≠ 2xx ou
//! resposta ilegível → `false`. O Cloudflare recusa um token já usado (uso único). O `hostname` da
//! resposta tem de ser o host do tenant do pedido (um token resolvido noutro site não serve).
//!
//! O segredo e o token nunca vão para logs nem eventos.

use std::{net::IpAddr, time::Duration};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::error::AppError;

const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
/// Timeout total do pedido (ligação + resposta).
pub const TURNSTILE_TIMEOUT: Duration = Duration::from_secs(3);
/// Limite do corpo da resposta (a real tem centenas de bytes).
const MAX_BODY_BYTES: usize = 16 * 1024;

#[async_trait]
pub trait CaptchaVerifier: Send + Sync {
    /// `true` só se o serviço confirmar o token E o `hostname` onde foi resolvido for
    /// `expected_host` (o host do tenant do pedido, já normalizado). Qualquer falha → `false`.
    async fn verify(&self, token: &str, ip: Option<IpAddr>, expected_host: &str) -> bool;
}

/// Cliente do `siteverify` do Cloudflare Turnstile.
pub struct TurnstileVerifier {
    client: reqwest::Client,
    url: String,
    secret: SecretString,
}

impl std::fmt::Debug for TurnstileVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TurnstileVerifier([redacted])")
    }
}

impl TurnstileVerifier {
    /// `secret` = `TURNSTILE_SECRET`.
    pub fn new(secret: SecretString) -> Result<Self, AppError> {
        Self::build(SITEVERIFY_URL.to_owned(), secret, TURNSTILE_TIMEOUT)
    }

    fn build(url: String, secret: SecretString, timeout: Duration) -> Result<Self, AppError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AppError::Internal(anyhow::anyhow!("falha ao criar cliente Turnstile")))?;
        Ok(Self {
            client,
            url,
            secret,
        })
    }

    async fn call(
        &self,
        token: &str,
        ip: Option<IpAddr>,
        expected_host: &str,
    ) -> Result<bool, String> {
        let ip = ip.map(|i| i.to_string());
        let mut form: Vec<(&str, &str)> =
            vec![("secret", self.secret.expose_secret()), ("response", token)];
        if let Some(ip) = ip.as_deref() {
            form.push(("remoteip", ip));
        }
        let mut resp = self
            .client
            .post(&self.url)
            .form(&form)
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err(format!("estado HTTP {}", resp.status().as_u16()));
        }
        let mut body = Vec::new();
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
        Ok(success(&body, expected_host))
    }
}

/// `{"success": true, "hostname": <expected_host>, ...}` → `true`; tudo o resto → `false`.
/// Hostnames comparam-se sem distinção de maiúsculas (DNS).
fn success(body: &[u8], expected_host: &str) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let ok = v.get("success").and_then(serde_json::Value::as_bool) == Some(true);
    let host = v.get("hostname").and_then(serde_json::Value::as_str);
    ok && !expected_host.is_empty() && host.is_some_and(|h| h.eq_ignore_ascii_case(expected_host))
}

#[async_trait]
impl CaptchaVerifier for TurnstileVerifier {
    async fn verify(&self, token: &str, ip: Option<IpAddr>, expected_host: &str) -> bool {
        match self.call(token, ip, expected_host).await {
            Ok(ok) => ok,
            Err(reason) => {
                tracing::warn!(%reason, "Turnstile indisponível; captcha recusado (falha fechado)");
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

    /// Servidor HTTP local de uma ligação: devolve o pedido (cabeçalhos + corpo) pelo canal.
    /// `body = None` → aceita e nunca responde (timeout).
    fn local_server(status: u16, body: Option<&'static str>) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            // Lê até o cliente parar de enviar (cabeçalhos + corpo do formulário).
            while let Ok(n) = sock.read(&mut buf) {
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req);
                if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    if rest.len() >= len {
                        break;
                    }
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&req).into_owned());
            match body {
                Some(b) => {
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                        b.len()
                    );
                    sock.write_all(resp.as_bytes()).unwrap();
                }
                None => std::thread::sleep(Duration::from_secs(4)),
            }
        });
        (format!("http://{addr}/siteverify"), rx)
    }

    fn verifier(url: String, timeout: Duration) -> TurnstileVerifier {
        TurnstileVerifier::build(url, SecretString::from("segredo-turnstile"), timeout).unwrap()
    }

    #[tokio::test]
    async fn posts_secret_token_and_ip_and_accepts_success() {
        let (url, rx) = local_server(
            200,
            Some(r#"{"success":true,"hostname":"loja.ptmarket.invalid","error-codes":[]}"#),
        );
        let v = verifier(url, TURNSTILE_TIMEOUT);
        assert!(
            v.verify(
                "tok-123",
                Some("203.0.113.7".parse().unwrap()),
                "loja.ptmarket.invalid"
            )
            .await
        );
        let req = rx.recv().unwrap();
        assert!(req.starts_with("POST /siteverify HTTP/1.1"), "{req}");
        assert!(req.contains("secret=segredo-turnstile"), "{req}");
        assert!(req.contains("response=tok-123"), "{req}");
        assert!(req.contains("remoteip=203.0.113.7"), "{req}");
    }

    #[tokio::test]
    async fn failure_bad_status_and_garbage_are_false() {
        for (status, body) in [
            (
                200,
                r#"{"success":false,"error-codes":["timeout-or-duplicate"]}"#,
            ),
            (500, r#"{"success":true,"hostname":"a.invalid"}"#),
            (200, "nao-e-json"),
            (200, r#"{"success":"true","hostname":"a.invalid"}"#),
        ] {
            let (url, _rx) = local_server(status, Some(body));
            assert!(
                !verifier(url, TURNSTILE_TIMEOUT)
                    .verify("t", None, "a.invalid")
                    .await,
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn hostname_must_be_the_tenant_host() {
        for body in [
            r#"{"success":true,"hostname":"outro-site.invalid"}"#,
            r#"{"success":true}"#,
            r#"{"success":true,"hostname":null}"#,
            r#"{"success":true,"hostname":"a.invalid.evil"}"#,
        ] {
            let (url, _rx) = local_server(200, Some(body));
            assert!(
                !verifier(url, TURNSTILE_TIMEOUT)
                    .verify("t", None, "a.invalid")
                    .await,
                "{body}"
            );
        }
        let ok = br#"{"success":true,"hostname":"A.Invalid"}"#;
        assert!(success(ok, "a.invalid"));
        assert!(!success(ok, ""));
    }

    #[tokio::test]
    async fn timeout_is_false() {
        let (url, _rx) = local_server(200, None);
        let t = std::time::Instant::now();
        assert!(
            !verifier(url, Duration::from_millis(200))
                .verify("t", None, "a.invalid")
                .await
        );
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn production_constants_and_debug() {
        assert_eq!(TURNSTILE_TIMEOUT, Duration::from_secs(3));
        assert!(SITEVERIFY_URL.starts_with("https://challenges.cloudflare.com/"));
        let v = TurnstileVerifier::new(SecretString::from("segredo-x")).unwrap();
        assert!(!format!("{v:?}").contains("segredo"));
    }
}
