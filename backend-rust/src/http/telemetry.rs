//! Logs JSON com redação de campos sensíveis (password, token, NIF, IBAN).

use std::io::Write;

use serde_json::Value;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

const SENSITIVE: [&str; 8] = [
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "nif",
    "iban",
    "cookie",
];
const MASK: &str = "[REDACTED]";

fn is_sensitive(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE.iter().any(|s| k.contains(s))
}

/// Substitui, recursivamente, os valores de chaves sensíveis.
pub fn redact(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if is_sensitive(k) {
                    *val = Value::String(MASK.into());
                } else {
                    redact(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact),
        _ => {}
    }
}

/// Escritor por evento: no fim, redige o JSON e escreve em stdout.
pub struct RedactingWriter(Vec<u8>);

impl Write for RedactingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        let out = match serde_json::from_slice::<Value>(&self.0) {
            Ok(mut v) => {
                redact(&mut v);
                let mut s = v.to_string();
                s.push('\n');
                s.into_bytes()
            }
            // Linha que não é JSON: não arriscar fuga.
            Err(_) => b"{\"message\":\"[unparseable log line dropped]\"}\n".to_vec(),
        };
        let _ = std::io::stdout().write_all(&out);
    }
}

pub struct RedactingMakeWriter;

impl<'a> MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter(Vec::new())
    }
}

pub fn init() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(RedactingMakeWriter)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_nested_sensitive_keys() {
        let mut v = serde_json::json!({
            "message": "x",
            "fields": { "password": "p", "user_token": "t", "nif": "123", "IBAN": "PT50", "ok": "1" }
        });
        redact(&mut v);
        let s = v.to_string();
        for leak in ["\"p\"", "\"t\"", "123", "PT50"] {
            assert!(!s.contains(leak), "{leak}");
        }
        assert!(s.contains("\"ok\":\"1\""));
    }
}
