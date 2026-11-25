//! Logs JSON com redação de campos sensíveis (password, token, NIF, IBAN).

use std::io::Write;
use std::sync::LazyLock;

use regex::{Captures, Regex};
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

struct Rules {
    url_creds: Regex,
    kv: Regex,
    bearer: Regex,
    pan: Regex,
    iban: Regex,
    nif: Regex,
}

/// `None` só se uma regex não compilar; nesse caso `redact_str` falha fechado (mascara tudo).
static RULES: LazyLock<Option<Rules>> = LazyLock::new(|| {
    Some(Rules {
        url_creds: Regex::new(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]*:[^\s/@]+@").ok()?,
        kv: Regex::new(
            r#"(?i)\b(password|passwd|pass|token|secret|nif|iban|api[_-]?key)(["']?\s*[:=]\s*["']?)[^\s,"'&;}]+"#,
        )
        .ok()?,
        bearer: Regex::new(r"(?i)bearer\s+\S+").ok()?,
        pan: Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").ok()?,
        iban: Regex::new(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b").ok()?,
        nif: Regex::new(r"\b[1-9]\d{8}\b").ok()?,
    })
});

fn luhn_ok(digits: &[u32]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn mask_pan(c: &Captures) -> String {
    let m = &c[0];
    let digits: Vec<u32> = m.chars().filter_map(|ch| ch.to_digit(10)).collect();
    if (13..=19).contains(&digits.len()) && luhn_ok(&digits) {
        format!("***{}", &m[m.len() - 4..])
    } else {
        m.to_string()
    }
}

/// Mascara credenciais em URLs, tokens, passwords, Bearer, PAN (Luhn), IBAN e NIF.
pub fn redact_str(s: &str) -> String {
    let Some(r) = RULES.as_ref() else {
        return MASK.to_owned();
    };
    let s = r.url_creds.replace_all(s, "${1}***:***@");
    let s = r.kv.replace_all(&s, "${1}${2}***");
    let s = r.bearer.replace_all(&s, "Bearer ***");
    let s = r.pan.replace_all(&s, mask_pan);
    let s = r.iban.replace_all(&s, "***");
    r.nif.replace_all(&s, "***").into_owned()
}

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
        Value::String(s) => *s = redact_str(s),
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
    fn all_rules_compile() {
        assert!(RULES.is_some(), "uma regex de redação não compila");
    }

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

    #[test]
    fn redacts_string_values() {
        let cases = [
            ("password=hunter2", "hunter2"),
            ("Key (nif)=(123456789)", "123456789"),
            ("cliente 123456789 pagou", "123456789"),
            (
                "iban PT50000201231234567890154",
                "PT50000201231234567890154",
            ),
            ("dsn postgres://u:p@h/db", "u:p"),
            ("redis://default:s3cr3t@127.0.0.1:6379/0", "s3cr3t"),
            ("cartao 4111 1111 1111 1111", "4111 1111 1111"),
            ("cartao 4111-1111-1111-1111", "4111-1111"),
            ("Authorization: Bearer abc.def", "abc.def"),
        ];
        for (input, leak) in cases {
            let mut v = serde_json::json!({ "fields": { "error": input } });
            redact(&mut v);
            let out = v.to_string();
            assert!(!out.contains(leak), "{input} -> {out}");
            assert!(out.contains("***"), "{input} -> {out}");
        }
        assert_eq!(redact_str("ref 1234567890123456"), "ref 1234567890123456");
        assert!(redact_str("4111 1111 1111 1111").ends_with("1111"));
        assert_eq!(redact_str("evento publicado"), "evento publicado");
    }
}
