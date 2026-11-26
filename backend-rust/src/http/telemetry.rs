//! Logs JSON com redação de segredos e dados pessoais.
//!
//! Mesma cobertura que a BD e o Go: `docs/testdata/redaction-vectors.json` (vetores com `rust` em
//! `layers`) corre nos testes deste módulo. Mascarar a mais é aceitável; deixar passar não.
//!
//! - Chaves: normalizadas (camelCase → snake_case, minúsculas, sem acentos, `-`/`.`/espaço → `_`)
//!   e comparadas por subcadeia (palavras longas e compostos, ex. `tax_id`, `api_key`) ou por
//!   palavra inteira (curtas e ambíguas, ex. `nif`, `pin`, `pan`, `nome`), mais `*_key`/`*_enc`.
//! - Pares etiquetados (`{"key"|"k"|"name"|"field"|"path"|...: <chave sensível>, "value"|"v": x}`,
//!   o caminho conta pelo último segmento) e tuplos de 2 (`["nif", x]`): o valor é mascarado.
//! - Texto: credenciais em URLs, `chave=valor`, Bearer, JWT, e-mail, prefixos de chaves de API,
//!   IBAN (qualquer caixa; espaço(s), NBSP, `-`, `.`), NIB de 21 dígitos, telefone (E.164, `00`,
//!   PT nacional), PAN (Luhn), DNI/NIE e NIF (com ou sem `PT`).
//! - Uma regex que não compile → `redact_str` falha fechado (mascara tudo).

use std::io::Write;
use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::Value;
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

const MASK: &str = "[REDACTED]";

/// Subcadeias da chave normalizada que a tornam sensível (palavras longas e compostos).
const SENSITIVE_SUBSTR: [&str; 49] = [
    "password",
    "passwd",
    "palavra_passe",
    "pwd",
    "senha",
    "secret",
    "segredo",
    "token",
    "authorization",
    "cookie",
    "session",
    "signature",
    "hmac",
    "bearer",
    "jwt",
    "credential",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "chave",
    "iban",
    "tax_id",
    "taxid",
    "vat_id",
    "vat_number",
    "national_id",
    "account_number",
    "card_number",
    "card_pan",
    "cartao",
    "passport",
    "passaporte",
    "phone",
    "telefone",
    "telemovel",
    "mobile",
    "email",
    "e_mail",
    "contribuinte",
    "apelido",
    "morada",
    "nascimento",
    "birth",
    "first_name",
    "last_name",
    "full_name",
    "surname",
    "address",
];

/// Palavras da chave normalizada (separadas por `_`) que a tornam sensível só se forem a palavra
/// inteira (curtas: como subcadeia apanhariam `company`, `japan`, `shipping`...).
const SENSITIVE_WORD: [&str; 9] = [
    "nif", "nib", "pin", "pan", "cvv", "otp", "nome", "dni", "nie",
];

/// Chaves que etiquetam um par (`{"key": "password", "value": "..."}`).
const PAIR_LABEL: [&str; 9] = [
    "k",
    "key",
    "name",
    "field",
    "path",
    "label",
    "attribute",
    "attr",
    "campo",
];
/// Chaves do valor de um par etiquetado.
const PAIR_VALUE: [&str; 5] = ["v", "value", "val", "valor", "values"];

/// Separadores aceites dentro de IBAN/NIB/telefone/PAN: espaço, NBSP, `-`, `.`.
const SEP: &str = r"[ \u{00A0}.\-]";

struct Rules {
    uuid: Regex,
    url_creds: Regex,
    kv: Regex,
    bearer: Regex,
    jwt: Regex,
    email: Regex,
    api_key: Regex,
    iban: Regex,
    nib: Regex,
    phone_e164: Regex,
    phone_00: Regex,
    phone_pt: Regex,
    pan: Regex,
    dni_nie: Regex,
    nif: Regex,
}

/// `None` só se uma regex não compilar; nesse caso `redact_str` falha fechado (mascara tudo).
static RULES: LazyLock<Option<Rules>> = LazyLock::new(|| {
    Some(Rules {
        uuid: Regex::new(
            r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
        )
        .ok()?,
        url_creds: Regex::new(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]*:[^\s/@]+@").ok()?,
        kv: Regex::new(
            r#"(?i)\b(password|passwd|pwd|pass|senha|token|secret|segredo|nif|nib|iban|api[_-]?key)(["']?\s*[:=]\s*["']?)[^\s,"'&;}]+"#,
        )
        .ok()?,
        bearer: Regex::new(r"(?i)bearer\s+\S+").ok()?,
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*").ok()?,
        email: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
            .ok()?,
        api_key: Regex::new(r"\b(?:(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]+|AKIA[0-9A-Z]{16})\b")
            .ok()?,
        iban: Regex::new(&format!(
            r"(?i)\b[A-Z]{{2}}\d{{2}}(?:{SEP}{{0,3}}[A-Z0-9]{{4}}){{2,7}}(?:{SEP}{{0,3}}[A-Z0-9]{{1,3}})?\b"
        ))
        .ok()?,
        nib: Regex::new(&format!(r"\b\d(?:{SEP}{{0,3}}\d){{20}}\b")).ok()?,
        phone_e164: Regex::new(&format!(r"\+\d{{1,3}}{SEP}?\d(?:{SEP}?\d){{6,13}}\b")).ok()?,
        phone_00: Regex::new(&format!(r"\b00[1-9]\d{{0,2}}{SEP}?\d(?:{SEP}?\d){{6,13}}\b"))
            .ok()?,
        phone_pt: Regex::new(&format!(r"\b[29]\d{{2}}{SEP}?\d{{3}}{SEP}?\d{{3}}\b")).ok()?,
        pan: Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").ok()?,
        dni_nie: Regex::new(r"\b(?:\d{8}|[XYZxyz]\d{7})[A-Za-z]\b").ok()?,
        nif: Regex::new(r"(?i)\b(?:PT)?[1-9]\d{8}\b").ok()?,
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

/// IBAN: só se o resto (depois do país e dos 2 dígitos de controlo) tiver ≥ 8 dígitos (os IBAN
/// reais têm; evita apanhar texto como `ab12 casa mesa`).
fn mask_iban(c: &Captures) -> String {
    let m = &c[0];
    let digits = m.chars().skip(4).filter(char::is_ascii_digit).count();
    if digits >= 8 {
        "***".to_owned()
    } else {
        m.to_string()
    }
}

/// Mascara credenciais em URLs, `chave=valor`, Bearer, JWT, e-mail, chaves de API, IBAN, NIB,
/// telefones, PAN (Luhn), DNI/NIE e NIF.
///
/// Duas fases: as regras de contexto (credenciais em URL, `chave=valor`, Bearer, JWT, e-mail,
/// chaves de API) correm sobre o texto INTEIRO, por isso um UUID usado como segredo
/// (`token=<uuid>`, `Bearer <uuid>`...) é mascarado. Só depois, nas regras numéricas
/// (IBAN/NIB/telefone/PAN/DNI/NIE/NIF), os UUID que sobram passam intactos (ids de pedido, de
/// tenant...: os dígitos e as letras hexadecimais confundir-se-iam com NIB/IBAN/PAN).
pub fn redact_str(s: &str) -> String {
    let Some(r) = RULES.as_ref() else {
        return MASK.to_owned();
    };
    let s = r.url_creds.replace_all(s, "${1}***:***@");
    let s = r.kv.replace_all(&s, "${1}${2}***");
    let s = r.bearer.replace_all(&s, "Bearer ***");
    let s = r.jwt.replace_all(&s, "***");
    let s = r.email.replace_all(&s, "***@***");
    let s = r.api_key.replace_all(&s, "***");
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for m in r.uuid.find_iter(&s) {
        out.push_str(&redact_numeric(r, &s[last..m.start()]));
        out.push_str(m.as_str());
        last = m.end();
    }
    out.push_str(&redact_numeric(r, &s[last..]));
    out
}

/// Regras numéricas (fora dos UUID).
fn redact_numeric(r: &Rules, s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let s = r.iban.replace_all(s, mask_iban);
    let s = r.nib.replace_all(&s, "***");
    let s = r.phone_e164.replace_all(&s, "***");
    let s = r.phone_00.replace_all(&s, "***");
    let s = r.phone_pt.replace_all(&s, "***");
    let s = r.pan.replace_all(&s, mask_pan);
    let s = r.dni_nie.replace_all(&s, "***");
    r.nif.replace_all(&s, "***").into_owned()
}

/// Chave normalizada: camelCase → snake_case, minúsculas, sem acentos, `-`/`.`/espaço → `_`.
fn normalize_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    let mut prev_lower_or_digit = false;
    for ch in key.chars() {
        if ch.is_uppercase() && prev_lower_or_digit {
            out.push('_');
        }
        prev_lower_or_digit = ch.is_lowercase() || ch.is_ascii_digit();
        for lc in ch.to_lowercase() {
            out.push(match lc {
                'á' | 'à' | 'â' | 'ã' | 'ä' => 'a',
                'é' | 'è' | 'ê' | 'ë' => 'e',
                'í' | 'ì' | 'î' | 'ï' => 'i',
                'ó' | 'ò' | 'ô' | 'õ' | 'ö' => 'o',
                'ú' | 'ù' | 'û' | 'ü' => 'u',
                'ç' => 'c',
                'ñ' => 'n',
                '-' | '.' | ' ' | '\u{00A0}' => '_',
                c => c,
            });
        }
    }
    out
}

/// A chave (já normalizada) leva um valor sensível.
fn is_sensitive_normalized(k: &str) -> bool {
    if SENSITIVE_SUBSTR.iter().any(|s| k.contains(s)) {
        return true;
    }
    let words: Vec<&str> = k.split('_').filter(|w| !w.is_empty()).collect();
    if words.iter().any(|w| SENSITIVE_WORD.contains(w)) {
        return true;
    }
    // `*_key` (chaves de API, split keys) e `*_enc` (cifrados).
    words.len() >= 2 && matches!(words.last(), Some(&"key" | &"enc"))
}

fn is_sensitive(key: &str) -> bool {
    is_sensitive_normalized(&normalize_key(key))
}

/// Etiqueta de um par: sensível se a chave nomeada (ou o último segmento de um caminho) o for.
fn label_is_sensitive(label: &str) -> bool {
    is_sensitive(label)
        || label
            .rsplit(['.', '/', ':', '['])
            .next()
            .is_some_and(|last| is_sensitive(last.trim_end_matches(']')))
}

/// Substitui, recursivamente, os valores de chaves sensíveis, de pares etiquetados e de tuplos de
/// 2 (`["nif", x]`); o resto do texto passa por `redact_str`.
pub fn redact(v: &mut Value) {
    match v {
        Value::Object(m) => {
            let labelled = m.iter().any(|(k, val)| {
                PAIR_LABEL.contains(&normalize_key(k).as_str())
                    && val.as_str().is_some_and(label_is_sensitive)
            });
            for (k, val) in m.iter_mut() {
                if is_sensitive(k) || (labelled && PAIR_VALUE.contains(&normalize_key(k).as_str()))
                {
                    *val = Value::String(MASK.into());
                } else {
                    redact(val);
                }
            }
        }
        Value::Array(a) => {
            if a.len() == 2 && a[0].as_str().is_some_and(label_is_sensitive) {
                a[1] = Value::String(MASK.into());
            } else {
                a.iter_mut().for_each(redact);
            }
        }
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

    /// Os vetores partilhados com a BD e o Go (`layers` com `rust`).
    #[test]
    fn shared_redaction_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs/testdata/redaction-vectors.json"
        );
        let raw = std::fs::read_to_string(path).unwrap_or_default();
        let vectors: Vec<Value> = serde_json::from_str(&raw).unwrap_or_default();
        let mut ran = 0;
        let mut failures = Vec::new();
        for v in &vectors {
            let in_rust = v["layers"]
                .as_array()
                .is_some_and(|l| l.iter().any(|x| x == "rust"));
            if !in_rust {
                continue;
            }
            ran += 1;
            let id = v["id"].as_str().unwrap_or("?");
            let (out, same) = match v["kind"].as_str() {
                Some("text") => {
                    let input = v["input"].as_str().unwrap_or_default();
                    let out = redact_str(input);
                    let same = out == input;
                    (out, same)
                }
                Some("json") => {
                    let mut val = v["input"].clone();
                    redact(&mut val);
                    let same = val == v["input"];
                    (val.to_string(), same)
                }
                other => {
                    failures.push(format!("{id}: kind {other:?}"));
                    continue;
                }
            };
            for leak in v["must_not_contain"].as_array().into_iter().flatten() {
                let leak = leak.as_str().unwrap_or_default();
                if !leak.is_empty() && out.contains(leak) {
                    failures.push(format!("{id}: deixa passar {leak:?} em {out}"));
                }
            }
            if v["must_equal_input"] == true && !same {
                failures.push(format!("{id}: alterou a entrada: {out}"));
            }
        }
        assert!(ran > 0, "sem vetores em {path}");
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn key_normalization() {
        assert_eq!(normalize_key("taxId"), "tax_id");
        assert_eq!(normalize_key("IBAN"), "iban");
        assert_eq!(normalize_key("TELEMÓVEL"), "telemovel");
        assert_eq!(normalize_key("palavra-passe"), "palavra_passe");
        assert_eq!(normalize_key("cardPAN"), "card_pan");
        for clear in [
            "company_id",
            "expand_id",
            "japan",
            "shipping",
            "store_id",
            "title",
            "name",
        ] {
            assert!(!is_sensitive(clear), "{clear}");
        }
        for k in [
            "eupago_split_key",
            "invoicing_credentials_enc",
            "user_token",
            "NIF",
        ] {
            assert!(is_sensitive(k), "{k}");
        }
    }

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
        // UUID (ex.: request_id) com um grupo que parece IBAN/NIB: intacto; o resto é redigido.
        let id = "01a21850-6862-74c0-be12-345678901234";
        assert_eq!(redact_str(id), id);
        assert_eq!(
            redact_str(&format!("{id} nif 512345678")),
            format!("{id} nif ***")
        );
        // Um UUID usado como segredo nunca é protegido: as regras de contexto vêm primeiro.
        let secret = "5f0c9a3e-1b2d-4c5e-8f9a-0b1c2d3e4f5a";
        for input in [
            format!("token={secret}"),
            format!("password={secret}"),
            format!("Authorization: Bearer {secret}"),
            format!("postgres://u:{secret}@h/db"),
            format!("joao+{secret}@gmail.com"),
        ] {
            let out = redact_str(&input);
            assert!(!out.contains(secret), "{input} -> {out}");
            assert!(out.contains("***"), "{input} -> {out}");
        }
        assert_eq!(redact_str("evento publicado"), "evento publicado");
    }
}
