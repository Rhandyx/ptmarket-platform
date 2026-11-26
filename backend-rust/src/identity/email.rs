//! Normalização do email de cliente (cartão 02/17; auditoria onda 4, achado 7).
//!
//! `normalize`: trim → NFC → minúsculas → NFC (a passagem a minúsculas pode desfazer a composição).
//! O email gravado e procurado é SEMPRE o normalizado (registo e login usam esta função): "Ana@X.pt ",
//! "ana@x.pt" e a forma NFD do mesmo texto são a mesma conta. Depois do trim não pode haver
//! caracteres de controlo nem espaços (CRLF, TAB, espaço no meio: injeção de cabeçalhos no envio) e
//! tem de haver exatamente um `@`, com texto antes e depois.

use unicode_normalization::UnicodeNormalization;

use crate::error::{AppError, FieldError};

/// Máximo em caracteres (= `customers.email VARCHAR(255)`).
pub const MAX_EMAIL_CHARS: usize = 255;

/// Email normalizado; vazio, com mais de 255 caracteres, com controlo/espaços, sem exatamente um
/// `@` ou com uma das partes vazia → erro de validação (campo `email`). A mensagem nunca repete o
/// valor recebido.
pub fn normalize(raw: &str) -> Result<String, AppError> {
    let lower = raw.trim().nfc().collect::<String>().to_lowercase();
    let email: String = lower.nfc().collect();
    if email.chars().count() > MAX_EMAIL_CHARS
        || email.chars().any(|c| c.is_control() || c.is_whitespace())
        || !one_at_with_both_parts(&email)
    {
        return Err(AppError::Validation(vec![FieldError {
            field: "email".into(),
            message: format!("Indique um email válido (até {MAX_EMAIL_CHARS} caracteres)."),
        }]));
    }
    Ok(email)
}

/// Exatamente um `@`, com texto antes e depois.
fn one_at_with_both_parts(email: &str) -> bool {
    match email.split_once('@') {
        Some((local, domain)) => !local.is_empty() && !domain.is_empty() && !domain.contains('@'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_composes_and_lowercases() {
        assert_eq!(
            normalize("  Ana@Exemplo.PT \n").ok().as_deref(),
            Some("ana@exemplo.pt")
        );
        // "é" decomposto (e + U+0301) e maiúsculo (E + U+0301) → U+00E9.
        let nfd = "Jose\u{0301}@x.pt";
        let upper_nfd = "JOSE\u{0301}@X.PT";
        let nfc = "jos\u{e9}@x.pt";
        assert_eq!(normalize(nfd).ok().as_deref(), Some(nfc));
        assert_eq!(normalize(upper_nfd).ok().as_deref(), Some(nfc));
        assert_eq!(normalize(nfc).ok().as_deref(), Some(nfc));
    }

    #[test]
    fn rejects_empty_long_and_without_at() {
        for bad in ["", "   ", "sem-arroba.pt"] {
            assert!(
                matches!(normalize(bad), Err(AppError::Validation(_))),
                "{bad:?}"
            );
        }
        let at_limit = format!("{}@x.pt", "a".repeat(MAX_EMAIL_CHARS - 5));
        assert_eq!(at_limit.chars().count(), MAX_EMAIL_CHARS);
        assert!(normalize(&at_limit).is_ok());
        let over = format!("{}@x.pt", "a".repeat(MAX_EMAIL_CHARS - 4));
        assert!(matches!(normalize(&over), Err(AppError::Validation(_))));
        // Os espaços das pontas não contam para o limite.
        assert!(normalize(&format!("  {at_limit}  ")).is_ok());
    }

    #[test]
    fn rejects_controls_whitespace_and_bad_at() {
        for bad in [
            "ana@x.pt\r\nBcc: z@y.pt",
            "ana\r\n@x.pt",
            "ana\t@x.pt",
            "ana silva@x.pt",
            "ana@x .pt",
            "ana\u{a0}@x.pt",
            "ana\u{0}@x.pt",
            "ana@@x.pt",
            "ana@x@y.pt",
            "@x.pt",
            "ana@",
            "@x",
            "@",
        ] {
            assert!(
                matches!(normalize(bad), Err(AppError::Validation(_))),
                "{bad:?}"
            );
        }
        // Espaços, TAB e CRLF só nas pontas: o trim tira-os.
        assert_eq!(
            normalize("\t ana@x.pt\r\n").ok().as_deref(),
            Some("ana@x.pt")
        );
    }

    #[test]
    fn lowercase_result_is_nfc() {
        // U+0130 (İ) em minúsculas dá "i" + U+0307: a 2.ª NFC deixa o resultado estável.
        let e = normalize("\u{130}@x.pt");
        assert!(e.is_ok());
        if let Ok(e) = e {
            let again: String = e.nfc().collect();
            assert_eq!(e, again);
            assert_eq!(normalize(&e).ok().as_deref(), Some(e.as_str()));
        }
    }

    #[test]
    fn error_never_echoes_the_value() {
        if let Err(AppError::Validation(f)) = normalize("segredo-sem-arroba") {
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].field, "email");
            assert!(!f[0].message.contains("segredo"));
        } else {
            unreachable!("devia ser erro de validação");
        }
    }
}
