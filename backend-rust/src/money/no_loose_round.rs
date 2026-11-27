//! Guarda: nenhum arredondamento solto em `src/`. `round_dp`, `round_sf` e `round` usam, por defeito, o
//! arredondamento bancário (metade para o par); a AT e o comércio usam half-up. Decimal → cêntimos passa só por
//! `money::half_up`, a única chamada permitida a `round_dp_with_strategy` (com `MidpointAwayFromZero`).
//! Os padrões são montados em tempo de execução para este ficheiro não se apanhar a si próprio.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

/// Chamadas proibidas, por método (`d.metodo(…)`) ou por caminho (`Decimal::metodo(&d, …)`).
fn forbidden() -> Vec<String> {
    let r = "round";
    vec![
        format!("{r}_dp("),
        format!("{r}_dp_with_strategy("),
        format!("{r}_sf("),
        format!("{r}_sf_with_strategy("),
        format!(".{r}("),
        format!("::{r}("),
    ]
}

/// Posições (byte) de cada ocorrência proibida, com o padrão encontrado.
fn occurrences(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for pat in forbidden() {
        let mut from = 0;
        while let Some(i) = src[from..].find(pat.as_str()) {
            let at = from + i;
            // Os padrões não se sobrepõem: todos acabam em `(` logo a seguir ao nome completo.
            out.push((at, pat.clone()));
            from = at + pat.len();
        }
    }
    out
}

/// Intervalo (byte) do corpo de `pub fn half_up` em `money/mod.rs`.
fn half_up_span(src: &str) -> (usize, usize) {
    let start = src
        .find("pub fn half_up(")
        .expect("money/mod.rs sem pub fn half_up");
    let end = start
        + src[start..]
            .find("\n}\n")
            .expect("fim de half_up não encontrado");
    (start, end)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_loose_rounding_outside_half_up() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let money_mod = src_dir.join("money").join("mod.rs");
    let mut files = Vec::new();
    rust_files(&src_dir, &mut files);
    assert!(files.len() >= 10, "esperava percorrer todo o src/");

    let mut allowed_seen = 0;
    let mut violations = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).unwrap();
        let span = (path == &money_mod).then(|| half_up_span(&src));
        for (at, pat) in occurrences(&src) {
            let in_half_up = span.is_some_and(|(s, e)| s <= at && at < e);
            if in_half_up && pat == format!("{}_dp_with_strategy(", "round") {
                allowed_seen += 1;
                continue;
            }
            let line = src[..at].matches('\n').count() + 1;
            violations.push(format!("{}:{line}: {pat}", path.display()));
        }
    }
    assert!(
        violations.is_empty(),
        "arredondamento solto (usar money::half_up): {violations:#?}"
    );
    assert_eq!(
        allowed_seen, 1,
        "half_up deve ter exatamente uma chamada round_dp_with_strategy"
    );

    let money_src = std::fs::read_to_string(&money_mod).unwrap();
    let (s, e) = half_up_span(&money_src);
    assert!(
        money_src[s..e].contains("RoundingStrategy::MidpointAwayFromZero"),
        "half_up tem de usar MidpointAwayFromZero"
    );
}

#[test]
fn detector_catches_loose_rounding() {
    let r = "round";
    for bad in [
        format!("let x = d.{r}_dp(2);"),
        format!("let x = Decimal::{r}_dp(&d, 2);"),
        format!("let x = d.{r}_dp_with_strategy(0, RoundingStrategy::BankersRounding);"),
        format!("let x = d.{r}();"),
        format!("let x = d.{r}_sf(3);"),
    ] {
        assert!(!occurrences(&bad).is_empty(), "devia apanhar: {bad}");
    }
    for ok in [
        "let x = half_up(d)?;",
        "let y = ts.round_subsecs(0);",
        "// arredondar com half_up",
        "let around = 1;",
    ] {
        assert!(occurrences(ok).is_empty(), "falso positivo: {ok}");
    }
}
