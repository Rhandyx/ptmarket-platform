//! Guarda: nenhum tipo de vírgula flutuante nem cast para ele em `src/money/`.
//! Os padrões são montados em tempo de execução para este ficheiro não se apanhar a si próprio.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

fn is_ident(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// Encontra, por palavra, os tipos proibidos (apanha também os casts `as` para eles).
/// Não procura `as` + palavra em `f`: daria falsos positivos em comentários PT ("as faturas").
fn violations(src: &str) -> Vec<String> {
    let float_types = [format!("f{}", 32), format!("f{}", 64)];
    src.split(|ch: char| !is_ident(ch))
        .filter(|w| float_types.iter().any(|t| w.contains(t.as_str())))
        .map(str::to_owned)
        .collect()
}

#[test]
fn money_has_no_float() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/money");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let v = violations(&src);
        assert!(v.is_empty(), "{}: {v:?}", path.display());
        checked += 1;
    }
    assert!(checked >= 3, "esperava mod.rs, tests.rs e este ficheiro");
}

#[test]
fn detector_catches_floats() {
    let bad_type = format!("let x: f{} = 1;", 64);
    let bad_cast = format!("let y = n a{} f{};", "s", 32);
    assert!(!violations(&bad_type).is_empty());
    assert!(!violations(&bad_cast).is_empty());
    assert!(violations("let z: i64 = 1; // has failed").is_empty());
    assert!(violations("// emitir as faturas da loja").is_empty());
}
