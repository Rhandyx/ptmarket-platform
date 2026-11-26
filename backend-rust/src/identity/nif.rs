//! NIF do cliente (cartão 02/17).
//!
//! - PT: 9 dígitos com dígito de controlo módulo 11 (`validate_pt`).
//! - ES: 9 caracteres alfanuméricos SEM validar o dígito de controlo (`plausible_es`). A validação
//!   NIF/NIE/CIF espera pela decisão do owner sobre ES.

/// Comprimento de um NIF (PT e ES).
pub const NIF_LEN: usize = 9;

/// NIF português: 9 dígitos ASCII, prefixo atribuído pela AT e o 9.º = 11 − (Σ dᵢ·(9−i), i = 0..8)
/// mod 11 (0 se o resultado for 10 ou 11).
///
/// Prefixos da AT (Portal das Finanças, "NIF/NIPC"):
/// - 1, 2, 3: pessoa singular (o 3 está reservado para quando esgotarem os 1 e 2);
/// - 45: pessoa singular não residente;
/// - 5: pessoa coletiva; 6: administração pública (central, regional, local);
/// - 70, 74, 75: herança indivisa; 71: não residente coletivo sujeito a retenção na fonte;
///   72: fundos de investimento; 77: atribuição oficiosa; 78: não residente abrangido pelo VAT
///   refund; 79: regime excecional (Expo 98);
/// - 8: empresário em nome individual (extinto; ainda há NIF em uso);
/// - 90, 91: condomínios, sociedades irregulares e heranças indivisas; 98: não residente sem
///   estabelecimento estável; 99: sociedades civis sem personalidade jurídica.
///
/// Aceites (lista do supervisor, 26/11): 1, 2, 3, 5, 6, 8, 9 ou 45, 70–79, 90–99.
pub fn validate_pt(nif: &str) -> bool {
    let bytes = nif.as_bytes();
    if bytes.len() != NIF_LEN || !bytes.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let prefix_ok = matches!(
        (bytes[0], bytes[1]),
        (b'1' | b'2' | b'3' | b'5' | b'6' | b'7' | b'8' | b'9', _) | (b'4', b'5')
    );
    if !prefix_ok {
        return false;
    }
    let digit = |i: usize| u32::from(bytes[i] - b'0');
    let sum: u32 = (0..8).map(|i| digit(i) * (9 - i as u32)).sum();
    let check = match 11 - sum % 11 {
        10 | 11 => 0,
        c => c,
    };
    digit(8) == check
}

/// NIF espanhol aceite por agora: 9 caracteres alfanuméricos ASCII (sem dígito de controlo).
pub fn plausible_es(nif: &str) -> bool {
    nif.len() == NIF_LEN && nif.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pt_valid_check_digits() {
        // Somas com resto 0, 1 (controlo 0) e restos comuns.
        for ok in [
            "123456789",
            "501964843",
            "999999990",
            "100000002",
            "100000100",
        ] {
            assert!(validate_pt(ok), "{ok}");
        }
    }

    #[test]
    fn pt_rejects_wrong_digit_length_and_non_digits() {
        for bad in [
            "123456788",
            "501964842",
            "12345678",
            "1234567890",
            "",
            "12345678a",
            " 23456789",
            "１23456789",
        ] {
            assert!(!validate_pt(bad), "{bad:?}");
        }
    }

    #[test]
    fn pt_only_at_prefixes() {
        // Dígito de controlo certo, prefixo fora da lista da AT.
        for bad in ["000000000", "400000008", "410000000", "490000002"] {
            assert!(!validate_pt(bad), "{bad}");
        }
        // 45, 7x, 3, 6, 8 e 9x com dígito de controlo certo.
        for ok in [
            "450000001",
            "700000003",
            "790000008",
            "300000006",
            "600000001",
            "800000005",
            "980000009",
        ] {
            assert!(validate_pt(ok), "{ok}");
        }
    }

    #[test]
    fn es_accepts_nine_alphanumerics_only() {
        for ok in ["12345678Z", "X1234567L", "B12345678", "123456789"] {
            assert!(plausible_es(ok), "{ok}");
        }
        for bad in [
            "12345678",
            "1234567890",
            "1234-678Z",
            "12345678 ",
            "12345678Ñ",
            "",
        ] {
            assert!(!plausible_es(bad), "{bad:?}");
        }
    }
}
