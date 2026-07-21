//! Truncation and string shaping helpers for EMV / display fields.

/// Truncate `s` to at most `max` characters (Unicode scalar values).
pub fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Map common Latin-1 accents to ASCII (PIX name/city friendliness).
pub fn strip_accents(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'ã' | 'â' | 'ä' | 'Á' | 'À' | 'Ã' | 'Â' | 'Ä' => 'A',
            'é' | 'è' | 'ê' | 'ë' | 'É' | 'È' | 'Ê' | 'Ë' => 'E',
            'í' | 'ì' | 'î' | 'ï' | 'Í' | 'Ì' | 'Î' | 'Ï' => 'I',
            'ó' | 'ò' | 'õ' | 'ô' | 'ö' | 'Ó' | 'Ò' | 'Õ' | 'Ô' | 'Ö' => 'O',
            'ú' | 'ù' | 'û' | 'ü' | 'Ú' | 'Ù' | 'Û' | 'Ü' => 'U',
            'ç' | 'Ç' => 'C',
            'ñ' | 'Ñ' => 'N',
            other => other,
        })
        .collect()
}

/// Truncate, strip accents, and upper-case (PIX city / name style).
pub fn truncate_upper(s: &str, max: usize) -> String {
    let cleaned = strip_accents(s);
    truncate_chars(&cleaned, max)
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

/// Normalize a PIX key for EMV embedding.
///
/// - CPF (11 digits) / CNPJ (14 digits): strip non-digits.
/// - Email / phone / EVP: trim only (phones keep `+` if present).
pub fn sanitize_pix_key(key: &str) -> String {
    let t = key.trim();
    let digits: String = t.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 11 || digits.len() == 14 {
        return digits;
    }
    t.to_string()
}

/// Keep only ASCII alphanumeric characters, then truncate to `max`.
pub fn sanitize_alnum(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(max)
        .collect()
}

/// Shorten a string for memo / status display with an ellipsis when truncated.
pub fn short_label(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let count = s.chars().count();
    if count <= max {
        return s.to_string();
    }
    if max <= 1 {
        return truncate_chars(s, max);
    }
    let mut out = truncate_chars(s, max - 1);
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_and_upper() {
        assert_eq!(truncate_chars("Hello World Extra", 11), "Hello World");
        assert_eq!(truncate_upper("sao paulo", 15), "SAO PAULO");
        assert_eq!(truncate_upper("São Paulo", 15), "SAO PAULO");
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_alnum("inv-001_x!", 25), "inv001x");
    }

    #[test]
    fn pix_key_cpf_cnpj_digits_only() {
        assert_eq!(sanitize_pix_key("123.456.789-09"), "12345678909");
        assert_eq!(
            sanitize_pix_key("12.345.678/0001-99"),
            "12345678000199"
        );
        assert_eq!(sanitize_pix_key("loja@empresa.com"), "loja@empresa.com");
    }
}
