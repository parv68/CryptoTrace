use base64::Engine as _;

#[derive(Debug, Clone)]
pub struct EncodingDetection {
    pub encoding_type: String,
    pub confidence: f64,
    pub decoded_preview: Option<Vec<u8>>,
}

/// Detect if input string matches a known encoding format.
pub fn detect_encoding(input: &str) -> Option<EncodingDetection> {
    // Hex first — any hex string is also valid Base64 (alphanumeric charset),
    // so we must check Hex before Base64 to avoid false positives.
    if let Some(result) = detect_hex(input) {
        return Some(result);
    }

    // Base64
    if let Some(result) = detect_base64(input) {
        return Some(result);
    }

    // URL encoding
    if let Some(result) = detect_url_encoding(input) {
        return Some(result);
    }

    // Base32
    if let Some(result) = detect_base32(input) {
        return Some(result);
    }

    None
}

fn detect_base64(input: &str) -> Option<EncodingDetection> {
    let charset_ok = input.chars().all(|c| {
        matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '=')
    });
    if !charset_ok {
        return None;
    }

    let trimmed = input.trim_end_matches('=');
    let padding_count = input.len() - trimmed.len();
    if padding_count > 2 {
        return None;
    }

    // Decode attempt
    let decode_ok = base64::engine::general_purpose::STANDARD
        .decode(input)
        .is_ok();

    let openssl_prefix = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(input) {
        decoded.starts_with(b"Salted__")
    } else {
        false
    };

    let charset_score = if charset_ok { 1.0 } else { 0.0 };
    let padding_score = if padding_count <= 2 { 1.0 } else { 0.0 };
    let decode_score = if decode_ok { 1.0 } else { 0.0 };
    let openssl_score = if openssl_prefix { 1.0 } else { 0.0 };

    let confidence: f64 = charset_score * 0.3 + padding_score * 0.2 + decode_score * 0.4 + openssl_score * 0.1;

    if confidence < 0.5 {
        return None;
    }

    let decoded_preview = if decode_ok {
        base64::engine::general_purpose::STANDARD
            .decode(input)
            .ok()
            .map(|v| v.into_iter().take(64).collect())
    } else {
        None
    };

    Some(EncodingDetection {
        encoding_type: "Base64".to_string(),
        confidence: confidence.min(0.99),
        decoded_preview,
    })
}

fn detect_hex(input: &str) -> Option<EncodingDetection> {
    if input.len() % 2 != 0 {
        return None;
    }
    if !input.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F')) {
        return None;
    }

    let decoded: Vec<u8> = (0..input.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect();

    Some(EncodingDetection {
        encoding_type: "Hex".to_string(),
        confidence: 0.95,
        decoded_preview: Some(decoded.into_iter().take(64).collect()),
    })
}

fn detect_url_encoding(input: &str) -> Option<EncodingDetection> {
    let has_pct = input.contains('%');
    if !has_pct {
        return None;
    }

    let valid_pairs = input
        .as_bytes()
        .windows(3)
        .filter(|w| w[0] == b'%')
        .all(|w| {
            w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit()
        });

    if !valid_pairs {
        return None;
    }

    Some(EncodingDetection {
        encoding_type: "URLEncoding".to_string(),
        confidence: 0.90,
        decoded_preview: None,
    })
}

fn detect_base32(input: &str) -> Option<EncodingDetection> {
    if input.len() % 8 != 0 {
        return None;
    }
    if !input.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '=')) {
        return None;
    }

    Some(EncodingDetection {
        encoding_type: "Base32".to_string(),
        confidence: 0.85,
        decoded_preview: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let result = detect_encoding("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(result.encoding_type, "Base64");
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_base64_openssl() {
        let data = base64::engine::general_purpose::STANDARD
            .encode(b"Salted__some_encrypted_data");
        let result = detect_encoding(&data).unwrap();
        assert_eq!(result.encoding_type, "Base64");
        assert!(result.confidence > 0.95);
    }

    #[test]
    fn test_hex() {
        let result = detect_encoding("48656c6c6f").unwrap();
        assert_eq!(result.encoding_type, "Hex");
    }

    #[test]
    fn test_url_encoding() {
        let result = detect_encoding("hello%20world%21").unwrap();
        assert_eq!(result.encoding_type, "URLEncoding");
    }

    #[test]
    fn test_base32() {
        let result = detect_encoding("JBSWY3DPEB3W64TMMQ======").unwrap();
        assert_eq!(result.encoding_type, "Base32");
    }

    #[test]
    fn test_invalid() {
        let result = detect_encoding("this is plain text with no encoding");
        assert!(result.is_none());
    }
}
