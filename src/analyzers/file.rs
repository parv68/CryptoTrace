use crate::error::Result;
use crate::types::DetectionResult;

/// Analyze a file by reading its contents and running the full detection pipeline.
pub fn analyze_file(path: &std::path::Path) -> Result<DetectionResult> {
    let guard = crate::sanitization::InputGuard::new();
    let sanitized = guard.sanitize_file(path)?;
    analyze_bytes(&sanitized.raw_bytes, crate::types::SourceType::File)
}

/// Analyze raw bytes through the detection pipeline.
pub fn analyze_bytes(data: &[u8], source_type: crate::types::SourceType) -> Result<DetectionResult> {
    // Entropy analysis
    let (entropy, _freq) = crate::core::entropy::shannon_entropy(data);
    let sliding = crate::core::sliding_entropy::sliding_window_entropy(data, None, None, None);

    // String analysis (if input looks like text)
    let input_str = String::from_utf8_lossy(data);

    // Hash detection
    let hash_detection = crate::core::hashing::detect_hash(&input_str);

    // Encoding detection
    let encoding_detection = crate::core::encoding::detect_encoding(&input_str);

    // Compression detection
    let _compression_detection = crate::core::compression::detect_compression(data);

    // Encryption detection
    let _encryption_detection = crate::core::encryption::detect_encryption(data, entropy);

    // Build result with Phase 1 confidence engine
    let result = crate::core::confidence::build_detection_result(
        data,
        source_type,
        hash_detection.as_ref(),
        encoding_detection.as_ref(),
        entropy,
        Some(&sliding),
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_bytes_plaintext() {
        let result = analyze_bytes(b"hello world", crate::types::SourceType::String).unwrap();
        assert_eq!(result.detected_type, "plaintext");
    }

    #[test]
    fn test_analyze_bytes_md5() {
        let result = analyze_bytes(b"5f4dcc3b5aa765d61d8327deb882cf99", crate::types::SourceType::String).unwrap();
        assert_eq!(result.detected_type, "hash");
        assert_eq!(result.algorithm.as_deref(), Some("MD5"));
    }
}
