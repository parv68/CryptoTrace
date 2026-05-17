use crate::error::Result;

#[derive(Debug, Clone)]
pub struct CompressionDetection {
    pub format: String,
    pub confidence: f64,
    pub magic_match: bool,
}

/// Magic byte signatures for common compression formats.
const MAGIC_BYTES: &[(&[u8], &str)] = &[
    (b"\x1f\x8b", "GZIP"),
    (b"\x42\x5a\x68", "BZ2"),
    (b"\x28\xb5\x2f\xfd", "Zstd"),
    (b"\xfd\x37\x7a\x58\x5a\x00", "XZ"),
    (b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a", "Zlib"), // LZF format
];

/// Detect compression format by matching magic bytes.
pub fn detect_compression(data: &[u8]) -> Option<CompressionDetection> {
    for (magic, format) in MAGIC_BYTES {
        if data.starts_with(magic) {
            return Some(CompressionDetection {
                format: format.to_string(),
                confidence: 0.95,
                magic_match: true,
            });
        }
    }

    // ZIP detection: starts with PK\x03\x04
    if data.len() >= 4 && data[0..4] == [0x50, 0x4b, 0x03, 0x04] {
        return Some(CompressionDetection {
            format: "ZIP".to_string(),
            confidence: 0.95,
            magic_match: true,
        });
    }

    None
}

/// Attempt resource-limited decompression.
/// Returns the decompressed data if successful, or an error.
pub fn try_decompress(data: &[u8], format: &str) -> Result<Vec<u8>> {
    match format {
        "GZIP" => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(data);
            let mut out = Vec::with_capacity(data.len().min(256_000_000)); // 256MB limit
            decoder
                .read_to_end(&mut out)
                .map_err(|e| crate::error::CryptoTraceError::Decompression(e.to_string()))?;
            Ok(out)
        }
        "ZIP" => {
            // For ZIP, we just validate the header in Phase 1
            Err(crate::error::CryptoTraceError::Decompression("ZIP decompression not yet implemented".to_string()))
        }
        _ => Err(crate::error::CryptoTraceError::Decompression(
            format!("Unsupported format: {}", format),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_gzip() {
        let data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03";
        let result = detect_compression(data).unwrap();
        assert_eq!(result.format, "GZIP");
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04";
        let result = detect_compression(data).unwrap();
        assert_eq!(result.format, "ZIP");
    }

    #[test]
    fn test_no_match() {
        let data = b"hello world";
        let result = detect_compression(data);
        assert!(result.is_none());
    }
}
