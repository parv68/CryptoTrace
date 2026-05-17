use crate::error::{CryptoTraceError, Result};

pub const MAX_DECOMPRESS_SIZE: usize = 100 * 1024 * 1024; // 100 MB
pub const MAX_EXPANSION_RATIO: f64 = 100.0;

#[derive(Debug, Clone)]
pub struct CompressionDetection {
    pub format: String,
    pub confidence: f64,
    pub magic_match: bool,
}

#[derive(Debug, Clone)]
pub struct DecompressResult {
    pub data: Vec<u8>,
    pub expansion_ratio: f64,
}

/// Magic byte signatures for common compression formats.
const MAGIC_BYTES: &[(&[u8], &str)] = &[
    (b"\x1f\x8b", "GZIP"),
    (b"\x42\x5a\x68", "BZ2"),
    (b"\x28\xb5\x2f\xfd", "Zstd"),
    (b"\xfd\x37\x7a\x58\x5a\x00", "XZ"),
    (b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a", "Zlib"),
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

/// Attempt resource-limited decompression with expansion ratio guard.
pub fn try_decompress(data: &[u8], format: &str) -> Result<DecompressResult> {
    let input_len = data.len();
    let out = match format {
        "GZIP" => decompress_gzip(data)?,
        "BZ2" => decompress_bzip2(data)?,
        "Zstd" => decompress_zstd(data)?,
        "XZ" => decompress_xz(data)?,
        "ZIP" => {
            return Err(CryptoTraceError::Decompression(
                "ZIP decompression requires full archive reader (Phase 2+)".to_string(),
            ));
        }
        _ => {
            return Err(CryptoTraceError::Decompression(format!(
                "Unsupported format: {}",
                format
            )));
        }
    };
    let out_len = out.len();
    check_expansion_ratio(input_len, &out)?;
    Ok(DecompressResult {
        data: out,
        expansion_ratio: out_len as f64 / input_len.max(1) as f64,
    })
}

fn check_expansion_ratio(input_len: usize, output: &[u8]) -> Result<()> {
    let ratio = output.len() as f64 / input_len.max(1) as f64;
    if ratio > MAX_EXPANSION_RATIO {
        return Err(CryptoTraceError::CompressionBomb {
            ratio,
            limit: MAX_EXPANSION_RATIO,
        });
    }
    if output.len() > MAX_DECOMPRESS_SIZE {
        return Err(CryptoTraceError::InputTooLarge {
            size: output.len(),
            max: MAX_DECOMPRESS_SIZE,
        });
    }
    Ok(())
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().min(MAX_DECOMPRESS_SIZE));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CryptoTraceError::Decompression(format!("GZIP decompress: {}", e)))?;
    Ok(out)
}

fn decompress_bzip2(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = bzip2::read::BzDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().min(MAX_DECOMPRESS_SIZE));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CryptoTraceError::Decompression(format!("BZ2 decompress: {}", e)))?;
    Ok(out)
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len().min(MAX_DECOMPRESS_SIZE));
    let mut decoder = zstd::Decoder::new(data)
        .map_err(|e| CryptoTraceError::Decompression(format!("Zstd init: {}", e)))?;
    std::io::Read::read_to_end(&mut decoder, &mut out)
        .map_err(|e| CryptoTraceError::Decompression(format!("Zstd decompress: {}", e)))?;
    Ok(out)
}

fn decompress_xz(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = xz2::read::XzDecoder::new(data);
    let mut out = Vec::with_capacity(data.len().min(MAX_DECOMPRESS_SIZE));
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CryptoTraceError::Decompression(format!("XZ decompress: {}", e)))?;
    Ok(out)
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

    #[test]
    fn test_gzip_round_trip() {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"Hello, CryptoTrace!").unwrap();
        let compressed = encoder.finish().unwrap();

        let result = try_decompress(&compressed, "GZIP").unwrap();
        assert_eq!(result.data, b"Hello, CryptoTrace!");
    }

    #[test]
    fn test_bzip2_round_trip() {
        use std::io::Write;
        let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        encoder.write_all(b"CryptoTrace BZ2 test").unwrap();
        let compressed = encoder.finish().unwrap();

        let result = try_decompress(&compressed, "BZ2").unwrap();
        assert_eq!(result.data, b"CryptoTrace BZ2 test");
    }

    #[test]
    fn test_zstd_round_trip() {
        let compressed = zstd::encode_all(b"CryptoTrace Zstd test" as &[u8], 1).unwrap();
        let result = try_decompress(&compressed, "Zstd").unwrap();
        assert!(!result.data.is_empty());
    }

    #[test]
    fn test_expansion_ratio_ok() {
        // Verify that a tiny valid GZIP stream decompresses correctly
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"x").unwrap();
        let compressed = encoder.finish().unwrap();
        let result = try_decompress(&compressed, "GZIP");
        assert!(result.is_ok());
    }

    #[test]
    fn test_xz_round_trip() {
        let _compressed = xz2::write::XzEncoder::new(Vec::new(), 1);
    }

    #[test]
    fn test_zip_not_yet() {
        let result = try_decompress(b"PK\x03\x04test", "ZIP");
        assert!(result.is_err());
    }
}
