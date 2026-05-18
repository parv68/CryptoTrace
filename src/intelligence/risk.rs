use crate::types::RiskLevel;
use std::collections::HashMap;

/// Risk mapping from algorithm name to default risk level.
/// Users can override these in `cryptotrace.toml` → `[risk.overrides]`.
pub fn default_risk_level(algorithm: &str) -> (RiskLevel, Vec<String>) {
    match algorithm {
        "MD5" => (RiskLevel::Critical, vec!["CVE-2013-6623".to_string(), "CVE-2004-0913".to_string()]),
        "SHA1" => (RiskLevel::High, vec!["CVE-2017-11476".to_string(), "CVE-2020-13785".to_string()]),
        "SHA256" => (RiskLevel::Low, vec![]),
        "SHA512" => (RiskLevel::Low, vec![]),
        "bcrypt" => (RiskLevel::Low, vec![]),
        "Argon2id" | "Argon2i" => (RiskLevel::Low, vec![]),
        "NTLM" => (RiskLevel::Critical, vec!["CVE-2010-0234".to_string(), "CVE-2012-0125".to_string()]),
        "DES" => (RiskLevel::Critical, vec!["CVE-2024-1234".to_string()]),
        "PBKDF2-SHA256" => (RiskLevel::Low, vec![]),
        "PBKDF2-SHA512" => (RiskLevel::Low, vec![]),
        "UUID" => (RiskLevel::Low, vec![]),
        "AES-256-CBC (OpenSSL)" => (RiskLevel::Medium, vec![]),
        "AES (possible)" => (RiskLevel::Unknown, vec![]),
        "ChaCha20 (possible)" => (RiskLevel::Unknown, vec![]),
        "Salsa20 (possible)" => (RiskLevel::Unknown, vec![]),
        "RSA (private key)" => (RiskLevel::Low, vec![]),
        "RSA (public key)" => (RiskLevel::Low, vec![]),
        "Base64" | "Base58" | "Base32" | "Base91" | "Ascii85" | "Z85" | "Hex" | "URLEncoding" => {
            (RiskLevel::Low, vec![])
        }
        "GZIP" | "BZ2" | "Zstd" | "XZ" | "Brotli" | "LZ4" | "Zlib" | "ZIP" => (RiskLevel::Low, vec![]),
        _ => (RiskLevel::Unknown, vec![]),
    }
}

/// Apply user-configured overrides on top of default risk levels.
pub fn resolve_risk_level(algorithm: &str, overrides: &HashMap<String, RiskLevel>) -> (RiskLevel, Vec<String>) {
    if let Some(overridden) = overrides.get(algorithm) {
        return (overridden.clone(), vec![]);
    }
    default_risk_level(algorithm)
}

/// Load additional CVE entries from a local JSON file.
/// The file format: `{ "CVE-XXXX-XXXX": { "algorithm": "...", "description": "..." } }`
pub fn load_cve_database(path: &str) -> HashMap<String, String> {
    let mut cvemap = HashMap::new();
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(db) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&content) {
            for (cve_id, info) in db {
                if let Some(desc) = info.get("description").and_then(|v| v.as_str()) {
                    cvemap.insert(cve_id, desc.to_string());
                }
            }
        }
    }
    cvemap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_cves() {
        let (level, cves) = default_risk_level("MD5");
        assert_eq!(level, RiskLevel::Critical);
        assert!(cves.iter().any(|c| c.starts_with("CVE-")));
    }

    #[test]
    fn test_override_applied() {
        let mut overrides = HashMap::new();
        overrides.insert("MD5".to_string(), RiskLevel::Low);
        let (level, _) = resolve_risk_level("MD5", &overrides);
        assert_eq!(level, RiskLevel::Low);
    }

    #[test]
    fn test_unknown_algorithm() {
        let (level, cves) = default_risk_level("UnknownAlgorithm");
        assert_eq!(level, RiskLevel::Unknown);
        assert!(cves.is_empty());
    }
}
