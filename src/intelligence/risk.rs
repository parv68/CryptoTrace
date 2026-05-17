use crate::types::RiskLevel;
use std::collections::HashMap;

/// Risk mapping from algorithm name to default risk level.
/// Users can override these in `cryptotrace.toml` → `[risk.overrides]`.
pub fn default_risk_level(algorithm: &str) -> (RiskLevel, Vec<String>) {
    match algorithm {
        "MD5" => (RiskLevel::Critical, vec!["CVE-2013-6623".to_string()]),
        "SHA1" => (RiskLevel::High, vec!["CVE-2017-11476".to_string()]),
        "SHA256" => (RiskLevel::Low, vec![]),
        "SHA512" => (RiskLevel::Low, vec![]),
        "bcrypt" => (RiskLevel::Low, vec![]),
        "Argon2id" | "Argon2i" => (RiskLevel::Low, vec![]),
        "NTLM" => (RiskLevel::Critical, vec![]),
        "DES" => (RiskLevel::Critical, vec![]),
        "AES-256-CBC (OpenSSL)" => (RiskLevel::Medium, vec![]),
        "AES (possible)" => (RiskLevel::Unknown, vec![]),
        "ChaCha20 (possible)" => (RiskLevel::Unknown, vec![]),
        "RSA (private key)" => (RiskLevel::Low, vec![]),
        "RSA (public key)" => (RiskLevel::Low, vec![]),
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
