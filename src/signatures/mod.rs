use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignatureRegistry {
    pub version: String,
    pub signatures: Vec<MagicEntry>,
}

#[derive(Debug, Deserialize)]
pub struct MagicEntry {
    pub id: String,
    pub name: String,
    pub magic_bytes: String,
    pub offset: usize,
    pub category: String,
    pub risk_level: String,
    pub notes: Option<String>,
    #[serde(default)]
    pub subtypes: Vec<SubtypeEntry>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

#[derive(Debug, Deserialize)]
pub struct SubtypeEntry {
    pub id: String,
    pub name: String,
    pub detect: String,
}

#[derive(Debug, Deserialize)]
pub struct Provenance {
    pub contributor: Option<String>,
    pub review_status: Option<String>,
    pub review_date: Option<String>,
    pub reviewer: Option<String>,
    pub origin_reference: Option<String>,
}

/// Load magic byte registry from a YAML file.
/// Phase 1 uses a built-in minimal registry. Phase 2 adds file loading + GPG verification.
pub fn load_registry(path: &str) -> Result<SignatureRegistry, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read signature registry '{}': {}", path, e))?;
    serde_yaml::from_str(&content)
        .map_err(|e| format!("Cannot parse signature registry: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_not_loaded_by_default() {
        // Phase 1: no external registry file required
        // Just verify the types compile
        let _entry = MagicEntry {
            id: "gzip".to_string(),
            name: "GZIP Compressed".to_string(),
            magic_bytes: "1F8B".to_string(),
            offset: 0,
            category: "compression".to_string(),
            risk_level: "LOW".to_string(),
            notes: None,
            subtypes: vec![],
            provenance: None,
        };
    }
}
