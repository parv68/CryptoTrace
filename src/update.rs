use crate::error::{CryptoTraceError, Result};
use std::path::{Path, PathBuf};

/// Manages signature database updates, rollback, and air-gap import.
pub struct UpdateManager {
    registry_path: PathBuf,
    backup_path: PathBuf,
}

impl UpdateManager {
    /// Filename of the signature registry within the registry directory.
    pub const REGISTRY_FILE: &'static str = "default.yaml";

    /// Create a new UpdateManager for the given registry path.
    pub fn new(registry_dir: &Path) -> Self {
        let registry_path = registry_dir.join(Self::REGISTRY_FILE);
        let backup_path = registry_dir.join("backup.yaml");
        Self {
            registry_path,
            backup_path,
        }
    }

    /// Check for available updates (Phase 4: HTTP fetch).
    /// Phase 2: returns current version info.
    pub fn check_for_updates(&self) -> Result<String> {
        let content = std::fs::read_to_string(&self.registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot read registry: {}", e)))?;
        let parsed: serde_yaml::Value = serde_yaml::from_str(&content)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot parse registry: {}", e)))?;
        let version = parsed
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        Ok(version)
    }

    /// Apply a signature update from a file.
    /// Creates a backup of the current registry first.
    pub fn apply_update(&self, new_registry_path: &Path) -> Result<()> {
        // Backup current registry
        if self.registry_path.exists() {
            std::fs::copy(&self.registry_path, &self.backup_path)
                .map_err(|e| CryptoTraceError::Other(format!("Cannot create backup: {}", e)))?;
        }

        // Ensure parent directory exists
        if let Some(parent) = self.registry_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CryptoTraceError::Other(format!("Cannot create registry dir: {}", e)))?;
        }

        // Validate the new registry file
        let content = std::fs::read_to_string(new_registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot read new registry: {}", e)))?;
        let registry: crate::signatures::SignatureRegistry = serde_yaml::from_str(&content)
            .map_err(|e| CryptoTraceError::Other(format!("Invalid registry format: {}", e)))?;

        if registry.signatures.is_empty() {
            return Err(CryptoTraceError::Other(
                "Refusing to apply empty signature registry".to_string(),
            ));
        }

        // Copy new registry into place
        std::fs::copy(new_registry_path, &self.registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot install new registry: {}", e)))?;

        tracing::info!(
            "Signature database updated to version {} ({} entries)",
            registry.version,
            registry.signatures.len()
        );

        Ok(())
    }

    /// Roll back to the previous signature database version.
    pub fn rollback(&self) -> Result<()> {
        if !self.backup_path.exists() {
            return Err(CryptoTraceError::Other(
                "No backup available for rollback".to_string(),
            ));
        }

        std::fs::copy(&self.backup_path, &self.registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot restore backup: {}", e)))?;

        tracing::info!("Signature database rolled back to previous version");
        Ok(())
    }

    /// Import a signature update from a local file (air-gap mode).
    pub fn import_local(&self, path: &Path) -> Result<()> {
        self.apply_update(path)
    }

    /// Return the current signature database version string.
    pub fn current_version(&self) -> String {
        if !self.registry_path.exists() {
            return "0.0.0".to_string();
        }
        match std::fs::read_to_string(&self.registry_path) {
            Ok(content) => {
                let parsed: std::result::Result<serde_yaml::Value, _> =
                    serde_yaml::from_str(&content);
                match parsed {
                    Ok(v) => v
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0")
                        .to_string(),
                    Err(_) => "0.0.0".to_string(),
                }
            }
            Err(_) => "0.0.0".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_current_version_default() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());
        assert_eq!(mgr.current_version(), "0.0.0");
    }

    #[test]
    fn test_check_updates_after_install() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        // Create a minimal valid registry
        let registry_content = r#"
version: "1.0.0"
signatures:
  - id: test
    name: Test Entry
    magic_bytes: "00"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let reg_path = dir.path().join("default.yaml");
        std::fs::write(&reg_path, registry_content).unwrap();

        let version = mgr.check_for_updates().unwrap();
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_apply_update_and_rollback() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        // Create first registry (no backup yet — nothing to back up)
        let first = r#"
version: "1.0.0"
signatures:
  - id: a
    name: A
    magic_bytes: "00"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let path_a = dir.path().join("reg_a.yaml");
        std::fs::write(&path_a, first).unwrap();
        mgr.apply_update(&path_a).unwrap();
        assert_eq!(mgr.current_version(), "1.0.0");

        // Create second registry
        let second = r#"
version: "2.0.0"
signatures:
  - id: b
    name: B
    magic_bytes: "01"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let path_b = dir.path().join("reg_b.yaml");
        std::fs::write(&path_b, second).unwrap();
        mgr.apply_update(&path_b).unwrap();
        assert_eq!(mgr.current_version(), "2.0.0");
        // Backup should now exist (second update backs up the first registry)
        assert!(mgr.backup_path.exists());

        // Rollback
        mgr.rollback().unwrap();
        assert_eq!(mgr.current_version(), "1.0.0");
    }

    #[test]
    fn test_reject_empty_registry() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        let empty = r#"
version: "1.0.0"
signatures: []
"#;
        let path = dir.path().join("empty.yaml");
        std::fs::write(&path, empty).unwrap();
        assert!(mgr.apply_update(&path).is_err());
    }
}
