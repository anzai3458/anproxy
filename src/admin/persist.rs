use std::path::Path;

use crate::config::types::RuntimeConfig;

/// Read-modify-write: loads existing config file, updates targets,
/// preserves all other fields, and atomically writes to disk.
pub async fn persist_config(
    config: &RuntimeConfig,
    config_path: &Path,
) -> Result<(), String> {
    // Read existing file to preserve non-routing fields
    let existing = tokio::fs::read_to_string(config_path)
        .await
        .unwrap_or_default();
    let mut doc: toml::Table = existing.parse::<>().unwrap_or_default();

    // Update targets
    let targets: Vec<toml::Value> = config
        .targets
        .iter()
        .map(|(host, backend)| {
            let mut t = toml::Table::new();
            t.insert("host".into(), toml::Value::String(host.clone()));
            t.insert("backend".into(), toml::Value::String(backend.to_string()));
            toml::Value::Table(t)
        })
        .collect();
    doc.insert("targets".into(), toml::Value::Array(targets));

    // Note: static_dirs section is no longer written (unified into targets)
    // Keep old static_dirs in file for backwards compatibility if present,
    // but we're not updating it anymore.

    let toml_str = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    // Atomic write: write to temp file then rename
    let tmp_path = config_path.with_extension("toml.tmp");
    tokio::fs::write(&tmp_path, toml_str.as_bytes())
        .await
        .map_err(|e| format!("Failed to write temp config: {}", e))?;
    tokio::fs::rename(&tmp_path, config_path)
        .await
        .map_err(|e| format!("Failed to rename config: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::config::TargetBackend;

    #[tokio::test]
    async fn test_persist_config_writes_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut targets = HashMap::new();
        targets.insert(
            "a.com".to_string(),
            TargetBackend::Http("1.2.3.4:80".parse().unwrap()),
        );
        targets.insert(
            "static.com".to_string(),
            TargetBackend::File(std::path::PathBuf::from("/var/www")),
        );
        let config = RuntimeConfig { targets };
        persist_config(&config, &path).await.unwrap();
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(contents.contains("a.com"));
        assert!(contents.contains("http://1.2.3.4:80"));
        assert!(contents.contains("static.com"));
        assert!(contents.contains("file:///var/www"));
    }

    #[tokio::test]
    async fn test_persist_preserves_existing_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        // Write initial config with non-routing fields
        tokio::fs::write(
            &path,
            r#"addr = "0.0.0.0:8443"
cert = "/path/cert.pem"
key = "/path/key.pem"

[[targets]]
host = "old.com"
backend = "http://1.1.1.1:80"
"#,
        )
        .await
        .unwrap();

        let mut targets = HashMap::new();
        targets.insert(
            "new.com".to_string(),
            TargetBackend::Http("2.2.2.2:80".parse().unwrap()),
        );
        let config = RuntimeConfig { targets };
        persist_config(&config, &path).await.unwrap();
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        // Routing changed
        assert!(contents.contains("new.com"));
        assert!(!contents.contains("old.com"));
        // Non-routing preserved
        assert!(contents.contains("0.0.0.0:8443"));
        assert!(contents.contains("/path/cert.pem"));
    }
}
