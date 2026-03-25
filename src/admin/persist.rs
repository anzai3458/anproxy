use std::path::Path;

use crate::config::types::RuntimeConfig;

/// Read-modify-write: loads existing config file, updates targets/static_dirs,
/// preserves all other fields, and atomically writes to disk.
pub async fn persist_config(
    config: &RuntimeConfig,
    config_path: &Path,
) -> Result<(), String> {
    // Read existing file to preserve non-routing fields
    let existing = tokio::fs::read_to_string(config_path)
        .await
        .unwrap_or_default();
    let mut doc: toml::Table = existing.parse::<toml::Table>().unwrap_or_default();

    // Update targets
    let targets: Vec<toml::Value> = config
        .targets
        .iter()
        .map(|(host, addr)| {
            let mut t = toml::Table::new();
            t.insert("host".into(), toml::Value::String(host.clone()));
            t.insert("address".into(), toml::Value::String(addr.to_string()));
            toml::Value::Table(t)
        })
        .collect();
    doc.insert("targets".into(), toml::Value::Array(targets));

    // Update static_dirs
    let static_dirs: Vec<toml::Value> = config
        .static_dirs
        .iter()
        .map(|(host, dir)| {
            let mut t = toml::Table::new();
            t.insert("host".into(), toml::Value::String(host.clone()));
            t.insert("dir".into(), toml::Value::String(dir.display().to_string()));
            toml::Value::Table(t)
        })
        .collect();
    doc.insert("static_dirs".into(), toml::Value::Array(static_dirs));

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
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_persist_config_writes_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut targets = HashMap::new();
        targets.insert(
            "a.com".to_string(),
            "1.2.3.4:80".parse::<SocketAddr>().unwrap(),
        );
        let config = RuntimeConfig {
            targets,
            static_dirs: HashMap::new(),
        };
        persist_config(&config, &path).await.unwrap();
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(contents.contains("a.com"));
        assert!(contents.contains("1.2.3.4:80"));
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
address = "1.1.1.1:80"
"#,
        )
        .await
        .unwrap();

        let mut targets = HashMap::new();
        targets.insert(
            "new.com".to_string(),
            "2.2.2.2:80".parse::<SocketAddr>().unwrap(),
        );
        let config = RuntimeConfig {
            targets,
            static_dirs: HashMap::new(),
        };
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
