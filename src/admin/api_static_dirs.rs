use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Error, Response, StatusCode};
use std::path::PathBuf;

use crate::admin::persist::persist_config;
use crate::admin::response::{json_err, json_ok};
use crate::config::types::SharedConfig;

fn validate_static_dir(dir: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(dir);
    if !path.is_absolute() {
        return Err("dir must be an absolute path".to_string());
    }
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Cannot access dir '{}': {}", dir, e))?;
    let canonical_str = canonical.to_string_lossy();
    if canonical_str == "/" {
        return Err("Cannot serve root directory".to_string());
    }
    for b in ["/etc", "/proc", "/sys", "/dev"] {
        if canonical_str == b || canonical_str.starts_with(&format!("{}/", b)) {
            return Err(format!(
                "Cannot serve sensitive directory '{}'",
                canonical_str
            ));
        }
    }
    Ok(canonical)
}

pub fn list_static_dirs(config: &SharedConfig) -> Response<BoxBody<Bytes, Error>> {
    let cfg = config.read().unwrap();
    let dirs: Vec<serde_json::Value> = cfg
        .static_dirs
        .iter()
        .map(|(host, dir)| serde_json::json!({"host": host, "dir": dir.to_string_lossy()}))
        .collect();
    json_ok(&dirs)
}

pub async fn add_static_dir(
    body: Bytes,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let host = match parsed.get("host").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() && !h.contains(char::is_whitespace) => h.to_string(),
        _ => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'host'"),
    };

    let dir_str = match parsed.get("dir").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'dir'"),
    };

    let dir = match validate_static_dir(dir_str) {
        Ok(d) => d,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &e),
    };

    {
        let mut cfg = config.write().unwrap();
        if cfg.static_dirs.contains_key(&host) {
            return json_err(
                StatusCode::CONFLICT,
                &format!("Static dir '{}' already exists", host),
            );
        }
        cfg.static_dirs.insert(host.clone(), dir.clone());
    }

    // Persist after releasing lock
    if let Some(path) = config_path {
        let cfg_clone = {
            let cfg = config.read().unwrap();
            crate::config::types::RuntimeConfig {
                targets: cfg.targets.clone(),
                static_dirs: cfg.static_dirs.clone(),
            }
        };
        if let Err(e) = persist_config(&cfg_clone, path).await {
            tracing::error!("Failed to persist config: {}", e);
        }
    }

    json_ok(&serde_json::json!({"host": host, "dir": dir.to_string_lossy()}))
}

pub async fn update_static_dir(
    host: &str,
    body: Bytes,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let dir_str = match parsed.get("dir").and_then(|v| v.as_str()) {
        Some(d) => d,
        None => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'dir'"),
    };

    let dir = match validate_static_dir(dir_str) {
        Ok(d) => d,
        Err(e) => return json_err(StatusCode::BAD_REQUEST, &e),
    };

    {
        let mut cfg = config.write().unwrap();
        if !cfg.static_dirs.contains_key(host) {
            return json_err(
                StatusCode::NOT_FOUND,
                &format!("Static dir '{}' not found", host),
            );
        }
        cfg.static_dirs.insert(host.to_string(), dir.clone());
    }

    if let Some(path) = config_path {
        let cfg_clone = {
            let cfg = config.read().unwrap();
            crate::config::types::RuntimeConfig {
                targets: cfg.targets.clone(),
                static_dirs: cfg.static_dirs.clone(),
            }
        };
        if let Err(e) = persist_config(&cfg_clone, path).await {
            tracing::error!("Failed to persist config: {}", e);
        }
    }

    json_ok(&serde_json::json!({"host": host, "dir": dir.to_string_lossy()}))
}

pub async fn delete_static_dir(
    host: &str,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    {
        let mut cfg = config.write().unwrap();
        if cfg.static_dirs.remove(host).is_none() {
            return json_err(
                StatusCode::NOT_FOUND,
                &format!("Static dir '{}' not found", host),
            );
        }
    }

    if let Some(path) = config_path {
        let cfg_clone = {
            let cfg = config.read().unwrap();
            crate::config::types::RuntimeConfig {
                targets: cfg.targets.clone(),
                static_dirs: cfg.static_dirs.clone(),
            }
        };
        if let Err(e) = persist_config(&cfg_clone, path).await {
            tracing::error!("Failed to persist config: {}", e);
        }
    }

    json_ok(&serde_json::json!({"deleted": host}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::RuntimeConfig;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    fn make_config() -> SharedConfig {
        Arc::new(RwLock::new(RuntimeConfig {
            targets: HashMap::new(),
            static_dirs: HashMap::new(),
        }))
    }

    #[test]
    fn test_list_static_dirs_empty() {
        let config = make_config();
        let resp = list_static_dirs(&config);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_list_static_dirs_with_entries() {
        let config = make_config();
        config
            .write()
            .unwrap()
            .static_dirs
            .insert("static.example.com".to_string(), PathBuf::from("/tmp"));
        let resp = list_static_dirs(&config);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_add_static_dir() {
        let config = make_config();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let body = Bytes::from(
            serde_json::json!({"host": "s.com", "dir": dir.to_string_lossy().as_ref()}).to_string(),
        );
        let resp = add_static_dir(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(config.read().unwrap().static_dirs.contains_key("s.com"));
    }

    #[tokio::test]
    async fn test_add_duplicate_static_dir() {
        let config = make_config();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        let body = Bytes::from(
            serde_json::json!({"host": "s.com", "dir": dir.to_string_lossy().as_ref()}).to_string(),
        );
        add_static_dir(body.clone(), &config, None).await;
        let resp = add_static_dir(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_add_static_dir_relative_path() {
        let config = make_config();
        let body = Bytes::from(r#"{"host":"s.com","dir":"relative/path"}"#);
        let resp = add_static_dir(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_static_dir() {
        let config = make_config();
        config
            .write()
            .unwrap()
            .static_dirs
            .insert("s.com".to_string(), PathBuf::from("/tmp"));
        let resp = delete_static_dir("s.com", &config, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!config.read().unwrap().static_dirs.contains_key("s.com"));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_static_dir() {
        let config = make_config();
        let resp = delete_static_dir("nope.com", &config, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
