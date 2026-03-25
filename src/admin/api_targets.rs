use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Error, Response, StatusCode};
use std::path::PathBuf;

use crate::admin::persist::persist_config;
use crate::admin::response::{json_err, json_ok};
use crate::config::types::SharedConfig;

pub fn list_targets(config: &SharedConfig) -> Response<BoxBody<Bytes, Error>> {
    let cfg = config.read().unwrap();
    let targets: Vec<serde_json::Value> = cfg
        .targets
        .iter()
        .map(|(host, addr)| serde_json::json!({"host": host, "address": addr.to_string()}))
        .collect();
    json_ok(&targets)
}

pub async fn add_target(
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

    let address = match parsed
        .get("address")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(a) => a,
        None => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'address' (expected ip:port)"),
    };

    {
        let mut cfg = config.write().unwrap();
        if cfg.targets.contains_key(&host) {
            return json_err(StatusCode::CONFLICT, &format!("Target '{}' already exists", host));
        }
        cfg.targets.insert(host.clone(), address);
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

    json_ok(&serde_json::json!({"host": host, "address": address.to_string()}))
}

pub async fn update_target(
    host: &str,
    body: Bytes,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let address = match parsed
        .get("address")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(a) => a,
        None => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'address'"),
    };

    {
        let mut cfg = config.write().unwrap();
        if !cfg.targets.contains_key(host) {
            return json_err(StatusCode::NOT_FOUND, &format!("Target '{}' not found", host));
        }
        cfg.targets.insert(host.to_string(), address);
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

    json_ok(&serde_json::json!({"host": host, "address": address.to_string()}))
}

pub async fn delete_target(
    host: &str,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    {
        let mut cfg = config.write().unwrap();
        if cfg.targets.remove(host).is_none() {
            return json_err(StatusCode::NOT_FOUND, &format!("Target '{}' not found", host));
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
    use std::sync::{Arc, RwLock};
    use crate::config::types::RuntimeConfig;
    use std::collections::HashMap;

    fn make_config() -> SharedConfig {
        Arc::new(RwLock::new(RuntimeConfig {
            targets: HashMap::new(),
            static_dirs: HashMap::new(),
        }))
    }

    #[test]
    fn test_list_targets_empty() {
        let config = make_config();
        let resp = list_targets(&config);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_list_targets_with_entries() {
        let config = make_config();
        config.write().unwrap().targets.insert(
            "example.com".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
        );
        let resp = list_targets(&config);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_add_target() {
        let config = make_config();
        let body = Bytes::from(r#"{"host":"a.com","address":"1.2.3.4:80"}"#);
        let resp = add_target(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(config.read().unwrap().targets.contains_key("a.com"));
    }

    #[tokio::test]
    async fn test_add_duplicate_target() {
        let config = make_config();
        let body = Bytes::from(r#"{"host":"a.com","address":"1.2.3.4:80"}"#);
        add_target(body.clone(), &config, None).await;
        let resp = add_target(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_add_target_invalid_json() {
        let config = make_config();
        let body = Bytes::from("not json");
        let resp = add_target(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_target() {
        let config = make_config();
        config.write().unwrap().targets.insert(
            "a.com".to_string(),
            "1.2.3.4:80".parse().unwrap(),
        );
        let resp = delete_target("a.com", &config, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!config.read().unwrap().targets.contains_key("a.com"));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_target() {
        let config = make_config();
        let resp = delete_target("nope.com", &config, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
