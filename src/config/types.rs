use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::config::TargetBackend;

#[derive(Debug, serde::Deserialize)]
pub struct ConfigTarget {
    pub host: String,
    #[serde(alias = "address")]
    pub backend: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ConfigStaticDir {
    pub host: String,
    pub dir: String,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Config {
    pub addr: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub targets: Vec<ConfigTarget>,
    pub static_dirs: Vec<ConfigStaticDir>,
    pub log_level: Option<String>,
    pub admin_addr: Option<String>,
    pub admin_user: Option<String>,
    pub admin_pass: Option<String>,
    pub no_tls: Option<bool>,
}

#[derive(Debug)]
pub struct ResolvedConfig {
    pub addr: SocketAddr,
    pub targets: HashMap<String, TargetBackend>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub log_level: String,
    pub admin_addr: Option<SocketAddr>,
    pub admin_user: Option<String>,
    pub admin_pass: Option<String>,
    pub config_file: Option<PathBuf>,
    pub no_tls: bool,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub targets: HashMap<String, TargetBackend>,
}

pub type SharedConfig = std::sync::Arc<std::sync::RwLock<RuntimeConfig>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_config_new() {
        let mut targets = HashMap::new();
        targets.insert(
            "example.com".to_string(),
            TargetBackend::Http("127.0.0.1:8080".parse().unwrap()),
        );
        let rc = RuntimeConfig { targets };
        assert_eq!(rc.targets.len(), 1);
    }

    #[test]
    fn test_runtime_config_mixed() {
        let mut targets = HashMap::new();
        targets.insert(
            "a.com".to_string(),
            TargetBackend::Http("1.2.3.4:80".parse().unwrap()),
        );
        targets.insert(
            "s.com".to_string(),
            TargetBackend::File(std::path::PathBuf::from("/var/www")),
        );
        let rc = RuntimeConfig { targets };
        assert_eq!(rc.targets.len(), 2);
    }
}
