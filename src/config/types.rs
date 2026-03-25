use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, serde::Deserialize)]
pub struct ConfigTarget {
    pub host: String,
    pub address: String,
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
}

#[derive(Debug)]
pub struct ResolvedConfig {
    pub addr: SocketAddr,
    pub targets: HashMap<String, SocketAddr>,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub log_level: String,
    pub static_dirs: HashMap<String, PathBuf>,
}

#[derive(Debug)]
pub struct RuntimeConfig {
    pub targets: HashMap<String, SocketAddr>,
    pub static_dirs: HashMap<String, PathBuf>,
}

pub type SharedConfig = std::sync::Arc<std::sync::RwLock<RuntimeConfig>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_config_new() {
        let mut targets = HashMap::new();
        targets.insert("example.com".to_string(), "127.0.0.1:8080".parse().unwrap());
        let rc = RuntimeConfig {
            targets,
            static_dirs: HashMap::new(),
        };
        assert_eq!(rc.targets.len(), 1);
        assert!(rc.static_dirs.is_empty());
    }

    #[test]
    fn test_runtime_config_from_resolved() {
        let mut targets = HashMap::new();
        targets.insert("a.com".to_string(), "1.2.3.4:80".parse().unwrap());
        let mut static_dirs = HashMap::new();
        static_dirs.insert("s.com".to_string(), PathBuf::from("/var/www"));
        let rc = RuntimeConfig { targets, static_dirs };
        assert_eq!(rc.targets.len(), 1);
        assert_eq!(rc.static_dirs.len(), 1);
    }
}
