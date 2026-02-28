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
