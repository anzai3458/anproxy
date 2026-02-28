use std::net::SocketAddr;
use std::path::PathBuf;

pub mod loader;
pub mod parse;
pub mod types;

#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub address: SocketAddr,
}

#[derive(Debug)]
pub struct StaticDir {
    pub host: String,
    pub dir: PathBuf,
}
