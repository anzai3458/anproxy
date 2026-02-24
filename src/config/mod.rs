use std::net::SocketAddr;

pub mod loader;
pub mod parse;
pub mod types;

#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub address: SocketAddr,
}
