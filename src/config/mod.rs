use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

pub mod loader;
pub mod parse;
pub mod types;

#[derive(Debug, Clone, PartialEq)]
pub enum TargetBackend {
    Http(SocketAddr),
    File(PathBuf),
}

impl fmt::Display for TargetBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetBackend::Http(addr) => write!(f, "http://{}", addr),
            TargetBackend::File(path) => write!(f, "file://{}", path.display()),
        }
    }
}

#[derive(Debug)]
pub struct Target {
    pub host: String,
    pub backend: TargetBackend,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_backend_display_http() {
        let b = TargetBackend::Http("127.0.0.1:8080".parse().unwrap());
        assert_eq!(b.to_string(), "http://127.0.0.1:8080");
    }

    #[test]
    fn test_target_backend_display_file() {
        let b = TargetBackend::File(PathBuf::from("/var/www/html"));
        assert_eq!(b.to_string(), "file:///var/www/html");
    }
}
