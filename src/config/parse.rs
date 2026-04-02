use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use crate::config::{Target, TargetBackend};

pub fn parse_socket_addr(addr: &str) -> Result<SocketAddr, String> {
    addr.to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| "".to_string())
}

fn parse_http_backend(value: &str) -> Result<TargetBackend, String> {
    // value is like "http://127.0.0.1:8080" - strip the http:// prefix
    let addr_part = value.strip_prefix("http://").unwrap_or(value);
    let addr = addr_part
        .to_socket_addrs()
        .map_err(|e| format!("Invalid http address '{}': {}", value, e))?
        .next()
        .ok_or_else(|| format!("Invalid http address '{}'", value))?;
    Ok(TargetBackend::Http(addr))
}

fn parse_file_backend(value: &str) -> Result<TargetBackend, String> {
    // value is like "file:///var/www/html" or "file:///C:/path" on Windows
    let path_part = value.strip_prefix("file://").unwrap_or(value);
    // Handle absolute paths - on Unix this starts with /, on Windows it might start with drive letter
    let path = PathBuf::from(path_part);
    if !path.is_absolute() {
        return Err(format!(
            "file:// path must be absolute, got '{}'",
            path.display()
        ));
    }
    Ok(TargetBackend::File(path))
}

pub fn parse_backend(value: &str) -> Result<TargetBackend, String> {
    if value.starts_with("http://") {
        parse_http_backend(value)
    } else if value.starts_with("file://") {
        parse_file_backend(value)
    } else {
        Err(format!(
            "Invalid backend '{}'. Expected http://ip:port or file:///path",
            value
        ))
    }
}

pub fn parse_host_mapping(value: &str) -> Result<Target, String> {
    if let Some((host, backend_str)) = value.split_once("@") {
        let backend = parse_backend(backend_str)?;
        return Ok(Target {
            host: host.to_string(),
            backend,
        });
    }
    Err(format!(
        "Invalid target format, expected '{{host}}@{{backend}}', got '{}'",
        value
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socket_addr_valid_ipv4() {
        let result = parse_socket_addr("127.0.0.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_socket_addr_valid_ipv6() {
        let result = parse_socket_addr("[::1]:9000");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_socket_addr_invalid_no_port() {
        assert!(parse_socket_addr("127.0.0.1").is_err());
    }

    #[test]
    fn test_parse_backend_http() {
        let b = parse_backend("http://127.0.0.1:8080").unwrap();
        match b {
            TargetBackend::Http(addr) => assert_eq!(addr.to_string(), "127.0.0.1:8080"),
            _ => panic!("Expected Http"),
        }
    }

    #[test]
    fn test_parse_backend_file() {
        let b = parse_backend("file:///var/www/html").unwrap();
        match b {
            TargetBackend::File(path) => assert_eq!(path.to_string_lossy(), "/var/www/html"),
            _ => panic!("Expected File"),
        }
    }

    #[test]
    fn test_parse_backend_bare_address_rejected() {
        // Bare addresses (without http://) should be rejected
        let result = parse_backend("127.0.0.1:8080");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected http://ip:port or file:///path"));
    }

    #[test]
    fn test_parse_host_mapping_http() {
        let t = parse_host_mapping("example.com@http://127.0.0.1:8080").unwrap();
        assert_eq!(t.host, "example.com");
        match t.backend {
            TargetBackend::Http(addr) => assert_eq!(addr.to_string(), "127.0.0.1:8080"),
            _ => panic!("Expected Http"),
        }
    }

    #[test]
    fn test_parse_host_mapping_file() {
        let t = parse_host_mapping("static.example.com@file:///var/www/html").unwrap();
        assert_eq!(t.host, "static.example.com");
        match t.backend {
            TargetBackend::File(path) => assert_eq!(path.to_string_lossy(), "/var/www/html"),
            _ => panic!("Expected File"),
        }
    }

    #[test]
    fn test_parse_host_mapping_no_at_separator() {
        assert!(parse_host_mapping("example.com:127.0.0.1:8080").is_err());
    }

    #[test]
    fn test_parse_host_mapping_empty_host() {
        // "@http://127.0.0.1:8080" — host is empty string, backend is valid
        let result = parse_host_mapping("@http://127.0.0.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().host, "");
    }
}
