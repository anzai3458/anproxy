use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use crate::config::{StaticDir, Target};

pub fn parse_socket_addr(addr: &str) -> Result<SocketAddr, String> {
    addr.to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| "".to_string())
}

pub fn parse_host_mapping(value: &str) -> Result<Target, String> {
    if let Some((host, addr)) = value.split_once("@") {
        let addr = addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| format!("Invalid address {}", value))?;
        return Ok(Target {
            host: host.to_string(),
            address: addr,
        });
    }
    Err(format!(
        "Invalid target format, expected '{{host}}@{{addr}}', got '{}'",
        value
    ))
}

pub fn parse_static_mapping(value: &str) -> Result<StaticDir, String> {
    if let Some((host, dir)) = value.split_once("@") {
        return Ok(StaticDir {
            host: host.to_string(),
            dir: PathBuf::from(dir),
        });
    }
    Err(format!(
        "Invalid static dir format, expected '{{host}}@{{path}}', got '{}'",
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
    fn test_parse_socket_addr_invalid_port() {
        assert!(parse_socket_addr("127.0.0.1:notaport").is_err());
    }

    #[test]
    fn test_parse_host_mapping_valid() {
        let result = parse_host_mapping("example.com@127.0.0.1:8080");
        assert!(result.is_ok());
        let target = result.unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.address.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_host_mapping_no_at_separator() {
        assert!(parse_host_mapping("example.com:127.0.0.1:8080").is_err());
    }

    #[test]
    fn test_parse_host_mapping_invalid_addr() {
        assert!(parse_host_mapping("example.com@not-an-addr:notaport").is_err());
    }

    #[test]
    fn test_parse_host_mapping_empty_host() {
        // "@127.0.0.1:8080" — host is empty string, addr is valid
        let result = parse_host_mapping("@127.0.0.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().host, "");
    }

    #[test]
    fn test_parse_static_mapping_valid_relative() {
        let result = parse_static_mapping("static.example.com@./www/html");
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.host, "static.example.com");
        assert_eq!(s.dir, PathBuf::from("./www/html"));
    }

    #[test]
    fn test_parse_static_mapping_valid_absolute() {
        let result = parse_static_mapping("example.com@/var/www/html");
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.host, "example.com");
        assert_eq!(s.dir, PathBuf::from("/var/www/html"));
    }

    #[test]
    fn test_parse_static_mapping_no_at_separator() {
        assert!(parse_static_mapping("example.com:/var/www").is_err());
    }
}
