use std::net::{SocketAddr, ToSocketAddrs};

use crate::config::Target;

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
}
