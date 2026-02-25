use std::error::Error as StdError;
use std::fs;
use std::path::PathBuf;

use crate::cli::Options;
use crate::config::parse::parse_socket_addr;
use crate::config::types::{Config, ResolvedConfig};
use crate::config::Target;

pub fn load_config_file(path: &PathBuf) -> Result<Config, Box<dyn StdError + Send + Sync>> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read config file {}: {}", path.display(), e))?;
    toml::from_str(&contents)
        .map_err(|e| format!("Invalid TOML in {}: {}", path.display(), e).into())
}

pub fn merge(opts: Options) -> Result<ResolvedConfig, Box<dyn StdError + Send + Sync>> {
    let file_cfg = match &opts.config_file {
        Some(p) => load_config_file(p)?,
        None => Config::default(),
    };

    let addr_str = opts
        .addr
        .or(file_cfg.addr)
        .ok_or("addr is required (positional arg or config file 'addr')")?;
    let addr = parse_socket_addr(&addr_str)
        .map_err(|e| format!("Invalid addr '{}': {}", addr_str, e))?;

    let cert = opts
        .cert
        .or_else(|| file_cfg.cert.map(PathBuf::from))
        .ok_or("cert is required (-c or config file 'cert')")?;

    let key = opts
        .key
        .or_else(|| file_cfg.key.map(PathBuf::from))
        .ok_or("key is required (-k or config file 'key')")?;

    let raw_targets: Vec<Target> = if !opts.targets.is_empty() {
        opts.targets
    } else {
        file_cfg
            .targets
            .into_iter()
            .map(|ct| {
                let a = parse_socket_addr(&ct.address).map_err(|e| {
                    format!(
                        "Invalid address '{}' for host '{}': {}",
                        ct.address, ct.host, e
                    )
                })?;
                Ok(Target {
                    host: ct.host,
                    address: a,
                })
            })
            .collect::<Result<Vec<_>, String>>()?
    };

    let targets = raw_targets.into_iter().map(|t| (t.host, t.address)).collect();

    let log_level = opts
        .log_level
        .or(file_cfg.log_level)
        .unwrap_or_else(|| "info".to_string());

    Ok(ResolvedConfig {
        addr,
        targets,
        cert,
        key,
        log_level,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse::parse_host_mapping;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml_config(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn make_opts(
        addr: Option<&str>,
        targets: Vec<Target>,
        cert: Option<&str>,
        key: Option<&str>,
        config_file: Option<PathBuf>,
    ) -> Options {
        Options {
            addr: addr.map(str::to_string),
            targets,
            cert: cert.map(PathBuf::from),
            key: key.map(PathBuf::from),
            config_file,
            log_level: None,
        }
    }

    // ── load_config_file ──────────────────────────────────────────────────

    #[test]
    fn test_load_config_file_all_fields() {
        let toml = r#"
addr = "0.0.0.0:8443"
cert = "/etc/anproxy/cert.pem"
key  = "/etc/anproxy/key.pem"

[[targets]]
host    = "example.com"
address = "127.0.0.1:8080"

[[targets]]
host    = "api.example.com"
address = "127.0.0.1:9090"
"#;
        let f = write_toml_config(toml);
        let cfg = load_config_file(&f.path().to_path_buf()).unwrap();
        assert_eq!(cfg.addr.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(cfg.cert.as_deref(), Some("/etc/anproxy/cert.pem"));
        assert_eq!(cfg.key.as_deref(), Some("/etc/anproxy/key.pem"));
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.targets[0].host, "example.com");
        assert_eq!(cfg.targets[0].address, "127.0.0.1:8080");
        assert_eq!(cfg.targets[1].host, "api.example.com");
        assert_eq!(cfg.targets[1].address, "127.0.0.1:9090");
    }

    #[test]
    fn test_load_config_file_partial() {
        let toml = r#"
cert = "/etc/anproxy/cert.pem"
key  = "/etc/anproxy/key.pem"
"#;
        let f = write_toml_config(toml);
        let cfg = load_config_file(&f.path().to_path_buf()).unwrap();
        assert!(cfg.addr.is_none());
        assert_eq!(cfg.cert.as_deref(), Some("/etc/anproxy/cert.pem"));
        assert_eq!(cfg.key.as_deref(), Some("/etc/anproxy/key.pem"));
        assert!(cfg.targets.is_empty());
    }

    #[test]
    fn test_load_config_file_empty() {
        let f = write_toml_config("");
        let cfg = load_config_file(&f.path().to_path_buf()).unwrap();
        assert!(cfg.addr.is_none());
        assert!(cfg.cert.is_none());
        assert!(cfg.key.is_none());
        assert!(cfg.targets.is_empty());
    }

    #[test]
    fn test_load_config_file_not_found() {
        let path = PathBuf::from("/nonexistent/anproxy.toml");
        let err = load_config_file(&path).unwrap_err();
        assert!(err.to_string().contains("Cannot read"));
    }

    #[test]
    fn test_load_config_file_invalid_toml() {
        let f = write_toml_config("addr = ][[ bad toml");
        let err = load_config_file(&f.path().to_path_buf()).unwrap_err();
        assert!(err.to_string().contains("Invalid TOML"));
    }

    // ── merge ─────────────────────────────────────────────────────────────

    #[test]
    fn test_merge_cli_only() {
        let opts = make_opts(
            Some("127.0.0.1:8443"),
            vec![parse_host_mapping("example.com@127.0.0.1:8080").unwrap()],
            Some("/tmp/cert.pem"),
            Some("/tmp/key.pem"),
            None,
        );
        let r = merge(opts).unwrap();
        assert_eq!(r.addr.to_string(), "127.0.0.1:8443");
        assert_eq!(r.cert, PathBuf::from("/tmp/cert.pem"));
        assert_eq!(r.key, PathBuf::from("/tmp/key.pem"));
        assert_eq!(r.targets.len(), 1);
        assert!(r.targets.contains_key("example.com"));
    }

    #[test]
    fn test_merge_config_file_only() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "cfg.example.com"
address = "127.0.0.1:7070"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let r = merge(opts).unwrap();
        assert_eq!(r.addr.to_string(), "0.0.0.0:9000");
        assert_eq!(r.cert, PathBuf::from("/cfg/cert.pem"));
        assert_eq!(r.key, PathBuf::from("/cfg/key.pem"));
        assert_eq!(r.targets.len(), 1);
        assert!(r.targets.contains_key("cfg.example.com"));
    }

    #[test]
    fn test_merge_cli_addr_overrides_config() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(
            Some("127.0.0.1:8443"),
            vec![],
            None,
            None,
            Some(f.path().to_path_buf()),
        );
        let r = merge(opts).unwrap();
        assert_eq!(r.addr.to_string(), "127.0.0.1:8443");
    }

    #[test]
    fn test_merge_cli_cert_key_override() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(
            None,
            vec![],
            Some("/cli/cert.pem"),
            Some("/cli/key.pem"),
            Some(f.path().to_path_buf()),
        );
        let r = merge(opts).unwrap();
        assert_eq!(r.cert, PathBuf::from("/cli/cert.pem"));
        assert_eq!(r.key, PathBuf::from("/cli/key.pem"));
    }

    #[test]
    fn test_merge_cli_targets_replace_config() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "cfg.example.com"
address = "127.0.0.1:7070"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(
            None,
            vec![parse_host_mapping("cli.example.com@127.0.0.1:8080").unwrap()],
            None,
            None,
            Some(f.path().to_path_buf()),
        );
        let r = merge(opts).unwrap();
        assert_eq!(r.targets.len(), 1);
        assert!(r.targets.contains_key("cli.example.com"));
        assert!(!r.targets.contains_key("cfg.example.com"));
    }

    #[test]
    fn test_merge_config_targets_used_when_cli_empty() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "cfg.example.com"
address = "127.0.0.1:7070"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let r = merge(opts).unwrap();
        assert_eq!(r.targets.len(), 1);
        assert!(r.targets.contains_key("cfg.example.com"));
    }

    #[test]
    fn test_merge_missing_addr_errors() {
        let toml = r#"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("addr"));
    }

    #[test]
    fn test_merge_missing_cert_errors() {
        let toml = r#"
addr = "0.0.0.0:9000"
key  = "/cfg/key.pem"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("cert"));
    }

    #[test]
    fn test_merge_missing_key_errors() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("key"));
    }

    #[test]
    fn test_merge_invalid_target_addr_in_config() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "bad.example.com"
address = "not-a-valid-addr"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("bad.example.com"));
    }
}
