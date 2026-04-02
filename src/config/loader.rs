use std::error::Error as StdError;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::Options;
use crate::config::parse::parse_backend;
use crate::config::types::{Config, ResolvedConfig};
use crate::config::Target;

fn resolve_path(raw: PathBuf, base: &Path) -> PathBuf {
    if raw.is_absolute() {
        raw
    } else {
        base.join(raw)
    }
}

fn into_unique_map<V>(
    entries: Vec<(String, V)>,
    kind: &str,
) -> Result<std::collections::HashMap<String, V>, String> {
    let mut map = std::collections::HashMap::with_capacity(entries.len());
    for (host, val) in entries {
        if map.contains_key(&host) {
            return Err(format!("duplicate {kind} entry for host '{host}'"));
        }
        map.insert(host, val);
    }
    Ok(map)
}

pub fn load_config_file(path: &PathBuf) -> Result<Config, Box<dyn StdError + Send + Sync>> {
    let contents = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read config file {}: {}", path.display(), e))?;
    toml::from_str(&contents)
        .map_err(|e| format!("Invalid TOML in {}: {}", path.display(), e).into())
}

pub fn merge(opts: Options) -> Result<ResolvedConfig, Box<dyn StdError + Send + Sync>> {
    let cli_base = std::env::current_dir()?;
    let config_file_path = opts.config_file.as_ref().map(|p| resolve_path(p.clone(), &cli_base));

    let file_cfg = match &opts.config_file {
        Some(p) => load_config_file(p)?,
        None => Config::default(),
    };

    let cfg_base: PathBuf = opts
        .config_file
        .as_ref()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| cli_base.clone());

    let addr_str = opts
        .addr
        .or(file_cfg.addr)
        .ok_or("addr is required (positional arg or config file 'addr')")?;
    let addr = crate::config::parse::parse_socket_addr(&addr_str)
        .map_err(|e| format!("Invalid addr '{}': {}", addr_str, e))?;

    let cert = opts
        .cert
        .map(|p| resolve_path(p, &cli_base))
        .or_else(|| {
            file_cfg
                .cert
                .map(|s| resolve_path(PathBuf::from(s), &cfg_base))
        });

    let key = opts
        .key
        .map(|p| resolve_path(p, &cli_base))
        .or_else(|| {
            file_cfg
                .key
                .map(|s| resolve_path(PathBuf::from(s), &cfg_base))
        });

    let no_tls = opts.no_tls || file_cfg.no_tls.unwrap_or(false);

    if !no_tls {
        if cert.is_none() {
            return Err("cert is required (-c or config file 'cert'). Use --no-tls to disable TLS.".into());
        }
        if key.is_none() {
            return Err("key is required (-k or config file 'key'). Use --no-tls to disable TLS.".into());
        }
    }

    // Collect targets from CLI or config file
    let raw_targets: Vec<Target> = if !opts.targets.is_empty() {
        opts.targets
    } else {
        file_cfg
            .targets
            .into_iter()
            .map(|ct| {
                let backend = parse_backend(&ct.backend).map_err(|e| {
                    format!(
                        "Invalid backend '{}' for host '{}': {}",
                        ct.backend, ct.host, e
                    )
                })?;
                Ok(Target {
                    host: ct.host,
                    backend,
                })
            })
            .collect::<Result<Vec<_>, String>>()?
    };

    let targets = into_unique_map(
        raw_targets.into_iter().map(|t| (t.host, t.backend)).collect(),
        "target",
    )?;

    let log_level = opts
        .log_level
        .or(file_cfg.log_level)
        .unwrap_or_else(|| "info".to_string());

    let admin_addr_str = opts.admin_addr.or(file_cfg.admin_addr);
    let admin_addr = admin_addr_str
        .map(|s| crate::config::parse::parse_socket_addr(&s).map_err(|e| format!("Invalid admin_addr '{}': {}", s, e)))
        .transpose()?;

    let admin_user = opts.admin_user.or(file_cfg.admin_user);
    let admin_pass = opts.admin_pass.or(file_cfg.admin_pass);

    if admin_addr.is_some() && (admin_user.is_none() || admin_pass.is_none()) {
        return Err("admin_user and admin_pass are required when admin_addr is set".into());
    }

    Ok(ResolvedConfig {
        addr,
        targets,
        cert,
        key,
        log_level,
        admin_addr,
        admin_user,
        admin_pass,
        config_file: config_file_path,
        no_tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse::parse_host_mapping;
    use crate::config::TargetBackend;
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
            admin_addr: None,
            admin_user: None,
            admin_pass: None,
            no_tls: false,
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
backend = "http://127.0.0.1:8080"

[[targets]]
host    = "api.example.com"
backend = "http://127.0.0.1:9090"
"#;
        let f = write_toml_config(toml);
        let cfg = load_config_file(&f.path().to_path_buf()).unwrap();
        assert_eq!(cfg.addr.as_deref(), Some("0.0.0.0:8443"));
        assert_eq!(cfg.cert.as_deref(), Some("/etc/anproxy/cert.pem"));
        assert_eq!(cfg.key.as_deref(), Some("/etc/anproxy/key.pem"));
        assert_eq!(cfg.targets.len(), 2);
        assert_eq!(cfg.targets[0].host, "example.com");
        assert_eq!(cfg.targets[0].backend, "http://127.0.0.1:8080");
        assert_eq!(cfg.targets[1].host, "api.example.com");
        assert_eq!(cfg.targets[1].backend, "http://127.0.0.1:9090");
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
            vec![parse_host_mapping("example.com@http://127.0.0.1:8080").unwrap()],
            Some("/tmp/cert.pem"),
            Some("/tmp/key.pem"),
            None,
        );
        let r = merge(opts).unwrap();
        assert_eq!(r.addr.to_string(), "127.0.0.1:8443");
        assert_eq!(r.cert, Some(PathBuf::from("/tmp/cert.pem")));
        assert_eq!(r.key, Some(PathBuf::from("/tmp/key.pem")));
        assert_eq!(r.targets.len(), 1);
        assert!(r.targets.contains_key("example.com"));
        match &r.targets["example.com"] {
            TargetBackend::Http(addr) => assert_eq!(addr.to_string(), "127.0.0.1:8080"),
            _ => panic!("Expected Http backend"),
        }
    }

    #[test]
    fn test_merge_config_file_only() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "cfg.example.com"
backend = "http://127.0.0.1:7070"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let r = merge(opts).unwrap();
        assert_eq!(r.addr.to_string(), "0.0.0.0:9000");
        assert_eq!(r.cert, Some(PathBuf::from("/cfg/cert.pem")));
        assert_eq!(r.key, Some(PathBuf::from("/cfg/key.pem")));
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
        assert_eq!(r.cert, Some(PathBuf::from("/cli/cert.pem")));
        assert_eq!(r.key, Some(PathBuf::from("/cli/key.pem")));
    }

    #[test]
    fn test_merge_cli_targets_replace_config() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "cfg.example.com"
backend = "http://127.0.0.1:7070"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(
            None,
            vec![parse_host_mapping("cli.example.com@http://127.0.0.1:8080").unwrap()],
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
backend = "http://127.0.0.1:7070"
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
    fn test_merge_invalid_target_backend_in_config() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "bad.example.com"
backend = "not-a-valid-backend"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("bad.example.com"));
    }

    #[test]
    fn test_merge_targets_from_config_file() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host = "example.com"
backend = "http://127.0.0.1:8080"

[[targets]]
host = "static.example.com"
backend = "file:///var/www/html"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let r = merge(opts).unwrap();
        assert_eq!(r.targets.len(), 2);

        assert!(r.targets.contains_key("example.com"));
        match &r.targets["example.com"] {
            TargetBackend::Http(addr) => assert_eq!(addr.to_string(), "127.0.0.1:8080"),
            _ => panic!("Expected Http backend"),
        }

        assert!(r.targets.contains_key("static.example.com"));
        match &r.targets["static.example.com"] {
            TargetBackend::File(path) => assert_eq!(path.to_string_lossy(), "/var/www/html"),
            _ => panic!("Expected File backend"),
        }
    }

    #[test]
    fn test_merge_duplicate_target_in_config_errors() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "example.com"
backend = "http://127.0.0.1:8080"

[[targets]]
host    = "example.com"
backend = "http://127.0.0.1:9090"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
        assert!(err.to_string().contains("example.com"));
    }

    #[test]
    fn test_merge_duplicate_target_via_cli_errors() {
        let opts = Options {
            addr: Some("127.0.0.1:8443".to_string()),
            targets: vec![
                parse_host_mapping("example.com@http://127.0.0.1:8080").unwrap(),
                parse_host_mapping("example.com@http://127.0.0.1:9090").unwrap(),
            ],
            cert: Some(PathBuf::from("/tmp/cert.pem")),
            key: Some(PathBuf::from("/tmp/key.pem")),
            config_file: None,
            log_level: None,
            admin_addr: None,
            admin_user: None,
            admin_pass: None,
            no_tls: false,
        };
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
        assert!(err.to_string().contains("example.com"));
    }

    #[test]
    fn test_merge_admin_fields_from_config() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"
admin_addr = "127.0.0.1:9090"
admin_user = "admin"
admin_pass = "secret"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let r = merge(opts).unwrap();
        assert_eq!(r.admin_addr.unwrap().to_string(), "127.0.0.1:9090");
        assert_eq!(r.admin_user.as_deref(), Some("admin"));
        assert_eq!(r.admin_pass.as_deref(), Some("secret"));
        assert!(!r.no_tls);
    }

    #[test]
    fn test_merge_admin_addr_without_creds_errors() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"
admin_addr = "127.0.0.1:9090"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let err = merge(opts).unwrap_err();
        assert!(err.to_string().contains("admin_user"));
    }

    #[test]
    fn test_merge_no_admin_fields_ok() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"
"#;
        let f = write_toml_config(toml);
        let opts = make_opts(None, vec![], None, None, Some(f.path().to_path_buf()));
        let r = merge(opts).unwrap();
        assert!(r.admin_addr.is_none());
    }

    #[test]
    fn test_existing_config_without_admin_fields_still_parses() {
        let toml = r#"
addr = "0.0.0.0:9000"
cert = "/cfg/cert.pem"
key  = "/cfg/key.pem"

[[targets]]
host    = "example.com"
backend = "http://127.0.0.1:8080"
"#;
        let f = write_toml_config(toml);
        let cfg = load_config_file(&f.path().to_path_buf()).unwrap();
        assert!(cfg.admin_addr.is_none());
        assert!(cfg.admin_user.is_none());
        assert!(cfg.admin_pass.is_none());
    }
}
