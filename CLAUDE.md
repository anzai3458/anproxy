# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build              # Debug build
cargo build --release    # Release build
cargo check              # Fast type/syntax check
cargo run -- <args>      # Build and run
cargo clippy             # Lint
cargo test               # Run tests
```

Example invocation:
```bash
cargo run -- 0.0.0.0:8443 -t example.com@http://127.0.0.1:8080 -c cert.pem -k key.pem
cargo run -- 0.0.0.0:8443 -t static.example.com@file:///var/www/html -c cert.pem -k key.pem
```

## Architecture

`anproxy` is an HTTPS reverse proxy that terminates TLS and routes requests to HTTP backends based on the `Host` header. It also supports per-host static file serving.

**Module layout:**

```
src/
├── main.rs              # mod declarations + main()
├── cli.rs               # Options struct (argh CLI parsing)
├── config/
│   ├── mod.rs           # Target, TargetBackend enum + submodule declarations
│   ├── types.rs         # ConfigTarget, Config, ResolvedConfig, RuntimeConfig
│   ├── parse.rs         # parse_socket_addr, parse_host_mapping, parse_backend
│   └── loader.rs        # load_config_file, merge, resolve_path
├── tls/
│   ├── mod.rs           # submodule declarations
│   ├── cert.rs          # DynamicCertResolver, load_certified_key
│   ├── watcher.rs       # file_mtime, try_reload_if_changed, watch_certs
│   └── test_helpers.rs  # write_test_cert_files (cfg(test) only)
├── admin/
│   ├── mod.rs           # Assets, API modules, auth, persist
│   ├── api_targets.rs   # Target CRUD with backend field
│   ├── persist.rs       # Config persistence (unified targets)
│   ├── router.rs        # Route handlers (removed static-dirs routes)
│   └── ...
└── proxy/
    ├── mod.rs           # submodule declarations
    ├── handler.rs       # proxy() - single targets lookup with TargetBackend match
    ├── server.rs        # process()
    └── static_handler.rs  # serve_static()
```

**Request flow:**

1. `main()` — binds TCP, loads TLS certs, spawns one task per connection
2. `proxy::server::process()` — performs TLS handshake (via `tokio-rustls`), then hands the connection to Hyper for HTTP/1.1
3. `proxy::handler::proxy()` — called per-request; extracts the `Host` header; looks up the target in `cfg.targets` (single HashMap); matches on `TargetBackend::File(_)` → calls `serve_static()`, `TargetBackend::Http(_)` → proxy forward
4. `proxy::static_handler::serve_static()` — resolves the request path under the configured directory, enforces path traversal protection via `canonicalize`, computes ETag from mtime+size, handles `If-None-Match` / `If-Modified-Since` for 304 responses, detects MIME type from extension
5. `proxy::handler::proxy_upgraded()` — handles connection upgrades (e.g. WebSocket) by bidirectionally piping raw bytes with `tokio::select!`

**CLI arguments** (parsed with `argh`):
- Positional `addr` — bind address (e.g. `0.0.0.0:8443`)
- `-t`/`--targets` — one or more `hostname@backend` mappings where backend is `http://ip:port` or `file:///path`
- `-c`/`--cert` — PEM certificate file
- `-k`/`--key` — PEM private key file
- `--config-file` — TOML config file (all fields optional; CLI args take precedence)

**Config TOML format (unified targets):**
```toml
addr = "0.0.0.0:8443"
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"

[[targets]]
host = "example.com"
backend = "http://127.0.0.1:8080"

[[targets]]
host = "static.example.com"
backend = "file:///var/www/html"
```

**Path resolution:** all file paths (cert, key, static dirs) are resolved to absolute paths during `merge()`. CLI paths resolve relative to `cwd`; config file paths resolve relative to the config file's parent directory. Absolute paths are always used as-is.

**Key types:**
- `cli::Options` — parsed CLI args
- `config::Target { host, backend }` — a single host-to-backend mapping
- `config::TargetBackend` — enum `Http(SocketAddr)` or `File(PathBuf)`
- `config::types::Config` — raw deserialized TOML config
- `config::types::ResolvedConfig` — merged, validated config passed to `main()`
- `config::types::RuntimeConfig` — shared runtime config (single `targets: HashMap<String, TargetBackend>`)
- `tls::cert::DynamicCertResolver` — `ResolvesServerCert` impl backed by an `Arc<RwLock<...>>` for hot-reload

**Stack:** Tokio (async runtime), Hyper 1.x (HTTP/1.1 only), rustls + tokio-rustls (TLS), argh (CLI), serde + toml (config file), httpdate (RFC 7231 date formatting).
