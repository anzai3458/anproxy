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
cargo run -- 0.0.0.0:8443 -t example.com@127.0.0.1:8080 -c cert.pem -k key.pem
```

## Architecture

`anproxy` is an HTTPS reverse proxy that terminates TLS and routes requests to HTTP backends based on the `Host` header.

**Module layout:**

```
src/
├── main.rs              # mod declarations + main()
├── cli.rs               # Options struct (argh CLI parsing)
├── config/
│   ├── mod.rs           # Target struct + submodule declarations
│   ├── types.rs         # ConfigTarget, Config, ResolvedConfig
│   ├── parse.rs         # parse_socket_addr, parse_host_mapping
│   └── loader.rs        # load_config_file, merge
├── tls/
│   ├── mod.rs           # submodule declarations
│   ├── cert.rs          # DynamicCertResolver, load_certified_key
│   ├── watcher.rs       # file_mtime, try_reload_if_changed, watch_certs
│   └── test_helpers.rs  # write_test_cert_files (cfg(test) only)
└── proxy/
    ├── mod.rs           # submodule declarations
    ├── handler.rs       # proxy(), proxy_upgraded(), send_request()
    └── server.rs        # process()
```

**Request flow:**

1. `main()` — binds TCP, loads TLS certs, spawns one task per connection
2. `proxy::server::process()` — performs TLS handshake (via `tokio-rustls`), then hands the connection to Hyper for HTTP/1.1
3. `proxy::handler::proxy()` — called per-request; extracts the `Host` header, looks up the target in the `--targets` map, adds `X-Forwarded-For` (IP only, no port) and `X-Forwarded-Proto: https`, forwards to backend
4. `proxy::handler::proxy_upgraded()` — handles connection upgrades (e.g. WebSocket) by bidirectionally piping raw bytes with `tokio::select!`

**CLI arguments** (parsed with `argh`):
- Positional `addr` — bind address (e.g. `0.0.0.0:8443`)
- `-t`/`--targets` — one or more `hostname@ip:port` mappings
- `-c`/`--cert` — PEM certificate file
- `-k`/`--key` — PEM private key file
- `--config-file` — TOML config file (all fields optional; CLI args take precedence)

**Key types:**
- `cli::Options` — parsed CLI args
- `config::Target { host, address }` — a single host-to-backend mapping
- `config::types::Config` — raw deserialized TOML config
- `config::types::ResolvedConfig` — merged, validated config passed to `main()`
- `tls::cert::DynamicCertResolver` — `ResolvesServerCert` impl backed by an `Arc<RwLock<...>>` for hot-reload

**Stack:** Tokio (async runtime), Hyper 1.x (HTTP/1.1 only), rustls + tokio-rustls (TLS), argh (CLI), serde + toml (config file).
