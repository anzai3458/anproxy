# anproxy

A lightweight HTTPS reverse proxy that terminates TLS and routes requests to HTTP backends based on the `Host` header.

## Features

- TLS termination with PEM certificate/key files
- Host-based routing to multiple HTTP backends
- Static file serving per host (with ETag-based caching)
- Forwards `X-Forwarded-For` and `X-Forwarded-Proto` headers
- WebSocket and HTTP upgrade support
- Hot-reloading of TLS certificates without restart
- Configuration via CLI flags or TOML file

## Installation

```bash
cargo build --release
# Binary at target/release/anproxy
```

## Usage

### CLI

```
anproxy [addr] [-t <host@ip:port>...] [-s <host@path>...] [-c <cert>] [-k <key>] [--config-file <file>] [-l <level>]
```

**Arguments:**

| Flag | Description |
|------|-------------|
| `addr` | Bind address (e.g. `0.0.0.0:8443`) |
| `-t`, `--targets` | Host-to-backend mapping: `hostname@ip:port` (repeatable) |
| `-s`, `--static` | Host-to-directory mapping: `hostname@path` (repeatable) |
| `-c`, `--cert` | PEM certificate file |
| `-k`, `--key` | PEM private key file |
| `--config-file` | TOML config file (CLI flags take precedence) |
| `-l`, `--log-level` | Log level: `error`, `warn`, `info`, `debug`, `trace` (default: `info`) |

**Example:**

```bash
anproxy 0.0.0.0:8443 \
  -t example.com@127.0.0.1:8080 \
  -t api.example.com@127.0.0.1:9090 \
  -s static.example.com@/var/www/html \
  -c cert.pem \
  -k key.pem
```

### Config file

Copy `anproxy.example.toml` and adjust as needed:

```toml
addr      = "0.0.0.0:8443"
cert      = "/etc/anproxy/cert.pem"
key       = "/etc/anproxy/key.pem"
log_level = "info"

[[targets]]
host    = "example.com"
address = "127.0.0.1:8080"

[[targets]]
host    = "api.example.com"
address = "127.0.0.1:9090"

[[static_dirs]]
host = "static.example.com"
dir  = "/var/www/html"
```

```bash
anproxy --config-file anproxy.toml
```

CLI flags override any values set in the config file.

Relative paths in the config file are resolved relative to the config file's directory. Relative paths passed as CLI flags are resolved relative to the working directory.

The `RUST_LOG` environment variable overrides the log level from all sources, and supports fine-grained directives (e.g. `RUST_LOG=anproxy=debug`).

## Static file serving

A host can serve files from a local directory instead of (or in addition to) a proxy backend. On each request anproxy:

1. Checks if the host has a static dir configured.
2. If yes, tries to resolve the request path to a file under that directory.
3. If the file exists, serves it and returns. If not, falls through to the proxy backend (if one is configured).

This makes it straightforward to run a mixed setup — e.g. `app.example.com` serves a pre-built SPA from disk while `api.example.com` proxies to a backend.

**Caching behaviour:**
- Responds with `ETag: "<mtime>-<size>"` and `Last-Modified` on every file response.
- Returns `304 Not Modified` when the client sends a matching `If-None-Match` or `If-Modified-Since` header.
- Sets `Cache-Control: public, max-age=0, must-revalidate` so browsers always revalidate but can use a cached copy instantly when the ETag matches.

**Path traversal protection:** the resolved file path is canonicalized and checked to be within the configured directory before the file is opened.

## Development

```bash
cargo check       # Fast type/syntax check
cargo build       # Debug build
cargo clippy      # Lint
cargo test        # Run tests
```

## Stack

- [Tokio](https://tokio.rs) — async runtime
- [Hyper](https://hyper.rs) 1.x — HTTP/1.1
- [rustls](https://github.com/rustls/rustls) + tokio-rustls — TLS
- [argh](https://github.com/google/argh) — CLI parsing
- [serde](https://serde.rs) + [toml](https://github.com/toml-rs/toml) — config file
- [httpdate](https://github.com/pyfisch/httpdate) — RFC 7231 date formatting
