# anproxy

A lightweight HTTPS reverse proxy that terminates TLS and routes requests to HTTP backends based on the `Host` header.

## Features

- TLS termination with PEM certificate/key files
- Host-based routing to multiple HTTP backends
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
anproxy [addr] [-t <host@ip:port>...] [-c <cert>] [-k <key>] [--config-file <file>]
```

**Arguments:**

| Flag | Description |
|------|-------------|
| `addr` | Bind address (e.g. `0.0.0.0:8443`) |
| `-t`, `--targets` | Host-to-backend mapping: `hostname@ip:port` (repeatable) |
| `-c`, `--cert` | PEM certificate file |
| `-k`, `--key` | PEM private key file |
| `--config-file` | TOML config file (CLI flags take precedence) |

**Example:**

```bash
anproxy 0.0.0.0:8443 \
  -t example.com@127.0.0.1:8080 \
  -t api.example.com@127.0.0.1:9090 \
  -c cert.pem \
  -k key.pem
```

### Config file

Copy `anproxy.example.toml` and adjust as needed:

```toml
addr = "0.0.0.0:8443"
cert = "/etc/anproxy/cert.pem"
key  = "/etc/anproxy/key.pem"

[[targets]]
host    = "example.com"
address = "127.0.0.1:8080"

[[targets]]
host    = "api.example.com"
address = "127.0.0.1:9090"
```

```bash
anproxy --config-file anproxy.toml
```

CLI flags override any values set in the config file.

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
