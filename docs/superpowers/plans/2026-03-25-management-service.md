# Management Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an embedded management service to anproxy with a React frontend for live routing config, monitoring, cert management, and speed testing.

**Architecture:** A second TLS-enabled Hyper HTTP server shares mutable routing config (`Arc<RwLock<RuntimeConfig>>`) with the proxy. The frontend is a React SPA embedded via `rust-embed`. Session-based auth protects all management endpoints.

**Tech Stack:** Rust (Tokio, Hyper 1.x, rustls, rust-embed, dashmap, serde_json, x509-parser, rand), React 18 + TypeScript + Redux Toolkit + Tailwind CSS + Vite

**Spec:** `docs/superpowers/specs/2026-03-25-management-service-design.md`

---

### Task 1: Add New Dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add dependencies to Cargo.toml**

Add to `[dependencies]`:
```toml
serde_json = "1"
rust-embed = "8"
dashmap = "6"
rand = "0.8"
x509-parser = "0.16"
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check`
Expected: compiles with no errors

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat(admin): add dependencies for management service"
```

---

### Task 2: RuntimeConfig and SharedConfig Types

**Files:**
- Modify: `src/config/types.rs:28-36`
- Modify: `src/config/mod.rs`

- [ ] **Step 1: Write tests for RuntimeConfig**

Add to `src/config/types.rs` at the end:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_config_new() {
        let mut targets = HashMap::new();
        targets.insert("example.com".to_string(), "127.0.0.1:8080".parse().unwrap());
        let rc = RuntimeConfig {
            targets,
            static_dirs: HashMap::new(),
        };
        assert_eq!(rc.targets.len(), 1);
        assert!(rc.static_dirs.is_empty());
    }

    #[test]
    fn test_runtime_config_from_resolved() {
        let mut targets = HashMap::new();
        targets.insert("a.com".to_string(), "1.2.3.4:80".parse().unwrap());
        let mut static_dirs = HashMap::new();
        static_dirs.insert("s.com".to_string(), PathBuf::from("/var/www"));
        let rc = RuntimeConfig { targets, static_dirs };
        assert_eq!(rc.targets.len(), 1);
        assert_eq!(rc.static_dirs.len(), 1);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib config::types::tests`
Expected: FAIL — `RuntimeConfig` not defined

- [ ] **Step 3: Add RuntimeConfig and SharedConfig**

Add to `src/config/types.rs` after `ResolvedConfig`:

```rust
#[derive(Debug)]
pub struct RuntimeConfig {
    pub targets: HashMap<String, SocketAddr>,
    pub static_dirs: HashMap<String, PathBuf>,
}

pub type SharedConfig = std::sync::Arc<std::sync::RwLock<RuntimeConfig>>;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib config::types::tests`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config/types.rs
git commit -m "feat(admin): add RuntimeConfig and SharedConfig types"
```

---

### Task 3: Stats Module

**Files:**
- Create: `src/stats.rs`
- Modify: `src/main.rs:1` (add `mod stats;`)

- [ ] **Step 1: Write tests for Stats**

Create `src/stats.rs`:

```rust
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct Stats {
    pub active_connections: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub per_host_requests: DashMap<String, AtomicU64>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            per_host_requests: DashMap::new(),
        }
    }

    pub fn inc_requests(&self, host: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.per_host_requests
            .entry(host.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stats_are_zero() {
        let stats = Stats::new();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_inc_requests_updates_total_and_per_host() {
        let stats = Stats::new();
        stats.inc_requests("example.com");
        stats.inc_requests("example.com");
        stats.inc_requests("other.com");
        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 3);
        assert_eq!(
            stats.per_host_requests.get("example.com").unwrap().load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            stats.per_host_requests.get("other.com").unwrap().load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_connection_counting() {
        let stats = Stats::new();
        stats.inc_connections();
        stats.inc_connections();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);
        stats.dec_connections();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);
    }
}
```

- [ ] **Step 2: Add mod declaration to main.rs**

Add `mod stats;` after line 4 in `src/main.rs` (after `mod tls;`).

- [ ] **Step 3: Run tests**

Run: `cargo test --lib stats::tests`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/stats.rs src/main.rs
git commit -m "feat(admin): add Stats module with atomic counters and DashMap"
```

---

### Task 4: Refactor Proxy to Use SharedConfig and Stats

**Files:**
- Modify: `src/proxy/handler.rs:19-24` (signature change)
- Modify: `src/proxy/server.rs:14-19` (signature change)
- Modify: `src/main.rs:36-69` (create SharedConfig, pass to process)

- [ ] **Step 1: Update proxy handler signature**

In `src/proxy/handler.rs`, change the function signature and body. Replace the imports and function:

Replace lines 1-24:
```rust
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::upgrade::OnUpgrade;
use hyper::{header, upgrade, Error, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::split;
use tokio::net::TcpStream;
use tokio::{io, select};

use crate::config::types::SharedConfig;
use crate::proxy::static_handler::serve_static;
use crate::stats::Stats;

pub async fn proxy(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    config: SharedConfig,
    stats: Arc<Stats>,
) -> Result<Response<BoxBody<Bytes, Error>>, String> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    // Strip optional port from the Host header for map lookups.
    let hostname = host.split(':').next().unwrap_or(&host).to_owned();

    stats.inc_requests(&hostname);

    // Read config under lock, clone what we need, then drop the guard.
    let (static_dir, target_addr) = {
        let cfg = config.read().unwrap();
        (
            cfg.static_dirs.get(&hostname).cloned(),
            cfg.targets.get(&hostname).copied(),
        )
    };

    // Try static file serving before proxy.
    if let Some(ref static_dir) = static_dir {
        if let Some(resp) = serve_static(&req, static_dir).await {
            tracing::info!(
                peer = %peer_addr, %host, %method, %path,
                status = resp.status().as_u16(),
                "static",
            );
            return Ok(resp);
        }
    }
```

Then replace lines 49-64 (the old target lookup and 404) — remove those lines since `target_addr` is already resolved above. The rest of the function from `let (parts, body) = req.into_parts();` continues with `target_addr` already available. Replace:

```rust
    let (parts, body) = req.into_parts();
    let mut req_from_client = Request::from_parts(parts, body.boxed());

    if target_addr.is_none() {
        tracing::warn!(peer = %peer_addr, %host, "no target configured for host");
        return Ok::<Response<BoxBody<Bytes, Error>>, String>(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(BoxBody::default())
                .unwrap(),
        );
    }

    let target_addr = target_addr.unwrap();
```

The rest of the function (from `let target_stream = TcpStream::connect(target_addr)`) stays the same.

- [ ] **Step 2: Update server.rs to use SharedConfig and Stats**

Replace `src/proxy/server.rs` entirely:

```rust
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::config::types::SharedConfig;
use crate::proxy::handler::proxy;
use crate::stats::Stats;

pub async fn process(
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    config: SharedConfig,
    stats: Arc<Stats>,
) -> Result<(), String> {
    let client_stream = acceptor.accept(stream).await.map_err(|e| e.to_string())?;
    let client_io = TokioIo::new(client_stream);

    stats.inc_connections();
    let stats_clone = Arc::clone(&stats);

    let service = service_fn(move |req| {
        let cfg = config.clone();
        let st = stats.clone();
        proxy(req, peer_addr, cfg, st)
    });

    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new()
            .serve_connection(client_io, service)
            .with_upgrades()
            .await
        {
            tracing::debug!(peer = %peer_addr, "Connection closed: {:?}", err);
        }
        stats_clone.dec_connections();
    });

    Ok(())
}
```

- [ ] **Step 3: Update main.rs to create SharedConfig and Stats**

In `src/main.rs`, update imports and the body. Replace lines 6-8:
```rust
use std::sync::{Arc, RwLock};
```
becomes:
```rust
use std::sync::{Arc, RwLock};
```
(stays the same, already imported)

Add import:
```rust
use config::types::RuntimeConfig;
```

Replace lines 36-38 (the old Arc wrapping):
```rust
    let addr = resolved.addr;
    let targets: Arc<HashMap<String, std::net::SocketAddr>> = Arc::new(resolved.targets);
    let static_dirs = Arc::new(resolved.static_dirs);
```
with:
```rust
    let addr = resolved.addr;
    let shared_config = Arc::new(RwLock::new(RuntimeConfig {
        targets: resolved.targets,
        static_dirs: resolved.static_dirs,
    }));
    let stats = Arc::new(stats::Stats::new());
```

Replace lines 63-69 (the process call):
```rust
        let fut = process(
            stream,
            peer_addr,
            acceptor,
            targets.clone(),
            static_dirs.clone(),
        );
```
with:
```rust
        let fut = process(
            stream,
            peer_addr,
            acceptor,
            shared_config.clone(),
            stats.clone(),
        );
```

Remove the unused `use std::collections::HashMap;` import from line 6 of main.rs.

- [ ] **Step 4: Verify everything compiles and existing tests pass**

Run: `cargo check && cargo test`
Expected: compiles, all tests pass

- [ ] **Step 5: Commit**

```bash
git add src/proxy/handler.rs src/proxy/server.rs src/main.rs
git commit -m "refactor: use SharedConfig and Stats in proxy handler"
```

---

### Task 5: CLI and Config for Admin Service

**Files:**
- Modify: `src/cli.rs:10-38` (add admin fields)
- Modify: `src/config/types.rs:17-36` (add admin fields to Config and ResolvedConfig)
- Modify: `src/config/loader.rs:39-144` (merge admin fields)

- [ ] **Step 1: Write tests for admin config merging**

Add to `src/config/loader.rs` in the test module:

```rust
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
address = "127.0.0.1:8080"
"#;
        let f = write_toml_config(toml);
        let cfg = load_config_file(&f.path().to_path_buf()).unwrap();
        assert!(cfg.admin_addr.is_none());
        assert!(cfg.admin_user.is_none());
        assert!(cfg.admin_pass.is_none());
    }
```

- [ ] **Step 2: Run tests to see failures**

Run: `cargo test --lib config::loader::tests`
Expected: FAIL — fields don't exist yet

- [ ] **Step 3: Add admin fields to CLI Options**

In `src/cli.rs`, add after the `log_level` field (line 37):

```rust
    /// admin management bind addr
    #[argh(option, long = "admin-addr")]
    pub admin_addr: Option<String>,

    /// admin username
    #[argh(option, long = "admin-user")]
    pub admin_user: Option<String>,

    /// admin password
    #[argh(option, long = "admin-pass")]
    pub admin_pass: Option<String>,
```

- [ ] **Step 4: Add admin fields to Config (TOML)**

In `src/config/types.rs`, add to `Config` struct after `log_level` (line 25):

```rust
    pub admin_addr: Option<String>,
    pub admin_user: Option<String>,
    pub admin_pass: Option<String>,
```

- [ ] **Step 5: Add admin fields to ResolvedConfig**

In `src/config/types.rs`, add to `ResolvedConfig` after `static_dirs` (line 35):

```rust
    pub admin_addr: Option<SocketAddr>,
    pub admin_user: Option<String>,
    pub admin_pass: Option<String>,
    pub config_file: Option<PathBuf>,
```

(`config_file` is needed so the admin service knows where to persist changes.)

- [ ] **Step 6: Update merge() to handle admin fields**

In `src/config/loader.rs`, add after the `log_level` merging (after line 134) and before the `Ok(ResolvedConfig {`:

```rust
    let admin_addr_str = opts.admin_addr.or(file_cfg.admin_addr);
    let admin_addr = admin_addr_str
        .map(|s| parse_socket_addr(&s).map_err(|e| format!("Invalid admin_addr '{}': {}", s, e)))
        .transpose()?;

    let admin_user = opts.admin_user.or(file_cfg.admin_user);
    let admin_pass = opts.admin_pass.or(file_cfg.admin_pass);

    if admin_addr.is_some() && (admin_user.is_none() || admin_pass.is_none()) {
        return Err("admin_user and admin_pass are required when admin_addr is set".into());
    }

    let config_file_path = opts.config_file.map(|p| resolve_path(p, &cli_base));
```

And add the fields to the `Ok(ResolvedConfig { ... })` return:

```rust
        admin_addr,
        admin_user,
        admin_pass,
        config_file: config_file_path,
```

Note: `opts.config_file` is consumed earlier (line 42-43). Clone it before that:
```rust
    let config_file_path = opts.config_file.as_ref().map(|p| resolve_path(p.clone(), &cli_base));
```
Place this line right after `let cli_base = ...` (line 40), before `opts.config_file` is used by `load_config_file`. Then use `config_file_path` in the returned `ResolvedConfig`.

- [ ] **Step 7: Update make_opts helper in tests**

Update `make_opts` to include admin fields, and update the `Options` literal in `test_merge_cli_static_dirs_replace_config`:

```rust
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
            static_dirs: vec![],
            cert: cert.map(PathBuf::from),
            key: key.map(PathBuf::from),
            config_file,
            log_level: None,
            admin_addr: None,
            admin_user: None,
            admin_pass: None,
        }
    }
```

Also update the `test_merge_cli_static_dirs_replace_config` test's raw `Options` literal to include the new fields.

- [ ] **Step 8: Run all tests**

Run: `cargo test`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/cli.rs src/config/types.rs src/config/loader.rs
git commit -m "feat(admin): add CLI/config fields for admin service"
```

---

### Task 6: Session Auth Module

**Files:**
- Create: `src/admin/mod.rs`
- Create: `src/admin/auth.rs`
- Modify: `src/main.rs:1` (add `mod admin;`)

- [ ] **Step 1: Create admin module structure**

Create `src/admin/mod.rs`:
```rust
pub mod auth;
```

Add `mod admin;` to `src/main.rs` after `mod config;`.

- [ ] **Step 2: Write auth tests**

Create `src/admin/auth.rs`:

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Session {
    pub last_activity: Instant,
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    timeout: Duration,
}

impl SessionStore {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    pub fn create_session(&self) -> String {
        use rand::Rng;
        let token: String = (0..32)
            .map(|_| format!("{:02x}", rand::rng().random::<u8>()))
            .collect();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(
            token.clone(),
            Session {
                last_activity: Instant::now(),
            },
        );
        token
    }

    pub fn validate(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(token) {
            if session.last_activity.elapsed() < self.timeout {
                session.last_activity = Instant::now();
                return true;
            }
            sessions.remove(token);
        }
        false
    }

    pub fn remove(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }

    pub fn cleanup_expired(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.last_activity.elapsed() < self.timeout);
    }
}

/// Extract session token from Cookie header value.
pub fn extract_session_cookie(cookie_header: &str) -> Option<&str> {
    cookie_header
        .split(';')
        .map(|s| s.trim())
        .find_map(|part| {
            let (key, value) = part.split_once('=')?;
            if key.trim() == "session" {
                Some(value.trim())
            } else {
                None
            }
        })
}

/// Build Set-Cookie header value for a session.
pub fn session_cookie(token: &str) -> String {
    format!("session={token}; HttpOnly; Secure; SameSite=Strict; Path=/")
}

/// Build Set-Cookie header that clears the session.
pub fn clear_session_cookie() -> String {
    "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_session() {
        let store = SessionStore::new(Duration::from_secs(1800));
        let token = store.create_session();
        assert!(store.validate(&token));
    }

    #[test]
    fn test_invalid_token_rejected() {
        let store = SessionStore::new(Duration::from_secs(1800));
        assert!(!store.validate("nonexistent"));
    }

    #[test]
    fn test_remove_session() {
        let store = SessionStore::new(Duration::from_secs(1800));
        let token = store.create_session();
        store.remove(&token);
        assert!(!store.validate(&token));
    }

    #[test]
    fn test_expired_session_rejected() {
        let store = SessionStore::new(Duration::from_millis(1));
        let token = store.create_session();
        std::thread::sleep(Duration::from_millis(10));
        assert!(!store.validate(&token));
    }

    #[test]
    fn test_cleanup_expired() {
        let store = SessionStore::new(Duration::from_millis(1));
        store.create_session();
        store.create_session();
        std::thread::sleep(Duration::from_millis(10));
        store.cleanup_expired();
        // All sessions should be cleaned up (we can't assert internals but no panics)
    }

    #[test]
    fn test_extract_session_cookie() {
        assert_eq!(
            extract_session_cookie("session=abc123; other=value"),
            Some("abc123")
        );
        assert_eq!(extract_session_cookie("other=value"), None);
        assert_eq!(extract_session_cookie("session=token"), Some("token"));
    }

    #[test]
    fn test_session_cookie_format() {
        let cookie = session_cookie("abc");
        assert!(cookie.contains("session=abc"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test --lib admin::auth::tests`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/admin/mod.rs src/admin/auth.rs src/main.rs
git commit -m "feat(admin): add session auth module"
```

---

### Task 7: JSON Response Helpers and Persist Module

**Files:**
- Create: `src/admin/response.rs`
- Create: `src/admin/persist.rs`
- Modify: `src/admin/mod.rs`

- [ ] **Step 1: Create response helpers**

Create `src/admin/response.rs`:

```rust
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Error, Response, StatusCode};

pub fn json_ok<T: serde::Serialize>(data: &T) -> Response<BoxBody<Bytes, Error>> {
    let body = serde_json::json!({ "ok": true, "data": data });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())).map_err(|e| match e {}).boxed())
        .unwrap()
}

pub fn json_err(status: StatusCode, msg: &str) -> Response<BoxBody<Bytes, Error>> {
    let body = serde_json::json!({ "ok": false, "error": msg });
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())).map_err(|e| match e {}).boxed())
        .unwrap()
}

pub fn empty_ok() -> Response<BoxBody<Bytes, Error>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(BoxBody::default())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_ok_response() {
        let resp = json_ok(&serde_json::json!({"key": "value"}));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("Content-Type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_json_err_response() {
        let resp = json_err(StatusCode::BAD_REQUEST, "bad input");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
```

- [ ] **Step 2: Create persist module**

Create `src/admin/persist.rs`:

```rust
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::config::types::RuntimeConfig;

/// Read-modify-write: loads existing config file, updates targets/static_dirs,
/// preserves all other fields (addr, cert, key, admin_*, log_level), and
/// atomically writes back.
pub async fn persist_config(
    config: &RuntimeConfig,
    config_path: &Path,
) -> Result<(), String> {
    // Read existing file to preserve non-routing fields
    let existing = tokio::fs::read_to_string(config_path)
        .await
        .unwrap_or_default();
    let mut doc: toml::Table = existing.parse::<toml::Table>().unwrap_or_default();

    // Update targets
    let targets: Vec<toml::Value> = config
        .targets
        .iter()
        .map(|(host, addr)| {
            let mut t = toml::Table::new();
            t.insert("host".into(), toml::Value::String(host.clone()));
            t.insert("address".into(), toml::Value::String(addr.to_string()));
            toml::Value::Table(t)
        })
        .collect();
    doc.insert("targets".into(), toml::Value::Array(targets));

    // Update static_dirs
    let static_dirs: Vec<toml::Value> = config
        .static_dirs
        .iter()
        .map(|(host, dir)| {
            let mut t = toml::Table::new();
            t.insert("host".into(), toml::Value::String(host.clone()));
            t.insert("dir".into(), toml::Value::String(dir.display().to_string()));
            toml::Value::Table(t)
        })
        .collect();
    doc.insert("static_dirs".into(), toml::Value::Array(static_dirs));

    let toml_str = toml::to_string_pretty(&doc)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    // Atomic write: write to temp file then rename
    let tmp_path = config_path.with_extension("toml.tmp");
    tokio::fs::write(&tmp_path, toml_str.as_bytes())
        .await
        .map_err(|e| format!("Failed to write temp config: {}", e))?;
    tokio::fs::rename(&tmp_path, config_path)
        .await
        .map_err(|e| format!("Failed to rename config: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_persist_config_writes_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut targets = HashMap::new();
        targets.insert("a.com".to_string(), "1.2.3.4:80".parse::<SocketAddr>().unwrap());
        let config = RuntimeConfig {
            targets,
            static_dirs: HashMap::new(),
        };
        persist_config(&config, &path).await.unwrap();
        let contents = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(contents.contains("a.com"));
        assert!(contents.contains("1.2.3.4:80"));
    }
}
```

- [ ] **Step 3: Update admin/mod.rs**

```rust
pub mod auth;
pub mod persist;
pub mod response;
```

- [ ] **Step 4: Run tests**

Run: `cargo test --lib admin`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/admin/response.rs src/admin/persist.rs src/admin/mod.rs
git commit -m "feat(admin): add JSON response helpers and config persistence"
```

---

### Task 8: Targets CRUD API Handlers

**Files:**
- Create: `src/admin/api_targets.rs`
- Modify: `src/admin/mod.rs`

- [ ] **Step 1: Create api_targets.rs**

Create `src/admin/api_targets.rs`:

```rust
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{Error, Request, Response, StatusCode};

use crate::admin::persist::persist_config;
use crate::admin::response::{json_err, json_ok};
use crate::config::types::SharedConfig;

use std::path::PathBuf;

pub fn list_targets(config: &SharedConfig) -> Response<BoxBody<Bytes, Error>> {
    let cfg = config.read().unwrap();
    let targets: Vec<serde_json::Value> = cfg
        .targets
        .iter()
        .map(|(host, addr)| serde_json::json!({"host": host, "address": addr.to_string()}))
        .collect();
    json_ok(&targets)
}

pub async fn add_target(
    body: Bytes,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let host = match parsed.get("host").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() && !h.contains(char::is_whitespace) => h.to_string(),
        _ => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'host'"),
    };

    let address = match parsed
        .get("address")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(a) => a,
        None => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'address' (expected ip:port)"),
    };

    {
        let mut cfg = config.write().unwrap();
        if cfg.targets.contains_key(&host) {
            return json_err(StatusCode::CONFLICT, &format!("Target '{}' already exists", host));
        }
        cfg.targets.insert(host.clone(), address);
    }

    // Persist after releasing lock
    if let Some(path) = config_path {
        let cfg_clone = {
            let cfg = config.read().unwrap();
            crate::config::types::RuntimeConfig {
                targets: cfg.targets.clone(),
                static_dirs: cfg.static_dirs.clone(),
            }
        };
        if let Err(e) = persist_config(&cfg_clone, path).await {
            tracing::error!("Failed to persist config: {}", e);
        }
    }

    json_ok(&serde_json::json!({"host": host, "address": address.to_string()}))
}

pub async fn update_target(
    host: &str,
    body: Bytes,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return json_err(StatusCode::BAD_REQUEST, "Invalid JSON"),
    };

    let address = match parsed
        .get("address")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
    {
        Some(a) => a,
        None => return json_err(StatusCode::BAD_REQUEST, "Invalid or missing 'address'"),
    };

    {
        let mut cfg = config.write().unwrap();
        if !cfg.targets.contains_key(host) {
            return json_err(StatusCode::NOT_FOUND, &format!("Target '{}' not found", host));
        }
        cfg.targets.insert(host.to_string(), address);
    }

    if let Some(path) = config_path {
        let cfg_clone = {
            let cfg = config.read().unwrap();
            crate::config::types::RuntimeConfig {
                targets: cfg.targets.clone(),
                static_dirs: cfg.static_dirs.clone(),
            }
        };
        if let Err(e) = persist_config(&cfg_clone, path).await {
            tracing::error!("Failed to persist config: {}", e);
        }
    }

    json_ok(&serde_json::json!({"host": host, "address": address.to_string()}))
}

pub async fn delete_target(
    host: &str,
    config: &SharedConfig,
    config_path: Option<&PathBuf>,
) -> Response<BoxBody<Bytes, Error>> {
    {
        let mut cfg = config.write().unwrap();
        if cfg.targets.remove(host).is_none() {
            return json_err(StatusCode::NOT_FOUND, &format!("Target '{}' not found", host));
        }
    }

    if let Some(path) = config_path {
        let cfg_clone = {
            let cfg = config.read().unwrap();
            crate::config::types::RuntimeConfig {
                targets: cfg.targets.clone(),
                static_dirs: cfg.static_dirs.clone(),
            }
        };
        if let Err(e) = persist_config(&cfg_clone, path).await {
            tracing::error!("Failed to persist config: {}", e);
        }
    }

    json_ok(&serde_json::json!({"deleted": host}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};
    use crate::config::types::RuntimeConfig;
    use std::collections::HashMap;

    fn make_config() -> SharedConfig {
        Arc::new(RwLock::new(RuntimeConfig {
            targets: HashMap::new(),
            static_dirs: HashMap::new(),
        }))
    }

    #[test]
    fn test_list_targets_empty() {
        let config = make_config();
        let resp = list_targets(&config);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_list_targets_with_entries() {
        let config = make_config();
        config.write().unwrap().targets.insert(
            "example.com".to_string(),
            "127.0.0.1:8080".parse().unwrap(),
        );
        let resp = list_targets(&config);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_add_target() {
        let config = make_config();
        let body = Bytes::from(r#"{"host":"a.com","address":"1.2.3.4:80"}"#);
        let resp = add_target(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(config.read().unwrap().targets.contains_key("a.com"));
    }

    #[tokio::test]
    async fn test_add_duplicate_target() {
        let config = make_config();
        let body = Bytes::from(r#"{"host":"a.com","address":"1.2.3.4:80"}"#);
        add_target(body.clone(), &config, None).await;
        let resp = add_target(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_add_target_invalid_json() {
        let config = make_config();
        let body = Bytes::from("not json");
        let resp = add_target(body, &config, None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_target() {
        let config = make_config();
        config.write().unwrap().targets.insert(
            "a.com".to_string(),
            "1.2.3.4:80".parse().unwrap(),
        );
        let resp = delete_target("a.com", &config, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!config.read().unwrap().targets.contains_key("a.com"));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_target() {
        let config = make_config();
        let resp = delete_target("nope.com", &config, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
```

- [ ] **Step 2: Add to admin/mod.rs**

Add `pub mod api_targets;` to `src/admin/mod.rs`.

- [ ] **Step 3: Run tests**

Run: `cargo test --lib admin::api_targets::tests`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/admin/api_targets.rs src/admin/mod.rs
git commit -m "feat(admin): add targets CRUD API handlers"
```

---

### Task 9: Static Dirs CRUD API Handlers

**Files:**
- Create: `src/admin/api_static_dirs.rs`
- Modify: `src/admin/mod.rs`

This follows the same pattern as Task 8 but for static dirs. Key difference: validates that `dir` is an absolute path to an existing directory, canonicalizes it, and rejects sensitive paths (`/`, `/etc`, `/proc`, `/sys`).

- [ ] **Step 1: Create api_static_dirs.rs with handlers and tests**

Create `src/admin/api_static_dirs.rs` following the same pattern as `api_targets.rs` but:
- `list_static_dirs` returns `{"host": ..., "dir": ...}` objects
- `add_static_dir` validates: host non-empty, dir is absolute, dir exists, canonicalized dir not in blocklist
- `update_static_dir` and `delete_static_dir` follow same pattern

Include validation function:
```rust
fn validate_static_dir(dir: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(dir);
    if !path.is_absolute() {
        return Err("dir must be an absolute path".to_string());
    }
    let canonical = path.canonicalize().map_err(|e| format!("Cannot access dir '{}': {}", dir, e))?;
    let canonical_str = canonical.to_string_lossy();
    if canonical_str == "/" {
        return Err("Cannot serve root directory".to_string());
    }
    for b in ["/etc", "/proc", "/sys", "/dev"] {
        if canonical_str == b || canonical_str.starts_with(&format!("{}/", b)) {
            return Err(format!("Cannot serve sensitive directory '{}'", canonical_str));
        }
    }
    Ok(canonical)
}
```

Include tests: list empty, add valid, add invalid path, add duplicate, delete, delete nonexistent.

- [ ] **Step 2: Add to mod.rs, run tests, commit**

Run: `cargo test --lib admin::api_static_dirs::tests`

```bash
git add src/admin/api_static_dirs.rs src/admin/mod.rs
git commit -m "feat(admin): add static dirs CRUD API handlers"
```

---

### Task 10: Stats and Certs API Handlers

**Files:**
- Create: `src/admin/api_stats.rs`
- Create: `src/admin/api_certs.rs`
- Modify: `src/admin/mod.rs`

- [ ] **Step 1: Create api_stats.rs**

Returns JSON from the `Arc<Stats>` using `Ordering::Relaxed` reads.

```rust
use std::sync::atomic::Ordering;
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes};
use hyper::{Error, Response};

use crate::admin::response::json_ok;
use crate::stats::Stats;

pub fn get_stats(stats: &Arc<Stats>) -> Response<BoxBody<Bytes, Error>> {
    let per_host: std::collections::HashMap<String, u64> = stats
        .per_host_requests
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
        .collect();

    json_ok(&serde_json::json!({
        "active_connections": stats.active_connections.load(Ordering::Relaxed),
        "total_requests": stats.total_requests.load(Ordering::Relaxed),
        "total_errors": stats.total_errors.load(Ordering::Relaxed),
        "bytes_sent": stats.bytes_sent.load(Ordering::Relaxed),
        "bytes_received": stats.bytes_received.load(Ordering::Relaxed),
        "per_host_requests": per_host,
    }))
}
```

- [ ] **Step 2: Create api_certs.rs**

```rust
use std::path::Path;
use std::sync::{Arc, RwLock};

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Error, Response, StatusCode};
use rustls::sign::CertifiedKey;

use crate::admin::response::{json_err, json_ok};
use crate::tls::cert::load_certified_key;

pub fn get_cert_info(
    cert_path: &Path,
    key_path: &Path,
) -> Response<BoxBody<Bytes, Error>> {
    // Read cert file and parse expiry
    let cert_bytes = match std::fs::read(cert_path) {
        Ok(b) => b,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot read cert: {}", e)),
    };

    let pem = match x509_parser::pem::parse_x509_pem(&cert_bytes) {
        Ok((_, pem)) => pem,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot parse PEM: {}", e)),
    };

    let cert = match pem.parse_x509() {
        Ok(c) => c,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Cannot parse X509: {}", e)),
    };

    let expiry = cert.validity().not_after.to_datetime();
    let now = time::OffsetDateTime::now_utc();
    let days_until_expiry = (expiry - now).whole_days();

    json_ok(&serde_json::json!({
        "cert_path": cert_path.display().to_string(),
        "key_path": key_path.display().to_string(),
        "expiry": expiry.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
        "days_until_expiry": days_until_expiry,
    }))
}

pub fn reload_certs(
    cert_path: &Path,
    key_path: &Path,
    cert_key: &Arc<RwLock<Arc<CertifiedKey>>>,
) -> Response<BoxBody<Bytes, Error>> {
    match load_certified_key(cert_path, key_path) {
        Ok(new_key) => {
            *cert_key.write().unwrap() = Arc::new(new_key);
            tracing::info!("Certificates reloaded via admin API");
            json_ok(&serde_json::json!({"reloaded": true}))
        }
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Failed to reload certs: {}", e),
        ),
    }
}
```

Note: `x509-parser` uses the `time` crate internally. We may need to add `time` as a direct dependency if not transitively available. Check with `cargo check` and add if needed.

- [ ] **Step 3: Add to mod.rs, run tests, commit**

```bash
git add src/admin/api_stats.rs src/admin/api_certs.rs src/admin/mod.rs
git commit -m "feat(admin): add stats and certs API handlers"
```

---

### Task 11: Speed Test API Handlers

**Files:**
- Create: `src/admin/api_speed_test.rs`
- Modify: `src/admin/mod.rs`

- [ ] **Step 1: Create api_speed_test.rs**

Three endpoints:
- `ping` — returns empty 200
- `download` — streams 10MB of zero-filled bytes using chunked `BoxBody`
- `upload` — reads the incoming body, measures bytes and duration, returns JSON result

Rate limiting: use an `Arc<Mutex<HashSet<String>>>` of active session tokens. Check if the requesting session is already running a test; if so return 429. Add token on start, remove on completion. This provides per-session limiting as specified.

Include tests for ping and the rate limiter logic.

- [ ] **Step 2: Add to mod.rs, run tests, commit**

```bash
git add src/admin/api_speed_test.rs src/admin/mod.rs
git commit -m "feat(admin): add speed test API handlers"
```

---

### Task 12: Admin Router

**Files:**
- Create: `src/admin/router.rs`
- Modify: `src/admin/mod.rs`

- [ ] **Step 1: Create router.rs**

Single function that dispatches based on method + path. Handles body reading, path parameter extraction, auth checking, and frontend asset fallback:

```rust
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{Error, Method, Request, Response, StatusCode};
use rustls::sign::CertifiedKey;

use crate::admin::api_certs;
use crate::admin::api_speed_test;
use crate::admin::api_static_dirs;
use crate::admin::api_stats;
use crate::admin::api_targets;
use crate::admin::assets::serve_asset;
use crate::admin::auth::{
    clear_session_cookie, extract_session_cookie, session_cookie, SessionStore,
};
use crate::admin::response::{json_err, json_ok};
use crate::config::types::SharedConfig;
use crate::stats::Stats;

/// Extract the path segment after a prefix, e.g. "/api/targets/foo.com" -> "foo.com"
fn extract_path_param<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).filter(|s| !s.is_empty())
}

/// Check if request has a valid session cookie.
fn check_auth(req: &Request<Incoming>, store: &SessionStore) -> bool {
    req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .map(|token| store.validate(token))
        .unwrap_or(false)
}

/// Get session token from request cookie.
fn get_session_token(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .map(|s| s.to_string())
}

pub async fn route(
    req: Request<Incoming>,
    session_store: Arc<SessionStore>,
    config: SharedConfig,
    stats: Arc<Stats>,
    admin_user: String,
    admin_pass: String,
    config_path: Option<PathBuf>,
    cert_key: Arc<RwLock<Arc<CertifiedKey>>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    speed_test_active: Arc<AtomicBool>,
) -> Result<Response<BoxBody<Bytes, Error>>, String> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Login doesn't require auth
    if method == Method::POST && path == "/api/login" {
        let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| "Invalid JSON".to_string())?;
        let user = parsed.get("username").and_then(|v| v.as_str()).unwrap_or("");
        let pass = parsed.get("password").and_then(|v| v.as_str()).unwrap_or("");
        if user == admin_user && pass == admin_pass {
            let token = session_store.create_session();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Set-Cookie", session_cookie(&token))
                .header("Content-Type", "application/json")
                .body(
                    http_body_util::Full::new(Bytes::from(r#"{"ok":true,"data":null}"#))
                        .map_err(|e| match e {})
                        .boxed(),
                )
                .unwrap());
        }
        return Ok(json_err(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    // All other /api/* routes require auth
    if path.starts_with("/api/") {
        if !check_auth(&req, &session_store) {
            return Ok(json_err(StatusCode::UNAUTHORIZED, "Unauthorized"));
        }
    }

    match (method, path.as_str()) {
        (Method::POST, "/api/logout") => {
            if let Some(token) = get_session_token(&req) {
                session_store.remove(&token);
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Set-Cookie", clear_session_cookie())
                .body(BoxBody::default())
                .unwrap())
        }

        // Targets CRUD
        (Method::GET, "/api/targets") => Ok(api_targets::list_targets(&config)),
        (Method::POST, "/api/targets") => {
            let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok(api_targets::add_target(body, &config, config_path.as_ref()).await)
        }
        (Method::PUT, p) if p.starts_with("/api/targets/") => {
            let host = extract_path_param(p, "/api/targets/").unwrap_or("");
            let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok(api_targets::update_target(host, body, &config, config_path.as_ref()).await)
        }
        (Method::DELETE, p) if p.starts_with("/api/targets/") => {
            let host = extract_path_param(p, "/api/targets/").unwrap_or("");
            Ok(api_targets::delete_target(host, &config, config_path.as_ref()).await)
        }

        // Static dirs CRUD
        (Method::GET, "/api/static-dirs") => Ok(api_static_dirs::list_static_dirs(&config)),
        (Method::POST, "/api/static-dirs") => {
            let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok(api_static_dirs::add_static_dir(body, &config, config_path.as_ref()).await)
        }
        (Method::PUT, p) if p.starts_with("/api/static-dirs/") => {
            let host = extract_path_param(p, "/api/static-dirs/").unwrap_or("");
            let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok(api_static_dirs::update_static_dir(host, body, &config, config_path.as_ref()).await)
        }
        (Method::DELETE, p) if p.starts_with("/api/static-dirs/") => {
            let host = extract_path_param(p, "/api/static-dirs/").unwrap_or("");
            Ok(api_static_dirs::delete_static_dir(host, &config, config_path.as_ref()).await)
        }

        // Stats & Certs
        (Method::GET, "/api/stats") => Ok(api_stats::get_stats(&stats)),
        (Method::GET, "/api/certs") => {
            Ok(api_certs::get_cert_info(&cert_path, &key_path))
        }
        (Method::POST, "/api/certs/reload") => {
            Ok(api_certs::reload_certs(&cert_path, &key_path, &cert_key))
        }

        // Speed test
        (Method::GET, "/api/speed-test/ping") => {
            Ok(api_speed_test::ping())
        }
        (Method::GET, "/api/speed-test/download") => {
            Ok(api_speed_test::download(&speed_test_active).await)
        }
        (Method::POST, "/api/speed-test/upload") => {
            let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok(api_speed_test::upload(body, &speed_test_active))
        }

        // Frontend assets — serve embedded files, fallback to index.html for SPA
        _ => {
            let asset_path = path.trim_start_matches('/');
            let asset_path = if asset_path.is_empty() { "index.html" } else { asset_path };
            match serve_asset(asset_path) {
                Some((data, mime)) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", mime)
                    .body(
                        http_body_util::Full::new(Bytes::from(data))
                            .map_err(|e| match e {})
                            .boxed(),
                    )
                    .unwrap()),
                None => {
                    // SPA fallback: serve index.html for any non-API, non-asset path
                    match serve_asset("index.html") {
                        Some((data, mime)) => Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("Content-Type", mime)
                            .body(
                                http_body_util::Full::new(Bytes::from(data))
                                    .map_err(|e| match e {})
                                    .boxed(),
                            )
                            .unwrap()),
                        None => Ok(json_err(
                            StatusCode::NOT_FOUND,
                            "Frontend not built. Run: cd admin-ui && npm run build",
                        )),
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Add to mod.rs, run cargo check**

- [ ] **Step 3: Commit**

```bash
git add src/admin/router.rs src/admin/mod.rs
git commit -m "feat(admin): add request router with auth middleware"
```

---

### Task 13: Embedded Frontend Assets

**Files:**
- Create: `src/admin/assets.rs`
- Modify: `src/admin/mod.rs`

- [ ] **Step 1: Create assets.rs**

```rust
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "admin-ui/dist/"]
pub struct AdminAssets;

pub fn serve_asset(path: &str) -> Option<(Vec<u8>, &'static str)> {
    let file = AdminAssets::get(path).or_else(|| AdminAssets::get("index.html"))?;
    let mime = match path.rsplit('.').next() {
        Some("html") => "text/html",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    Some((file.data.to_vec(), mime))
}
```

- [ ] **Step 2: Create placeholder admin-ui/dist/index.html (not committed — gitignored)**

```bash
mkdir -p admin-ui/dist
echo '<html><body>Frontend not built. Run: cd admin-ui && npm run build</body></html>' > admin-ui/dist/index.html
```

This placeholder is only for local development so `cargo check` succeeds with `rust-embed`. It is not committed to git.

- [ ] **Step 3: Add to mod.rs, add .gitignore entries, run cargo check, commit**

Add to `.gitignore`:
```
admin-ui/node_modules/
admin-ui/dist/
.superpowers/
```

```bash
git add src/admin/assets.rs src/admin/mod.rs .gitignore
git commit -m "feat(admin): add embedded frontend asset serving"
```

---

### Task 14: Admin Server (TLS Listener)

**Files:**
- Create: `src/admin/server.rs`
- Modify: `src/admin/mod.rs`
- Modify: `src/main.rs` (spawn admin server)

- [ ] **Step 1: Create server.rs**

Similar to `proxy/server.rs` but calls the admin router. Binds its own TLS listener, spawns session cleanup task.

```rust
pub async fn run_admin_server(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    config: SharedConfig,
    stats: Arc<Stats>,
    admin_user: String,
    admin_pass: String,
    config_path: Option<PathBuf>,
    cert_key: Arc<RwLock<Arc<CertifiedKey>>>,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_store = Arc::new(SessionStore::new(Duration::from_secs(1800)));
    let speed_test_active: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Admin server listening on {}", addr);

    // Session cleanup task
    let cleanup_store = Arc::clone(&session_store);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            cleanup_store.cleanup_expired();
        }
    });

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        // TLS handshake, then serve with admin router
        // ... (similar to proxy/server.rs but using route())
    }
}
```

- [ ] **Step 2: Update main.rs to spawn admin server**

After the cert watcher spawn (line 57), add:

```rust
    if let Some(admin_addr) = resolved.admin_addr {
        let admin_user = resolved.admin_user.unwrap();
        let admin_pass = resolved.admin_pass.unwrap();
        tokio::spawn(admin::server::run_admin_server(
            admin_addr,
            acceptor.clone(),
            shared_config.clone(),
            stats.clone(),
            admin_user,
            admin_pass,
            resolved.config_file,
            Arc::clone(&certified_key),
            resolved.cert.clone(),
            resolved.key.clone(),
        ));
    }
```

- [ ] **Step 3: Run cargo check, verify compilation**

Run: `cargo check`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add src/admin/server.rs src/admin/mod.rs src/main.rs
git commit -m "feat(admin): add admin TLS server with session cleanup"
```

---

### Task 15: Frontend — Project Scaffold

**Files:**
- Create: `admin-ui/package.json`
- Create: `admin-ui/tsconfig.json`
- Create: `admin-ui/tailwind.config.ts`
- Create: `admin-ui/vite.config.ts`
- Create: `admin-ui/index.html`
- Create: `admin-ui/src/main.tsx`
- Create: `admin-ui/src/styles/main.css`

- [ ] **Step 1: Initialize project**

```bash
cd admin-ui
npm create vite@latest . -- --template react-ts
npm install
npm install @reduxjs/toolkit react-redux react-router-dom
npm install -D tailwindcss @tailwindcss/vite
```

- [ ] **Step 2: Configure Tailwind**

In `admin-ui/src/styles/main.css`:
```css
@import "tailwindcss";
```

In `admin-ui/vite.config.ts`:
```ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: 'dist' },
})
```

- [ ] **Step 3: Verify build works**

```bash
cd admin-ui && npm run build
```

Expected: produces `admin-ui/dist/` with index.html

- [ ] **Step 4: Verify .gitignore already covers admin-ui/dist/ and node_modules/**

These were added in Task 13. Verify with `cat .gitignore`.

- [ ] **Step 5: Commit**

```bash
git add admin-ui/ .gitignore
git commit -m "feat(admin): scaffold React + TypeScript + Tailwind frontend"
```

---

### Task 16: Frontend — Redux Store and API Layer

**Files:**
- Create: `admin-ui/src/store/index.ts`
- Create: `admin-ui/src/store/authSlice.ts`
- Create: `admin-ui/src/store/targetsSlice.ts`
- Create: `admin-ui/src/store/staticDirsSlice.ts`
- Create: `admin-ui/src/store/statsSlice.ts`
- Create: `admin-ui/src/store/certsSlice.ts`
- Create: `admin-ui/src/store/speedTestSlice.ts`
- Create: `admin-ui/src/api.ts`

- [ ] **Step 1: Create api.ts with fetch wrappers**

Each function calls `fetch('/api/...')`, checks response, returns parsed JSON or throws.

- [ ] **Step 2: Create Redux slices**

Each slice uses `createAsyncThunk` to call the API and stores the result. `authSlice` handles login/logout and stores auth status.

- [ ] **Step 3: Create store/index.ts**

Combines all slices with `configureStore`.

- [ ] **Step 4: Build and verify**

```bash
cd admin-ui && npm run build
```

- [ ] **Step 5: Commit**

```bash
git add admin-ui/src/
git commit -m "feat(admin): add Redux store and API layer"
```

---

### Task 17: Frontend — Layout Components

**Files:**
- Create: `admin-ui/src/App.tsx`
- Create: `admin-ui/src/components/Sidebar.tsx`
- Create: `admin-ui/src/components/BottomTabs.tsx`
- Create: `admin-ui/src/components/StatsCard.tsx`
- Create: `admin-ui/src/components/DataTable.tsx`
- Create: `admin-ui/src/components/Modal.tsx`

- [ ] **Step 1: Create App.tsx with HashRouter**

Routes: `/login`, `/`, `/targets`, `/static-dirs`, `/certs`, `/speed-test`. Protected routes redirect to `/login` if not authenticated.

- [ ] **Step 2: Create Sidebar.tsx**

Icon sidebar for desktop (hidden on mobile via `hidden md:flex`). Icons for Dashboard, Targets, Static Dirs, Certs, Speed Test.

- [ ] **Step 3: Create BottomTabs.tsx**

Bottom tab bar for mobile (visible below md breakpoint via `flex md:hidden`).

- [ ] **Step 4: Create shared components**

`StatsCard`, `DataTable`, `Modal` — reusable across pages.

- [ ] **Step 5: Build and verify**

```bash
cd admin-ui && npm run build
```

- [ ] **Step 6: Commit**

```bash
git add admin-ui/src/
git commit -m "feat(admin): add layout components with responsive sidebar/tabs"
```

---

### Task 18: Frontend — Login Page

**Files:**
- Create: `admin-ui/src/pages/Login.tsx`

- [ ] **Step 1: Create Login.tsx**

Split panel design: branded gradient left (`bg-gradient-to-br from-blue-600 to-purple-700`), form right. Stacks vertically on mobile (`flex-col md:flex-row`). Dispatches `loginThunk`, redirects to `/` on success.

- [ ] **Step 2: Build, verify, commit**

```bash
cd admin-ui && npm run build
git add admin-ui/src/pages/Login.tsx
git commit -m "feat(admin): add login page with split panel design"
```

---

### Task 19: Frontend — Dashboard Page

**Files:**
- Create: `admin-ui/src/pages/Dashboard.tsx`

- [ ] **Step 1: Create Dashboard.tsx**

Fetches stats on mount (polling every 5s). Displays StatsCards for active connections, total requests, errors, cert expiry. Summary tables for targets and static dirs.

- [ ] **Step 2: Build, verify, commit**

```bash
cd admin-ui && npm run build
git add admin-ui/src/pages/Dashboard.tsx
git commit -m "feat(admin): add dashboard page with stats polling"
```

---

### Task 20: Frontend — Targets and Static Dirs Pages

**Files:**
- Create: `admin-ui/src/pages/Targets.tsx`
- Create: `admin-ui/src/pages/StaticDirs.tsx`

- [ ] **Step 1: Create Targets.tsx**

Uses DataTable component. Add button opens Modal for new target (host + address fields). Edit/delete buttons on each row. Dispatches CRUD thunks.

- [ ] **Step 2: Create StaticDirs.tsx**

Same pattern, fields are host + dir.

- [ ] **Step 3: Build, verify, commit**

```bash
cd admin-ui && npm run build
git add admin-ui/src/pages/
git commit -m "feat(admin): add targets and static dirs management pages"
```

---

### Task 21: Frontend — Certs and Speed Test Pages

**Files:**
- Create: `admin-ui/src/pages/Certs.tsx`
- Create: `admin-ui/src/pages/SpeedTest.tsx`

- [ ] **Step 1: Create Certs.tsx**

Displays cert path, expiry date, days until expiry (color-coded). Reload button triggers POST to `/api/certs/reload`.

- [ ] **Step 2: Create SpeedTest.tsx**

"Run Test" button that sequentially runs ping, download, upload. Progress indicators during each phase. Results displayed as Mbps with latency in ms.

- [ ] **Step 3: Build, verify, commit**

```bash
cd admin-ui && npm run build
git add admin-ui/src/pages/
git commit -m "feat(admin): add certs and speed test pages"
```

---

### Task 22: Integration — Build Frontend and Embed

**Files:**
- Modify: `admin-ui/dist/` (rebuilt)
- Modify: `.gitignore`

- [ ] **Step 1: Build the frontend**

```bash
cd admin-ui && npm run build
```

- [ ] **Step 2: Verify full Rust build with embedded frontend**

```bash
cargo build
```
Expected: compiles with embedded frontend

- [ ] **Step 3: Run all Rust tests**

```bash
cargo test
```
Expected: all pass

- [ ] **Step 4: Run clippy**

```bash
cargo clippy
```
Expected: no warnings

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(admin): complete management service with embedded React frontend"
```

---

### Task 23: Manual Integration Test

- [ ] **Step 1: Generate test certs**

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -nodes -subj '/CN=localhost'
```

- [ ] **Step 2: Start anproxy with admin service**

```bash
cargo run -- 0.0.0.0:8443 \
  -t example.com@127.0.0.1:8080 \
  -c /tmp/cert.pem -k /tmp/key.pem \
  --admin-addr 127.0.0.1:9090 \
  --admin-user admin \
  --admin-pass secret
```

- [ ] **Step 3: Verify management UI**

Open `https://localhost:9090` in browser. Login with admin/secret. Verify:
- Dashboard shows stats
- Can add/remove targets
- Can add/remove static dirs
- Cert info displays
- Speed test runs
- Responsive layout works on mobile viewport

- [ ] **Step 4: Verify config persistence**

Add a target via UI, restart anproxy with a config file, verify the target persists.
