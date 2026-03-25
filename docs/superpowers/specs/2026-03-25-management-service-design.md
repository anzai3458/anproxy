# Management Service Design

An embedded management service for anproxy that allows live routing configuration, monitoring, certificate management, and network speed testing through a web UI.

## 1. Runtime Config — Mutable Routing

Replace immutable `Arc<HashMap<...>>` with shared mutable state:

```rust
pub struct RuntimeConfig {
    pub targets: HashMap<String, SocketAddr>,
    pub static_dirs: HashMap<String, PathBuf>,
}

type SharedConfig = Arc<std::sync::RwLock<RuntimeConfig>>;
```

- Uses `std::sync::RwLock` (not `tokio::sync::RwLock`) for reader performance — readers never block each other and no `.await` is needed under the read guard.
- Proxy reads: `config.read().unwrap()` per request, clone the needed value, then drop the guard before any `.await`.
- Management writes: acquire write guard, mutate the HashMap, clone the full config for persistence, then drop the guard. Persistence (async file I/O) happens **after** releasing the lock.
- Persistence: after every write, serialize config to a temp file then atomically rename over the TOML config file. If no config file was specified at startup, log a warning and skip persistence. If the file write fails, log the error but keep the in-memory change (the file is best-effort persistence).

## 2. Management HTTP Server

A second Hyper HTTP/1.1 server on a separate TLS port, reusing the same cert/key and `DynamicCertResolver`.

### CLI/Config Additions

- `--admin-addr` — bind address (optional; management disabled if omitted)
- `--admin-user` / `--admin-pass` — credentials (required if admin-addr is set; validated at startup, exits with error if one is set without the other)
- Corresponding TOML config fields (with `serde(default)` so existing config files continue to parse)
- Credentials are compared as plaintext strings in memory. Acceptable for a local admin tool over TLS; the spec explicitly acknowledges this tradeoff.

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Serve SPA frontend |
| POST | `/api/login` | Authenticate, create session, set cookie |
| POST | `/api/logout` | Destroy session |
| GET | `/api/targets` | List proxy targets |
| POST | `/api/targets` | Add a target |
| PUT | `/api/targets/:host` | Modify a target |
| DELETE | `/api/targets/:host` | Remove a target |
| GET | `/api/static-dirs` | List static dir mappings |
| POST | `/api/static-dirs` | Add a static dir |
| PUT | `/api/static-dirs/:host` | Modify a static dir |
| DELETE | `/api/static-dirs/:host` | Remove a static dir |
| GET | `/api/stats` | Connection/request stats |
| GET | `/api/certs` | Cert info (path, expiry, last reload) |
| POST | `/api/certs/reload` | Trigger cert reload |
| GET | `/api/speed-test/ping` | Latency measurement (empty 200) |
| GET | `/api/speed-test/download` | Stream ~10MB for download speed |
| POST | `/api/speed-test/upload` | Receive payload for upload speed |

### API Response Format

All API responses use a consistent JSON envelope:

```json
// Success
{ "ok": true, "data": { ... } }

// Error
{ "ok": false, "error": "Human-readable error message" }
```

**Target object:** `{ "host": "example.com", "address": "10.0.0.1:8080" }`

**Static dir object:** `{ "host": "static.example.com", "dir": "/var/www/html" }`

**Stats object:** `{ "active_connections": 42, "total_requests": 12400, "total_errors": 3, "bytes_sent": 1048576, "bytes_received": 524288, "per_host_requests": { "example.com": 500 } }`

**Cert object:** `{ "cert_path": "/path/to/cert.pem", "key_path": "/path/to/key.pem", "last_reload": "2026-03-25T10:00:00Z", "expiry": "2026-06-25T00:00:00Z", "days_until_expiry": 92 }`

### Input Validation

- **Targets:** `host` must be a non-empty valid hostname (no whitespace, no port). `address` must parse as a valid `SocketAddr`. Duplicates rejected (409 Conflict).
- **Static dirs:** `host` must be a non-empty valid hostname. `dir` must be an absolute path to an existing directory. Paths are canonicalized and must not escape to sensitive system directories (reject if canonicalized path is `/`, `/etc`, `/proc`, `/sys`, or similar).
- Invalid input returns 400 with descriptive error message.

### Authentication

- Session-based with a login page
- In-memory `HashMap<String, Session>` behind `Mutex`
- Session tokens: random 32-byte hex strings
- Cookie-based session tracking: `Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/`
- `SameSite=Strict` mitigates CSRF. `HttpOnly` prevents JS access to the cookie. `Secure` ensures TLS-only.
- Every `/api/*` request (except `/api/login`) requires valid session cookie; 401 otherwise
- Sessions expire after 30 min idle timeout
- **Session cleanup:** a background task runs every 5 minutes and removes expired sessions from the map

## 3. Monitoring & Stats

```rust
pub struct Stats {
    pub active_connections: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub per_host_requests: DashMap<String, AtomicU64>,
}
```

- `Arc<Stats>` shared with proxy handlers
- Atomic counters for hot-path metrics (no locking)
- `per_host_requests` uses `DashMap` for lock-free concurrent updates (sharded internally)
- Stats are ephemeral (reset on restart)

### Certificate Info

- `GET /api/certs` returns: file path, last reload time, expiry date, days until expiry
- Parses PEM to extract expiry (via `x509-parser`)

## 4. Speed Test

Bidirectional network speed testing:

- **Ping:** `GET /api/speed-test/ping` — empty 200 for round-trip latency
- **Download:** `GET /api/speed-test/download` — server streams ~10MB from a pre-allocated zero-filled buffer (not cryptographic random; avoids CPU overhead)
- **Upload:** `POST /api/speed-test/upload` — client sends blob, server measures throughput
- **Rate limiting:** max 1 concurrent speed test per session. Subsequent requests while a test is running return 429 Too Many Requests.
- Frontend measures timing and displays download/upload Mbps plus latency

## 5. Frontend

### Stack

- React 18 + TypeScript
- Redux Toolkit for state management
- Tailwind CSS for styling
- Vite build tool
- React Router (hash-based)

### Project Structure

```
admin-ui/
├── package.json
├── tsconfig.json
├── tailwind.config.ts
├── vite.config.ts
├── index.html
└── src/
    ├── main.tsx
    ├── App.tsx               # Router + layout
    ├── api.ts                # fetch() wrappers
    ├── store/
    │   ├── index.ts          # Redux store
    │   ├── authSlice.ts
    │   ├── targetsSlice.ts
    │   ├── staticDirsSlice.ts
    │   ├── statsSlice.ts
    │   ├── certsSlice.ts
    │   └── speedTestSlice.ts
    ├── pages/
    │   ├── Login.tsx
    │   ├── Dashboard.tsx
    │   ├── Targets.tsx
    │   ├── StaticDirs.tsx
    │   ├── Certs.tsx
    │   └── SpeedTest.tsx
    ├── components/
    │   ├── Sidebar.tsx
    │   ├── BottomTabs.tsx
    │   ├── StatsCard.tsx
    │   ├── DataTable.tsx
    │   └── Modal.tsx
    └── styles/
        └── main.css
```

### Build Integration

- Developer runs `cd admin-ui && npm run build` to produce `admin-ui/dist/`
- `cargo build` then embeds the dist via `rust-embed`
- No `build.rs` auto-trigger — keeps the Rust build fast and avoids requiring Node in CI unless the frontend changed
- CI pipeline: `npm ci && npm run build` step before `cargo build`
- If `admin-ui/dist/` doesn't exist at Rust compile time, `rust-embed` embeds an empty set and the admin server returns a helpful "frontend not built" message

### Embedding

- `rust-embed` crate embeds `admin-ui/dist/` at compile time
- Management server serves embedded files, `index.html` as SPA fallback

### UI Design

- **Login:** Split panel — branded gradient left, form right. Stacks vertically on mobile.
- **Dashboard:** Icon sidebar (desktop) / bottom tab bar (mobile). Stats cards, summary tables.
- **Responsive breakpoint:** 768px. Sidebar → bottom tabs, stats 4-across → 2×2 grid, tables stack vertically.

### Pages

1. **Login** — split panel form
2. **Dashboard** — stats cards + summary tables + cert expiry warning
3. **Targets** — CRUD table with add/edit/delete modals
4. **Static Dirs** — CRUD table with add/edit/delete modals
5. **Certificates** — cert info, reload button, expiry countdown
6. **Speed Test** — download/upload/ping with progress indicators

## 6. Rust Module Layout

### New Modules

```
src/
├── admin/
│   ├── mod.rs              # Submodule declarations
│   ├── server.rs           # TLS listener, accept loop
│   ├── router.rs           # Method + path dispatch
│   ├── auth.rs             # Session management, login/logout, cookies
│   ├── api_targets.rs      # Targets CRUD handlers
│   ├── api_static_dirs.rs  # Static dirs CRUD handlers
│   ├── api_stats.rs        # Stats endpoint
│   ├── api_certs.rs        # Cert info + reload
│   ├── api_speed_test.rs   # Ping, download, upload
│   ├── assets.rs           # Serve embedded frontend (rust-embed)
│   └── persist.rs          # Write RuntimeConfig to TOML
└── stats.rs                # Arc<Stats> shared with proxy
```

### Changes to Existing Modules

- `main.rs` — spawn admin server task, create `SharedConfig` and `Arc<Stats>`
- `cli.rs` — add `--admin-addr`, `--admin-user`, `--admin-pass`
- `config/types.rs` — add admin fields (with `serde(default)`) to `Config` and `ResolvedConfig`
- `config/loader.rs` — merge admin config fields
- `proxy/handler.rs` — change signature to accept `SharedConfig` instead of `Arc<HashMap>`, increment stats counters
- `proxy/server.rs` — change `process()` signature to accept `SharedConfig` and `Arc<Stats>`, pass through to handler
- Any existing tests calling `proxy()` or `process()` updated for new signatures

## 7. New Dependencies

- `rust-embed` — embed frontend dist at compile time
- `x509-parser` — parse cert expiry from PEM
- `rand` — generate session tokens
- `serde_json` — JSON serialization for API responses
- `dashmap` — concurrent HashMap for per-host stats
