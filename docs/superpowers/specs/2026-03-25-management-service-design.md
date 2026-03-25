# Management Service Design

An embedded management service for anproxy that allows live routing configuration, monitoring, certificate management, and network speed testing through a web UI.

## 1. Runtime Config — Mutable Routing

Replace immutable `Arc<HashMap<...>>` with shared mutable state:

```rust
pub struct RuntimeConfig {
    pub targets: HashMap<String, SocketAddr>,
    pub static_dirs: HashMap<String, PathBuf>,
}

type SharedConfig = Arc<RwLock<RuntimeConfig>>;
```

- Proxy reads: `config.read()` per request for host lookup. RwLock readers don't block each other.
- Management writes: `config.write()` to mutate. Briefly blocks readers; writes are infrequent.
- Persistence: After every write, serialize current config back to the TOML config file. If no config file was specified, skip persistence with a warning.

## 2. Management HTTP Server

A second Hyper HTTP/1.1 server on a separate TLS port, reusing the same cert/key and `DynamicCertResolver`.

### CLI/Config Additions

- `--admin-addr` — bind address (optional; management disabled if omitted)
- `--admin-user` / `--admin-pass` — credentials (required if admin-addr is set)
- Corresponding TOML config fields

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

### Authentication

- Session-based with a login page
- In-memory `HashMap<String, Session>` behind `Mutex`
- Session tokens: random 32-byte hex strings
- Cookie-based session tracking
- Every `/api/*` request (except `/api/login`) requires valid session cookie; 401 otherwise
- Sessions expire after 30 min idle timeout

## 3. Monitoring & Stats

```rust
pub struct Stats {
    pub active_connections: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub per_host_requests: Mutex<HashMap<String, u64>>,
}
```

- `Arc<Stats>` shared with proxy handlers
- Atomic counters for hot-path metrics
- `per_host_requests` behind Mutex (low contention, one update per request)
- Stats are ephemeral (reset on restart)

### Certificate Info

- `GET /api/certs` returns: file path, last reload time, expiry date, days until expiry
- Parses PEM to extract expiry (via `x509-parser` or similar)

## 4. Speed Test

Bidirectional network speed testing:

- **Ping:** `GET /api/speed-test/ping` — empty 200 for round-trip latency
- **Download:** `GET /api/speed-test/download` — server streams ~10MB of random bytes
- **Upload:** `POST /api/speed-test/upload` — client sends blob, server measures throughput
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
- `config/types.rs` — add admin fields to `Config` and `ResolvedConfig`
- `config/loader.rs` — merge admin config fields
- `proxy/handler.rs` — accept `SharedConfig` instead of `Arc<HashMap>`, increment stats
- `proxy/server.rs` — pass `SharedConfig` and `Arc<Stats>`

## 7. New Dependencies

- `rust-embed` — embed frontend dist at compile time
- `x509-parser` — parse cert expiry from PEM
- `rand` — generate session tokens and speed test data
- `serde_json` — JSON serialization for API responses
