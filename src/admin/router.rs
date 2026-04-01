use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Error, Method, Request, Response, StatusCode};
use rustls::sign::CertifiedKey;

use crate::admin::api_certs;
use crate::admin::api_speed_test::{self, SpeedTestLimiter};
use crate::admin::api_static_dirs;
use crate::admin::api_stats;
use crate::admin::api_targets;
use crate::admin::assets::serve_asset;
use crate::admin::auth::{
    clear_session_cookie, extract_session_cookie, session_cookie, SessionStore,
};
use crate::admin::response::json_err;
use crate::config::types::SharedConfig;
use crate::stats::Stats;

/// TLS-specific context for admin server
pub struct TlsContext {
    pub cert_key: Arc<RwLock<Arc<CertifiedKey>>>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl Clone for TlsContext {
    fn clone(&self) -> Self {
        Self {
            cert_key: Arc::clone(&self.cert_key),
            cert_path: self.cert_path.clone(),
            key_path: self.key_path.clone(),
        }
    }
}

fn extract_path_param<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).filter(|s| !s.is_empty())
}

fn check_auth(req: &Request<Incoming>, store: &SessionStore) -> bool {
    req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .map(|token| store.validate(token))
        .unwrap_or(false)
}

fn get_session_token(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_session_cookie)
        .map(|s| s.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn route(
    req: Request<Incoming>,
    session_store: Arc<SessionStore>,
    config: SharedConfig,
    stats: Arc<Stats>,
    admin_user: String,
    admin_pass: String,
    config_path: Option<PathBuf>,
    tls_context: Option<TlsContext>,
    speed_test_limiter: Arc<SpeedTestLimiter>,
    proxy_port: u16,
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
                    Full::new(Bytes::from(r#"{"ok":true,"data":null}"#))
                        .map_err(|e| match e {})
                        .boxed(),
                )
                .unwrap());
        }
        return Ok(json_err(StatusCode::UNAUTHORIZED, "Invalid credentials"));
    }

    // All other /api/* routes require auth
    if path.starts_with("/api/") && !check_auth(&req, &session_store) {
        return Ok(json_err(StatusCode::UNAUTHORIZED, "Unauthorized"));
    }

    let session_token = get_session_token(&req);

    match (method, path.as_str()) {
        (Method::POST, "/api/logout") => {
            if let Some(ref token) = session_token {
                session_store.remove(token);
            }
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Set-Cookie", clear_session_cookie())
                .header("Content-Type", "application/json")
                .body(
                    Full::new(Bytes::from(r#"{"ok":true,"data":null}"#))
                        .map_err(|e| match e {})
                        .boxed(),
                )
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
        (Method::GET, "/api/stats") => Ok(api_stats::get_stats(&stats, proxy_port)),
        (Method::GET, "/api/certs") => {
            if let Some(ref ctx) = tls_context {
                Ok(api_certs::get_cert_info(&ctx.cert_path, &ctx.key_path))
            } else {
                Ok(json_err(StatusCode::SERVICE_UNAVAILABLE, "TLS not enabled in this mode"))
            }
        }
        (Method::POST, "/api/certs/reload") => {
            if let Some(ref ctx) = tls_context {
                Ok(api_certs::reload_certs(&ctx.cert_path, &ctx.key_path, &ctx.cert_key))
            } else {
                Ok(json_err(StatusCode::SERVICE_UNAVAILABLE, "TLS not enabled in this mode"))
            }
        }

        // Speed test
        (Method::GET, "/api/speed-test/ping") => Ok(api_speed_test::ping()),
        (Method::GET, "/api/speed-test/download") => {
            Ok(api_speed_test::download(session_token.as_deref(), &speed_test_limiter).await)
        }
        (Method::POST, "/api/speed-test/upload") => {
            let start = Instant::now();
            let body = req.collect().await.map_err(|e| e.to_string())?.to_bytes();
            Ok(api_speed_test::upload(
                body,
                session_token.as_deref(),
                &speed_test_limiter,
                start,
            ))
        }

        // Frontend assets — serve embedded files, fallback to index.html for SPA
        _ => {
            let asset_path = path.trim_start_matches('/');
            let asset_path = if asset_path.is_empty() {
                "index.html"
            } else {
                asset_path
            };
            match serve_asset(asset_path) {
                Some((data, mime)) => Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", mime)
                    .body(
                        Full::new(Bytes::from(data))
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
