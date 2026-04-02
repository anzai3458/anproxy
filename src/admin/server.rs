use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::admin::api_speed_test;
use crate::admin::auth::SessionStore;
use crate::config::types::SharedConfig;
use crate::log_buffer::LogBufferHandle;
use crate::stats::Stats;
use crate::system_metrics::SystemMetrics;

/// Admin context that holds all dependencies for the admin server
#[derive(Clone)]
pub struct AdminContext {
    pub config: SharedConfig,
    pub stats: Arc<Stats>,
    pub session_store: Arc<SessionStore>,
    pub speed_test_limiter: Arc<api_speed_test::SpeedTestLimiter>,
    pub admin_user: String,
    pub admin_pass: String,
    pub config_path: Option<PathBuf>,
    pub proxy_port: u16,
    pub system_metrics: Arc<SystemMetrics>,
    pub log_buffer: LogBufferHandle,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_admin_server(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    config: SharedConfig,
    stats: Arc<Stats>,
    admin_user: String,
    admin_pass: String,
    config_path: Option<PathBuf>,
    cert_key: std::sync::Arc<std::sync::RwLock<std::sync::Arc<rustls::sign::CertifiedKey>>>,
    cert_path: PathBuf,
    key_path: PathBuf,
    proxy_port: u16,
    system_metrics: Arc<SystemMetrics>,
    log_buffer: LogBufferHandle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_store = Arc::new(SessionStore::new(Duration::from_secs(1800)));
    let speed_test_limiter = Arc::new(api_speed_test::new_limiter());

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Admin server listening on https://{}", addr);

    // Session cleanup task — runs every 5 minutes
    let cleanup_store = Arc::clone(&session_store);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            cleanup_store.cleanup_expired();
        }
    });

    let tls_context = crate::admin::router::TlsContext {
        cert_key,
        cert_path,
        key_path,
    };

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let session_store = Arc::clone(&session_store);
        let config = config.clone();
        let stats = Arc::clone(&stats);
        let admin_user = admin_user.clone();
        let admin_pass = admin_pass.clone();
        let config_path = config_path.clone();
        let tls_context = crate::admin::router::TlsContext {
            cert_key: Arc::clone(&tls_context.cert_key),
            cert_path: tls_context.cert_path.clone(),
            key_path: tls_context.key_path.clone(),
        };
        let speed_test_limiter = Arc::clone(&speed_test_limiter);
        let system_metrics = Arc::clone(&system_metrics);
        let log_buffer = log_buffer.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("Admin TLS accept failed: {:?}", e);
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);

            let ctx = AdminContext {
                session_store,
                config,
                stats,
                admin_user,
                admin_pass,
                config_path,
                speed_test_limiter,
                proxy_port,
                system_metrics: Arc::clone(&system_metrics),
                log_buffer: log_buffer.clone(),
            };

            let service = service_fn(move |req| {
                let ctx = ctx.clone();
                let tls_context = tls_context.clone();
                async move {
                    crate::admin::router::route(
                        req,
                        ctx.session_store,
                        ctx.config,
                        ctx.stats,
                        ctx.admin_user,
                        ctx.admin_pass,
                        ctx.config_path,
                        Some(tls_context),
                        ctx.speed_test_limiter,
                        ctx.proxy_port,
                        ctx.system_metrics,
                        ctx.log_buffer,
                    )
                    .await
                }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("Admin connection closed: {:?}", err);
            }
        });
    }
}

/// Run admin server in plain HTTP mode (for --no-tls)
#[allow(clippy::too_many_arguments)]
pub async fn run_admin_server_plain(
    addr: SocketAddr,
    config: SharedConfig,
    stats: Arc<Stats>,
    admin_user: String,
    admin_pass: String,
    config_path: Option<PathBuf>,
    proxy_port: u16,
    system_metrics: Arc<SystemMetrics>,
    log_buffer: LogBufferHandle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_store = Arc::new(SessionStore::new(Duration::from_secs(1800)));
    let speed_test_limiter = Arc::new(api_speed_test::new_limiter());

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Admin server listening on http://{} (plain HTTP, no TLS)", addr);

    // Session cleanup task — runs every 5 minutes
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
        let session_store = Arc::clone(&session_store);
        let config = config.clone();
        let stats = Arc::clone(&stats);
        let admin_user = admin_user.clone();
        let admin_pass = admin_pass.clone();
        let config_path = config_path.clone();
        let speed_test_limiter = Arc::clone(&speed_test_limiter);
        let system_metrics = Arc::clone(&system_metrics);
        let log_buffer = log_buffer.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let ctx = AdminContext {
                session_store,
                config,
                stats,
                admin_user,
                admin_pass,
                config_path,
                speed_test_limiter,
                proxy_port,
                system_metrics: Arc::clone(&system_metrics),
                log_buffer: log_buffer.clone(),
            };

            let service = service_fn(move |req| {
                let ctx = ctx.clone();
                async move {
                    crate::admin::router::route(
                        req,
                        ctx.session_store,
                        ctx.config,
                        ctx.stats,
                        ctx.admin_user,
                        ctx.admin_pass,
                        ctx.config_path,
                        None::<crate::admin::router::TlsContext>,
                        ctx.speed_test_limiter,
                        ctx.proxy_port,
                        ctx.system_metrics,
                        ctx.log_buffer,
                    )
                    .await
                }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!("Admin connection closed: {:?}", err);
            }
        });
    }
}
