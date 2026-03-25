use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::admin::api_speed_test;
use crate::admin::auth::SessionStore;
use crate::admin::router::route;
use crate::config::types::SharedConfig;
use crate::stats::Stats;

#[allow(clippy::too_many_arguments)]
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
    let speed_test_limiter = Arc::new(api_speed_test::new_limiter());

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Admin server listening on {}", addr);

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
        let acceptor = acceptor.clone();
        let session_store = Arc::clone(&session_store);
        let config = config.clone();
        let stats = Arc::clone(&stats);
        let admin_user = admin_user.clone();
        let admin_pass = admin_pass.clone();
        let config_path = config_path.clone();
        let cert_key = Arc::clone(&cert_key);
        let cert_path = cert_path.clone();
        let key_path = key_path.clone();
        let speed_test_limiter = Arc::clone(&speed_test_limiter);

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!("Admin TLS accept failed: {:?}", e);
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);

            let service = service_fn(move |req| {
                let session_store = Arc::clone(&session_store);
                let config = config.clone();
                let stats = Arc::clone(&stats);
                let admin_user = admin_user.clone();
                let admin_pass = admin_pass.clone();
                let config_path = config_path.clone();
                let cert_key = Arc::clone(&cert_key);
                let cert_path = cert_path.clone();
                let key_path = key_path.clone();
                let speed_test_limiter = Arc::clone(&speed_test_limiter);
                async move {
                    route(
                        req,
                        session_store,
                        config,
                        stats,
                        admin_user,
                        admin_pass,
                        config_path,
                        cert_key,
                        cert_path,
                        key_path,
                        speed_test_limiter,
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
