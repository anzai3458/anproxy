mod cli;
mod config;
mod proxy;
mod tls;
mod stats;

use std::error::Error as StdError;
use std::sync::{Arc, RwLock};

use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};

use cli::Options;
use config::loader::merge;
use config::types::RuntimeConfig;
use proxy::server::process;
use tls::cert::{load_certified_key, DynamicCertResolver};
use tls::watcher::watch_certs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();
    let resolved = merge(options)?;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&resolved.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        cert = %resolved.cert.display(),
        key = %resolved.key.display(),
    );
    for (host, dir) in &resolved.static_dirs {
        tracing::info!(static_dir = true, %host, dir = %dir.display());
    }

    let addr = resolved.addr;
    let shared_config = Arc::new(RwLock::new(RuntimeConfig {
        targets: resolved.targets,
        static_dirs: resolved.static_dirs,
    }));
    let stats = Arc::new(stats::Stats::new());

    let certified_key = Arc::new(RwLock::new(Arc::new(load_certified_key(
        &resolved.cert,
        &resolved.key,
    )?)));

    let resolver = Arc::new(DynamicCertResolver {
        certified_key: Arc::clone(&certified_key),
    });

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);

    tokio::spawn(watch_certs(resolved.cert, resolved.key, certified_key));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = process(
            stream,
            peer_addr,
            acceptor,
            shared_config.clone(),
            stats.clone(),
        );

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                tracing::error!(peer = %peer_addr, "TLS accept failed: {}", err);
            }
        });
    }
}
