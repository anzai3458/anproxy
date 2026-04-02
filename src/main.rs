mod cli;
mod admin;
mod config;
mod log_buffer;
mod proxy;
mod system_metrics;
mod tls;
mod stats;

use std::error::Error as StdError;
use std::sync::{Arc, RwLock};

use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};

use cli::Options;
use config::loader::merge;
use config::types::RuntimeConfig;
use proxy::server::{process, process_plain};
use tls::cert::{load_certified_key, DynamicCertResolver};
use tls::watcher::watch_certs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();
    let resolved = merge(options)?;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&resolved.log_level));

    let log_buffer_layer = log_buffer::LogBuffer::new(1000);
    let log_buffer = log_buffer_layer.handle();
    use tracing_subscriber::layer::SubscriberExt;
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .finish()
        .with(log_buffer_layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let system_metrics = Arc::new(system_metrics::SystemMetrics::new());
    system_metrics::spawn_collector(Arc::clone(&system_metrics));

    if resolved.no_tls {
        tracing::info!("TLS disabled - running in HTTP mode (NOT FOR PRODUCTION)");
    } else {
        tracing::info!(
            cert = %resolved.cert.as_ref().unwrap().display(),
            key = %resolved.key.as_ref().unwrap().display(),
        );
    }
    for (host, dir) in &resolved.static_dirs {
        tracing::info!(static_dir = true, %host, dir = %dir.display());
    }

    let addr = resolved.addr;
    let shared_config = Arc::new(RwLock::new(RuntimeConfig {
        targets: resolved.targets,
        static_dirs: resolved.static_dirs,
    }));
    let stats = Arc::new(stats::Stats::new());

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);

    if resolved.no_tls {
        // Plain HTTP mode - no TLS
        if let Some(admin_addr) = resolved.admin_addr {
            let admin_user = resolved.admin_user.unwrap();
            let admin_pass = resolved.admin_pass.unwrap();
            tokio::spawn(admin::server::run_admin_server_plain(
                admin_addr,
                shared_config.clone(),
                stats.clone(),
                admin_user,
                admin_pass,
                resolved.config_file,
                addr.port(),
                system_metrics.clone(),
                log_buffer.clone(),
            ));
        }

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let config = shared_config.clone();
            let stats_loop = stats.clone();

            tokio::spawn(async move {
                if let Err(err) = process_plain(
                    stream,
                    peer_addr,
                    config,
                    stats_loop.clone(),
                ).await {
                    tracing::error!(peer = %peer_addr, "Connection error: {}", err);
                    stats_loop.inc_errors();
                }
            });
        }
    } else {
        // TLS mode
        let cert = resolved.cert.as_ref().unwrap();
        let key = resolved.key.as_ref().unwrap();

        let certified_key = Arc::new(RwLock::new(Arc::new(load_certified_key(
            cert,
            key,
        )?)));

        let resolver = Arc::new(DynamicCertResolver {
            certified_key: Arc::clone(&certified_key),
        });

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let cert_path = resolved.cert.clone().unwrap();
        let key_path = resolved.key.clone().unwrap();
        tokio::spawn(watch_certs(
            cert_path.clone(),
            key_path.clone(),
            Arc::clone(&certified_key),
        ));

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
                cert_path,
                key_path,
                addr.port(),
                system_metrics.clone(),
                log_buffer.clone(),
            ));
        }

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let acceptor = acceptor.clone();
            let config = shared_config.clone();
            let stats_loop = stats.clone();

            tokio::spawn(async move {
                if let Err(err) = process(
                    stream,
                    peer_addr,
                    acceptor,
                    config,
                    stats_loop.clone(),
                ).await {
                    tracing::error!(peer = %peer_addr, "TLS accept failed: {}", err);
                    stats_loop.inc_errors();
                }
            });
        }
    }
}
