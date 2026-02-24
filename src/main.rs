mod cli;
mod config;
mod proxy;
mod tls;

use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::{Arc, RwLock};

use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};

use cli::Options;
use config::loader::merge;
use proxy::server::process;
use tls::cert::{load_certified_key, DynamicCertResolver};
use tls::watcher::watch_certs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();
    let resolved = merge(options)?;

    let addr = resolved.addr;
    let targets: Arc<HashMap<String, std::net::SocketAddr>> = Arc::new(resolved.targets);

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

    tokio::spawn(watch_certs(resolved.cert, resolved.key, certified_key));

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = process(stream, peer_addr, acceptor, targets.clone());

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("Error handling proxy: {:?}", err);
            }
        });
    }
}
