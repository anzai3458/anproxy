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
        let inner_config = config.clone();
        let inner_stats = stats.clone();
        proxy(req, peer_addr, inner_config, inner_stats)
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

pub async fn process_plain(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: SharedConfig,
    stats: Arc<Stats>,
) -> Result<(), String> {
    let client_io = TokioIo::new(stream);

    stats.inc_connections();
    let stats_clone = Arc::clone(&stats);

    let service = service_fn(move |req| {
        let inner_config = config.clone();
        let inner_stats = stats.clone();
        proxy(req, peer_addr, inner_config, inner_stats)
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
