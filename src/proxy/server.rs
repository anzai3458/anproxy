use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use crate::proxy::handler::proxy;

pub async fn process(
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    targets: Arc<HashMap<String, SocketAddr>>,
) -> Result<(), String> {
    let client_stream = acceptor.accept(stream).await.map_err(|e| e.to_string())?;
    let client_io = TokioIo::new(client_stream);

    let service = service_fn(move |req| {
        let inner_targets = targets.clone();
        proxy(req, peer_addr, inner_targets)
    });

    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new()
            .serve_connection(client_io, service)
            .with_upgrades()
            .await
        {
            println!("Failed to serve connection: {:?}", err);
        }
    });

    Ok(())
}
