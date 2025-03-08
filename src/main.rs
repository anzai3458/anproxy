use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use argh::FromArgs;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{rustls, TlsAcceptor};

/// Simple https reverse proxy
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional, from_str_fn(parse_socket_addr))]
    addr: SocketAddr,

    /// host address mapping
    #[argh(option, short = 't', from_str_fn(parse_host_mapping))]
    targets: Vec<Target>,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,
}

#[derive(Debug)]
struct Target {
    host: String,
    address: SocketAddr,
}

fn parse_socket_addr(addr: &str) -> Result<SocketAddr, String> {
    Ok(addr
        .to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| "".to_string())?)
}

fn parse_host_mapping(value: &str) -> Result<Target, String> {
    if let Some((host, addr)) = value.split_once("@") {
        let addr = addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| format!("Invalid address {}", value.to_string()))?;
        return Ok(Target {
            host: host.to_string(),
            address: addr,
        });
    }
    Err(format!(
        "Invalid target format, expected '{{host}}@{{addr}}', got '{}'",
        value
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();

    let addr = options.addr;
    let targets: Arc<HashMap<String, SocketAddr>> = Arc::new(
        options
            .targets
            .iter()
            .map(|t| (t.host.to_string(), t.address))
            .collect(),
    );

    let certs = CertificateDer::pem_file_iter(&options.cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&options.key)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;

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

async fn process(
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    targets: Arc<HashMap<String, SocketAddr>>,
) -> Result<(), String> {
    let client_stream = acceptor.accept(stream).await.map_err(|e| e.to_string())?;
    let client_io = TokioIo::new(client_stream);

    let service = service_fn(move |mut req| {
        let inner_targets = targets.clone();

        async move {
            let target_addr = req
                .headers()
                .get("Host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.splitn(2, ':').next())
                .flatten()
                .map(|h| inner_targets.get(h))
                .flatten();

            if let None = target_addr {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(BoxBody::default())
                    .unwrap());
            }

            let target_addr = target_addr.unwrap();

            let target_stream = TcpStream::connect(*target_addr)
                .await
                .map_err(|e| e.to_string())?;
            let target_io = TokioIo::new(target_stream);

            let (mut sender, conn) = hyper::client::conn::http1::handshake(target_io)
                .await
                .map_err(|e| e.to_string())?;

            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    println!("Connection failed: {:?}", err);
                }
            });

            req.headers_mut()
                .insert("X-Forwarded-For", peer_addr.to_string().parse().unwrap());
            req.headers_mut()
                .insert("X-Forwarded-Proto", "https".parse().unwrap());

            sender
                .send_request(req)
                .await
                .map(|resp| {
                    let (parts, body) = resp.into_parts();
                    return Response::from_parts(parts, body.boxed());
                })
                .map_err(|e| e.to_string())
        }
    });

    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new()
            .serve_connection(client_io, service)
            .await
        {
            println!("Failed to serve connection: {:?}", err);
        }
    });

    Ok(())
}
