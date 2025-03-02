use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use argh::FromArgs;
use hyper::server::conn::http1;
use hyper::service::service_fn;
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
    #[argh(positional)]
    addr: String,

    /// target address
    #[argh(option, short = 't')]
    target: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let target_addr = options
        .target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
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

        let fut = async move {
            let client_stream = acceptor.accept(stream).await?;
            let client_io = TokioIo::new(client_stream);

            let service = service_fn(move |mut req| async move {
                let target_stream = TcpStream::connect(target_addr).await.unwrap();
                let target_io = TokioIo::new(target_stream);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(target_io).await?;
                tokio::task::spawn(async move {
                    if let Err(err) = conn.await {
                        println!("Connection failed: {:?}", err);
                    }
                });
                req.headers_mut().insert("X-Forwarded-For", peer_addr.to_string().parse().unwrap());
                req.headers_mut().insert("X-Forwarded-Proto", "https".parse().unwrap());
                sender.send_request(req).await
            });

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(client_io, service)
                    .await
                {
                    println!("Failed to serve the connection: {:?}", err);
                }
            });

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("Error handling proxy: {:?}", err);
            }
        });
    }
}
