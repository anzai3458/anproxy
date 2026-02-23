use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use argh::FromArgs;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::OnUpgrade;
use hyper::{header, upgrade, Error, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::error::Error as StdError;
use std::sync::Arc;
use tokio::io::split;
use tokio::net::{TcpListener, TcpStream};
use tokio::{io, select};
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

fn load_certified_key(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<CertifiedKey, Box<dyn StdError + Send + Sync>> {
    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificates found in cert file".into());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

#[derive(Debug)]
struct DynamicCertResolver {
    certified_key: Arc<RwLock<Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified_key.read().unwrap()))
    }
}

fn file_mtime(path: &PathBuf) -> Option<SystemTime> {
    fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn try_reload_if_changed(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    last_cert_mtime: &mut Option<SystemTime>,
    last_key_mtime: &mut Option<SystemTime>,
    certified_key: &Arc<RwLock<Arc<CertifiedKey>>>,
) -> bool {
    let cert_mtime = file_mtime(cert_path);
    let key_mtime = file_mtime(key_path);

    if cert_mtime == *last_cert_mtime && key_mtime == *last_key_mtime {
        return false;
    }

    match load_certified_key(cert_path, key_path) {
        Ok(new_key) => {
            *certified_key.write().unwrap() = Arc::new(new_key);
            eprintln!("TLS certificate reloaded successfully");
            *last_cert_mtime = cert_mtime;
            *last_key_mtime = key_mtime;
            true
        }
        Err(e) => {
            eprintln!("Failed to reload TLS certificate (keeping current): {}", e);
            false
        }
    }
}

async fn watch_certs(
    cert_path: PathBuf,
    key_path: PathBuf,
    certified_key: Arc<RwLock<Arc<CertifiedKey>>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.tick().await; // consume the initial immediate tick

    let mut last_cert_mtime = file_mtime(&cert_path);
    let mut last_key_mtime = file_mtime(&key_path);

    loop {
        interval.tick().await;
        try_reload_if_changed(
            &cert_path,
            &key_path,
            &mut last_cert_mtime,
            &mut last_key_mtime,
            &certified_key,
        );
    }
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

    let certified_key = Arc::new(RwLock::new(Arc::new(load_certified_key(
        &options.cert,
        &options.key,
    )?)));

    let resolver = Arc::new(DynamicCertResolver {
        certified_key: Arc::clone(&certified_key),
    });

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;

    tokio::spawn(watch_certs(options.cert, options.key, certified_key));

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

async fn proxy(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    targets: Arc<HashMap<String, SocketAddr>>,
) -> Result<Response<BoxBody<Bytes, Error>>, String> {
    let (parts, body) = req.into_parts();
    let mut req_from_client = Request::from_parts(parts, body.boxed());

    let target_addr = req_from_client
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.splitn(2, ':').next())
        .flatten()
        .map(|h| targets.get(h))
        .flatten();

    if let None = target_addr {
        return Ok::<Response<BoxBody<Bytes, Error>>, String>(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(BoxBody::default())
                .unwrap(),
        );
    }

    let target_addr = target_addr.unwrap();

    let target_stream = TcpStream::connect(*target_addr)
        .await
        .map_err(|e| e.to_string())?;
    let target_io = TokioIo::new(target_stream);

    let (mut target_sender, conn) = hyper::client::conn::http1::handshake(target_io)
        .await
        .map_err(|e| e.to_string())?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            println!("Connection failed: {:?}", err);
        }
    });
    req_from_client.headers_mut().insert(
        "X-Forwarded-For",
        peer_addr.ip().to_string().parse().unwrap(),
    );
    req_from_client
        .headers_mut()
        .insert("X-Forwarded-Proto", "https".parse().unwrap());

    if let Some(conn_value) = req_from_client.headers().get(header::CONNECTION) {
        if conn_value != "Upgrade" && conn_value != "upgrade" {
            return send_request(&mut target_sender, req_from_client).await;
        }
    }

    let client_on_upgrade = upgrade::on(&mut req_from_client);
    let mut res_from_target = send_request(&mut target_sender, req_from_client).await?;
    let target_on_upgrade = upgrade::on(&mut res_from_target);

    proxy_upgraded(client_on_upgrade, target_on_upgrade);

    Ok(res_from_target)
}

fn proxy_upgraded(client_on_upgrade: OnUpgrade, target_on_upgrade: OnUpgrade) {
    tokio::spawn(async move {
        let (client_result, target_result) = tokio::join!(client_on_upgrade, target_on_upgrade);

        if let Err(e) = &client_result {
            println!("Failed to upgrade client connection: {:?}", e);
        }
        if let Err(e) = &target_result {
            println!("Failed to upgrade target connection: {:?}", e);
        }

        if let (Ok(client_upgraded), Ok(target_upgraded)) = (client_result, target_result) {
            let (mut target_read, mut target_write) = split(TokioIo::new(target_upgraded));
            let (mut client_read, mut client_write) = split(TokioIo::new(client_upgraded));
            let _ = select! {
                res = io::copy(&mut client_read, &mut target_write) => res,
                res = io::copy(&mut target_read, &mut client_write) => res,
            };
        }
    });
}

async fn send_request(
    sender: &mut SendRequest<BoxBody<Bytes, Error>>,
    request: Request<BoxBody<Bytes, Error>>,
) -> Result<Response<BoxBody<Bytes, Error>>, String> {
    sender
        .send_request(request)
        .await
        .map(|resp| {
            let (parts, body) = resp.into_parts();
            return Response::from_parts(parts, body.boxed());
        })
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Writes a fresh self-signed cert+key to two temp files.
    // Returns (cert_path, key_path, cert_file, key_file); the NamedTempFile
    // handles must be kept alive for the duration of the test.
    fn write_test_cert_files() -> (PathBuf, PathBuf, NamedTempFile, NamedTempFile) {
        let rcgen_cert =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = rcgen_cert.cert.pem();
        let key_pem = rcgen_cert.key_pair.serialize_pem();

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert_pem.as_bytes()).unwrap();
        cert_file.flush().unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key_pem.as_bytes()).unwrap();
        key_file.flush().unwrap();

        let cert_path = cert_file.path().to_path_buf();
        let key_path = key_file.path().to_path_buf();
        (cert_path, key_path, cert_file, key_file)
    }

    // ── parse_socket_addr ─────────────────────────────────────────────────

    #[test]
    fn test_parse_socket_addr_valid_ipv4() {
        let result = parse_socket_addr("127.0.0.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_socket_addr_valid_ipv6() {
        let result = parse_socket_addr("[::1]:9000");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_socket_addr_invalid_no_port() {
        assert!(parse_socket_addr("127.0.0.1").is_err());
    }

    #[test]
    fn test_parse_socket_addr_invalid_port() {
        assert!(parse_socket_addr("127.0.0.1:notaport").is_err());
    }

    // ── parse_host_mapping ────────────────────────────────────────────────

    #[test]
    fn test_parse_host_mapping_valid() {
        let result = parse_host_mapping("example.com@127.0.0.1:8080");
        assert!(result.is_ok());
        let target = result.unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.address.to_string(), "127.0.0.1:8080");
    }

    #[test]
    fn test_parse_host_mapping_no_at_separator() {
        assert!(parse_host_mapping("example.com:127.0.0.1:8080").is_err());
    }

    #[test]
    fn test_parse_host_mapping_invalid_addr() {
        assert!(parse_host_mapping("example.com@not-an-addr:notaport").is_err());
    }

    #[test]
    fn test_parse_host_mapping_empty_host() {
        // "@127.0.0.1:8080" — host is empty string, addr is valid
        let result = parse_host_mapping("@127.0.0.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().host, "");
    }

    // ── file_mtime ────────────────────────────────────────────────────────

    #[test]
    fn test_file_mtime_existing_file() {
        let f = NamedTempFile::new().unwrap();
        assert!(file_mtime(&f.path().to_path_buf()).is_some());
    }

    #[test]
    fn test_file_mtime_nonexistent_file() {
        assert!(file_mtime(&PathBuf::from("/nonexistent/path/cert.pem")).is_none());
    }

    // ── load_certified_key ────────────────────────────────────────────────

    #[test]
    fn test_load_certified_key_valid() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        assert!(load_certified_key(&cert_path, &key_path).is_ok());
    }

    #[test]
    fn test_load_certified_key_missing_cert_file() {
        let (_, key_path, _kf, _) = write_test_cert_files();
        let bad_cert = PathBuf::from("/nonexistent/cert.pem");
        assert!(load_certified_key(&bad_cert, &key_path).is_err());
    }

    #[test]
    fn test_load_certified_key_missing_key_file() {
        let (cert_path, _, _cf, _) = write_test_cert_files();
        let bad_key = PathBuf::from("/nonexistent/key.pem");
        assert!(load_certified_key(&cert_path, &bad_key).is_err());
    }

    #[test]
    fn test_load_certified_key_invalid_key_content() {
        let (cert_path, _, _cf, _) = write_test_cert_files();

        let mut key_file = NamedTempFile::new().unwrap();
        // Valid PEM envelope but garbage payload — any_supported_type will reject it
        key_file
            .write_all(
                b"-----BEGIN PRIVATE KEY-----\ndGhpcyBpcyBub3QgYSByZWFsIGtleQo=\n-----END PRIVATE KEY-----\n",
            )
            .unwrap();
        key_file.flush().unwrap();

        assert!(load_certified_key(&cert_path, &key_file.path().to_path_buf()).is_err());
    }

    // ── DynamicCertResolver ───────────────────────────────────────────────

    #[test]
    fn test_dynamic_cert_resolver_holds_key() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));
        let _resolver = DynamicCertResolver {
            certified_key: Arc::clone(&shared),
        };
        // The lock must be readable without poisoning
        let read_key = shared.read().unwrap();
        assert_eq!(read_key.cert, key.cert);
    }

    #[test]
    fn test_dynamic_cert_resolver_key_swap() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let initial = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&initial)));

        // Generate a second, distinct cert/key pair
        let (cert_path2, key_path2, _cf2, _kf2) = write_test_cert_files();
        let replacement = Arc::new(load_certified_key(&cert_path2, &key_path2).unwrap());

        // Swap the key (simulates what try_reload_if_changed does on reload)
        *shared.write().unwrap() = Arc::clone(&replacement);

        // The shared slot now points to the replacement key
        let current = shared.read().unwrap();
        assert_eq!(current.cert, replacement.cert);
        assert_ne!(current.cert, initial.cert);
    }

    // ── try_reload_if_changed ─────────────────────────────────────────────

    #[test]
    fn test_try_reload_no_change_returns_false() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));

        // Initialise last-seen mtimes to match the files on disk
        let mut last_cert = file_mtime(&cert_path);
        let mut last_key = file_mtime(&key_path);

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(!reloaded);
        // The shared pointer must be the same Arc (no swap)
        assert!(Arc::ptr_eq(&shared.read().unwrap(), &key));
    }

    #[test]
    fn test_try_reload_detects_mtime_change_and_reloads() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));

        // Simulate "files not seen before" by starting with None
        let mut last_cert: Option<SystemTime> = None;
        let mut last_key: Option<SystemTime> = None;

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(reloaded);
        // last-seen mtimes must be updated after a successful reload
        assert!(last_cert.is_some());
        assert!(last_key.is_some());
    }

    #[test]
    fn test_try_reload_keeps_old_key_on_invalid_cert() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let original_key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&original_key)));

        // Overwrite the cert file with garbage so the reload will fail
        std::fs::write(&cert_path, b"not a valid certificate").unwrap();

        // last_cert = None forces a reload attempt regardless of mtime
        let mut last_cert: Option<SystemTime> = None;
        let mut last_key: Option<SystemTime> = None;

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(!reloaded);
        // The shared slot must still hold the original key
        assert!(Arc::ptr_eq(&shared.read().unwrap(), &original_key));
        // last-seen mtimes must NOT be updated (so we retry next tick)
        assert!(last_cert.is_none());
    }

    #[test]
    fn test_try_reload_updates_mtimes_only_on_success() {
        let (cert_path, key_path, _cf, _kf) = write_test_cert_files();
        let key = Arc::new(load_certified_key(&cert_path, &key_path).unwrap());
        let shared = Arc::new(RwLock::new(Arc::clone(&key)));

        let actual_cert_mtime = file_mtime(&cert_path);
        let actual_key_mtime = file_mtime(&key_path);

        let mut last_cert: Option<SystemTime> = None;
        let mut last_key: Option<SystemTime> = None;

        let reloaded =
            try_reload_if_changed(&cert_path, &key_path, &mut last_cert, &mut last_key, &shared);

        assert!(reloaded);
        assert_eq!(last_cert, actual_cert_mtime);
        assert_eq!(last_key, actual_key_mtime);
    }
}
