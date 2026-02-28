use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::upgrade::OnUpgrade;
use hyper::{header, upgrade, Error, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::split;
use tokio::net::TcpStream;
use tokio::{io, select};

use crate::proxy::static_handler::serve_static;

pub async fn proxy(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    targets: Arc<HashMap<String, SocketAddr>>,
    static_dirs: Arc<HashMap<String, PathBuf>>,
) -> Result<Response<BoxBody<Bytes, Error>>, String> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-")
        .to_owned();
    let method = req.method().clone();
    let path = req.uri().path().to_owned();

    // Strip optional port from the Host header for map lookups.
    let hostname = host.split(':').next().unwrap_or(&host).to_owned();

    // Try static file serving before proxy.
    if let Some(static_dir) = static_dirs.get(&hostname) {
        if let Some(resp) = serve_static(&req, static_dir).await {
            tracing::info!(
                peer = %peer_addr, %host, %method, %path,
                status = resp.status().as_u16(),
                "static",
            );
            return Ok(resp);
        }
    }

    let (parts, body) = req.into_parts();
    let mut req_from_client = Request::from_parts(parts, body.boxed());

    let target_addr = targets.get(&hostname).copied();

    if target_addr.is_none() {
        tracing::warn!(peer = %peer_addr, %host, "no target configured for host");
        return Ok::<Response<BoxBody<Bytes, Error>>, String>(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(BoxBody::default())
                .unwrap(),
        );
    }

    let target_addr = target_addr.unwrap();

    let target_stream = TcpStream::connect(target_addr)
        .await
        .map_err(|e| e.to_string())?;
    let target_io = TokioIo::new(target_stream);

    let (mut target_sender, conn) = hyper::client::conn::http1::handshake(target_io)
        .await
        .map_err(|e| e.to_string())?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!("Upstream connection closed: {:?}", err);
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
            let resp = send_request(&mut target_sender, req_from_client).await?;
            tracing::info!(
                peer = %peer_addr, %host, %method, %path,
                status = resp.status().as_u16(),
            );
            return Ok(resp);
        }
    }

    let client_on_upgrade = upgrade::on(&mut req_from_client);
    let mut res_from_target = send_request(&mut target_sender, req_from_client).await?;
    let target_on_upgrade = upgrade::on(&mut res_from_target);

    proxy_upgraded(client_on_upgrade, target_on_upgrade);

    tracing::info!(
        peer = %peer_addr, %host, %method, %path,
        status = res_from_target.status().as_u16(),
        "upgrade",
    );
    Ok(res_from_target)
}

fn proxy_upgraded(client_on_upgrade: OnUpgrade, target_on_upgrade: OnUpgrade) {
    tokio::spawn(async move {
        let (client_result, target_result) = tokio::join!(client_on_upgrade, target_on_upgrade);

        if let Err(e) = &client_result {
            tracing::warn!("Failed to upgrade client connection: {:?}", e);
        }
        if let Err(e) = &target_result {
            tracing::warn!("Failed to upgrade target connection: {:?}", e);
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
            Response::from_parts(parts, body.boxed())
        })
        .map_err(|e| e.to_string())
}
