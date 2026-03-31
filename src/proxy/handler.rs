use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::upgrade::OnUpgrade;
use hyper::{header, upgrade, Error, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io;
use tokio::io::split;
use tokio::net::TcpStream;

use crate::config::types::SharedConfig;
use crate::proxy::static_handler::serve_static;
use crate::stats::Stats;

/// Body wrapper that counts bytes as each data frame passes through.
struct CountingBody {
    inner: BoxBody<Bytes, Error>,
    stats: Arc<Stats>,
    add_fn: fn(&Stats, u64),
}

impl Body for CountingBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    (this.add_fn)(&this.stats, data.len() as u64);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// Wrap a response body to count bytes sent to the client.
fn count_sent(
    resp: Response<BoxBody<Bytes, Error>>,
    stats: &Arc<Stats>,
) -> Response<BoxBody<Bytes, Error>> {
    let (parts, body) = resp.into_parts();
    let counting = CountingBody {
        inner: body,
        stats: Arc::clone(stats),
        add_fn: Stats::add_bytes_sent,
    };
    Response::from_parts(parts, counting.boxed())
}

pub async fn proxy(
    req: Request<Incoming>,
    peer_addr: SocketAddr,
    config: SharedConfig,
    stats: Arc<Stats>,
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

    stats.inc_requests(&hostname);

    let (static_dir, target_addr) = {
        let cfg = config.read().unwrap();
        (
            cfg.static_dirs.get(&hostname).cloned(),
            cfg.targets.get(&hostname).copied(),
        )
    };

    // Try static file serving before proxy.
    if let Some(ref static_dir) = static_dir {
        if let Some(resp) = serve_static(&req, static_dir).await {
            tracing::info!(
                peer = %peer_addr, %host, %method, %path,
                status = resp.status().as_u16(),
                "static",
            );
            return Ok(count_sent(resp, &stats));
        }
    }

    let (parts, body) = req.into_parts();
    // Wrap the request body to count bytes received from the client.
    let counting_body = CountingBody {
        inner: body.boxed(),
        stats: Arc::clone(&stats),
        add_fn: Stats::add_bytes_received,
    };
    let mut req_from_client = Request::from_parts(parts, counting_body.boxed());

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
            return Ok(count_sent(resp, &stats));
        }
    }

    let client_on_upgrade = upgrade::on(&mut req_from_client);
    let mut res_from_target = send_request(&mut target_sender, req_from_client).await?;
    let target_on_upgrade = upgrade::on(&mut res_from_target);

    proxy_upgraded(client_on_upgrade, target_on_upgrade, Arc::clone(&stats));

    tracing::info!(
        peer = %peer_addr, %host, %method, %path,
        status = res_from_target.status().as_u16(),
        "upgrade",
    );
    Ok(count_sent(res_from_target, &stats))
}

fn proxy_upgraded(client_on_upgrade: OnUpgrade, target_on_upgrade: OnUpgrade, stats: Arc<Stats>) {
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
            let (client_to_target, target_to_client) = tokio::join!(
                io::copy(&mut client_read, &mut target_write),
                io::copy(&mut target_read, &mut client_write),
            );
            if let Ok(n) = client_to_target {
                stats.add_bytes_received(n);
            }
            if let Ok(n) = target_to_client {
                stats.add_bytes_sent(n);
            }
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
