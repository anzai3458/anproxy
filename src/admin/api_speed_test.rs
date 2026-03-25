use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Instant;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Error, Response, StatusCode};

use crate::admin::response::{json_err, json_ok};

pub type SpeedTestLimiter = Mutex<HashSet<String>>;

pub fn new_limiter() -> SpeedTestLimiter {
    Mutex::new(HashSet::new())
}

pub fn ping() -> Response<BoxBody<Bytes, Error>> {
    Response::builder()
        .status(StatusCode::OK)
        .body(BoxBody::default())
        .unwrap()
}

pub async fn download(
    session_token: Option<&str>,
    limiter: &SpeedTestLimiter,
) -> Response<BoxBody<Bytes, Error>> {
    // Rate limit check
    if let Some(token) = session_token {
        let mut active = limiter.lock().unwrap();
        if active.contains(token) {
            return json_err(StatusCode::TOO_MANY_REQUESTS, "Speed test already in progress");
        }
        active.insert(token.to_string());
    }

    // 10MB of zero-filled data
    const TOTAL_SIZE: usize = 10 * 1024 * 1024;
    let data = vec![0u8; TOTAL_SIZE];

    // Remove from limiter
    if let Some(token) = session_token {
        limiter.lock().unwrap().remove(token);
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", TOTAL_SIZE.to_string())
        .body(
            Full::new(Bytes::from(data))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

pub fn upload(
    body: Bytes,
    session_token: Option<&str>,
    limiter: &SpeedTestLimiter,
    start_time: Instant,
) -> Response<BoxBody<Bytes, Error>> {
    let _ = (session_token, limiter); // reserved for future use
    let elapsed = start_time.elapsed();
    let bytes = body.len() as u64;
    let seconds = elapsed.as_secs_f64();
    let mbps = if seconds > 0.0 {
        (bytes as f64 * 8.0) / (seconds * 1_000_000.0)
    } else {
        0.0
    };

    json_ok(&serde_json::json!({
        "bytes": bytes,
        "elapsed_ms": elapsed.as_millis(),
        "mbps": mbps,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping() {
        let resp = ping();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_new_limiter() {
        let limiter = new_limiter();
        assert!(limiter.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_download() {
        let limiter = new_limiter();
        let resp = download(Some("test-session"), &limiter).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_upload() {
        let limiter = new_limiter();
        let data = Bytes::from(vec![0u8; 1024]);
        let start = Instant::now();
        let resp = upload(data, Some("test-session"), &limiter, start);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_download_rate_limit() {
        let limiter = new_limiter();
        limiter.lock().unwrap().insert("busy-session".to_string());
        let resp = download(Some("busy-session"), &limiter).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
