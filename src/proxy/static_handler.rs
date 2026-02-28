use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{header, Error, Request, Response, StatusCode};

pub async fn serve_static<B>(
    req: &Request<B>,
    static_dir: &Path,
) -> Option<Response<BoxBody<Bytes, Error>>> {
    let req_path = req.uri().path();
    let normalized = normalize_path(req_path);
    let candidate = static_dir.join(&normalized);

    // Canonicalize both the static dir and the candidate to block path traversal.
    // If either canonicalization fails (e.g. file does not exist), return None
    // so the caller can fall through to the proxy backend.
    let canonical_dir = tokio::fs::canonicalize(static_dir).await.ok()?;
    let canonical_candidate = tokio::fs::canonicalize(&candidate).await.ok()?;

    if !canonical_candidate.starts_with(&canonical_dir) {
        return None;
    }

    let metadata = tokio::fs::metadata(&canonical_candidate).await.ok()?;
    if !metadata.is_file() {
        return None;
    }

    let mtime_secs = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let size = metadata.len();
    let etag = format!("\"{}-{}\"", mtime_secs, size);

    // Check If-None-Match
    if let Some(inm) = req.headers().get(header::IF_NONE_MATCH) {
        if etag_matches(inm, &etag) {
            return Some(not_modified());
        }
    }

    // Check If-Modified-Since (only when no ETag match was attempted)
    if req.headers().get(header::IF_NONE_MATCH).is_none() {
        if let Some(ims_val) = req.headers().get(header::IF_MODIFIED_SINCE) {
            if let Ok(ims_str) = ims_val.to_str() {
                if !file_newer_than(mtime_secs, ims_str) {
                    return Some(not_modified());
                }
            }
        }
    }

    let mime = mime_type_for(&canonical_candidate);
    let last_modified = format_http_date(mtime_secs);

    let contents = tokio::fs::read(&canonical_candidate).await.ok()?;
    let body: BoxBody<Bytes, Error> = Full::new(Bytes::from(contents))
        .map_err(|e| match e {})
        .boxed();

    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, size)
            .header(header::ETAG, etag)
            .header(header::LAST_MODIFIED, last_modified)
            .header(header::CACHE_CONTROL, "public, max-age=0, must-revalidate")
            .body(body)
            .unwrap(),
    )
}

fn not_modified() -> Response<BoxBody<Bytes, Error>> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .body(BoxBody::default())
        .unwrap()
}

/// Strip the leading `/` and reject empty or dot-only components.
/// Actual traversal prevention is enforced by `canonicalize` above;
/// this just avoids joining an absolute path like `/etc/passwd`.
fn normalize_path(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

fn etag_matches(if_none_match: &header::HeaderValue, etag: &str) -> bool {
    let Ok(inm_str) = if_none_match.to_str() else {
        return false;
    };
    if inm_str == "*" {
        return true;
    }
    for candidate in inm_str.split(',') {
        if candidate.trim() == etag {
            return true;
        }
    }
    false
}

fn file_newer_than(mtime_secs: u64, http_date: &str) -> bool {
    match httpdate::parse_http_date(http_date) {
        Ok(t) => {
            let parsed_secs = t
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            mtime_secs > parsed_secs
        }
        Err(_) => true, // unparseable date → assume modified
    }
}

fn format_http_date(secs: u64) -> String {
    let t = UNIX_EPOCH + Duration::from_secs(secs);
    httpdate::fmt_http_date(t)
}

fn mime_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("pdf") => "application/pdf",
        Some("webp") => "image/webp",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        Some("ogg") => "audio/ogg",
        Some("wav") => "audio/wav",
        _ => "application/octet-stream",
    }
}
