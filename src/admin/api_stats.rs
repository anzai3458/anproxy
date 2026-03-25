use std::sync::atomic::Ordering;
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Error, Response};

use crate::admin::response::json_ok;
use crate::stats::Stats;

pub fn get_stats(stats: &Arc<Stats>) -> Response<BoxBody<Bytes, Error>> {
    let per_host: std::collections::HashMap<String, u64> = stats
        .per_host_requests
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Relaxed)))
        .collect();

    json_ok(&serde_json::json!({
        "active_connections": stats.active_connections.load(Ordering::Relaxed),
        "total_requests": stats.total_requests.load(Ordering::Relaxed),
        "total_errors": stats.total_errors.load(Ordering::Relaxed),
        "bytes_sent": stats.bytes_sent.load(Ordering::Relaxed),
        "bytes_received": stats.bytes_received.load(Ordering::Relaxed),
        "per_host_requests": per_host,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;

    #[test]
    fn test_get_stats_empty() {
        let stats = Arc::new(Stats::new());
        let resp = get_stats(&stats);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_get_stats_with_data() {
        let stats = Arc::new(Stats::new());
        stats.inc_requests("example.com");
        stats.inc_requests("example.com");
        stats.inc_connections();
        let resp = get_stats(&stats);
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
