use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Error, Response};

use crate::admin::response::json_ok;
use crate::log_buffer::LogBufferHandle;
use crate::system_metrics::SystemMetrics;

pub fn get_system_metrics(metrics: &Arc<SystemMetrics>) -> Response<BoxBody<Bytes, Error>> {
    let snap = metrics.get_snapshot();
    json_ok(&snap)
}

pub fn get_logs(log_buffer: &LogBufferHandle, lines: usize) -> Response<BoxBody<Bytes, Error>> {
    let entries = log_buffer.recent(lines);
    json_ok(&entries)
}
