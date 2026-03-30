use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Stats {
    pub active_connections: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_errors: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub per_host_requests: DashMap<String, AtomicU64>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            per_host_requests: DashMap::new(),
        }
    }

    pub fn inc_requests(&self, host: &str) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.per_host_requests
            .entry(host.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_errors(&self) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stats_are_zero() {
        let stats = Stats::new();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_inc_requests_updates_total_and_per_host() {
        let stats = Stats::new();
        stats.inc_requests("example.com");
        stats.inc_requests("example.com");
        stats.inc_requests("other.com");
        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 3);
        assert_eq!(
            stats.per_host_requests.get("example.com").unwrap().load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            stats.per_host_requests.get("other.com").unwrap().load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn test_connection_counting() {
        let stats = Stats::new();
        stats.inc_connections();
        stats.inc_connections();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);
        stats.dec_connections();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);
    }
}
