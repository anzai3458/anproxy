use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct LogEntry {
    pub timestamp_ms: i64,
    pub level: String,
    pub target: String,
    pub message: String,
}

struct Inner {
    entries: VecDeque<LogEntry>,
    capacity: usize,
}

/// A shared handle to read log entries.
#[derive(Clone)]
pub struct LogBufferHandle {
    inner: Arc<Mutex<Inner>>,
}

impl LogBufferHandle {
    pub fn recent(&self, n: usize) -> Vec<LogEntry> {
        let inner = self.inner.lock().unwrap();
        let skip = inner.entries.len().saturating_sub(n);
        inner.entries.iter().skip(skip).cloned().collect()
    }
}

/// A tracing Layer that captures log events into a ring buffer.
pub struct LogBuffer {
    inner: Arc<Mutex<Inner>>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: VecDeque::with_capacity(capacity),
                capacity,
            })),
        }
    }

    pub fn handle(&self) -> LogBufferHandle {
        LogBufferHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for LogBuffer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let metadata = event.metadata();
        let level = metadata.level().to_string();
        let target = metadata.target().to_string();

        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let entry = LogEntry {
            timestamp_ms: now,
            level,
            target,
            message: visitor.0,
        };

        let mut inner = self.inner.lock().unwrap();
        if inner.entries.len() >= inner.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else {
            if !self.0.is_empty() {
                self.0.push(' ');
            }
            self.0.push_str(&format!("{}={}", field.name(), value));
        }
    }
}
