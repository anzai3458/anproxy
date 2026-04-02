use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sysinfo::{Disks, Pid, ProcessesToUpdate, System};

const CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Serialize, Default)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub fs_type: String,
}

#[derive(Clone, Serialize, Default)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub process_cpu_percent: f32,
    pub process_memory_bytes: u64,
    pub system_cpu_percent: f32,
    pub system_memory_total: u64,
    pub system_memory_used: u64,
    pub system_swap_total: u64,
    pub system_swap_used: u64,
    pub disks: Vec<DiskInfo>,
}

struct CachedMetrics {
    snapshot: MetricsSnapshot,
    last_updated: Instant,
}

pub struct SystemMetrics {
    cache: Mutex<Option<CachedMetrics>>,
    start_time: Instant,
    sys: Mutex<System>,
    disks: Mutex<Disks>,
    pid: Pid,
}

impl SystemMetrics {
    pub fn new() -> Arc<Self> {
        let mut sys = System::new();
        let mut disks = Disks::new();

        // Initial refresh to get baseline CPU readings
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        disks.refresh(true);

        Arc::new(Self {
            cache: Mutex::new(None),
            start_time: Instant::now(),
            sys: Mutex::new(sys),
            disks: Mutex::new(disks),
            pid: Pid::from_u32(std::process::id()),
        })
    }

    pub fn get_snapshot(self: &Arc<Self>) -> MetricsSnapshot {
        // Check if we have a valid cached value
        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.last_updated.elapsed() < CACHE_TTL {
                    return cached.snapshot.clone();
                }
            }
        }

        // Need to collect fresh metrics
        self.collect_metrics()
    }

    fn collect_metrics(self: &Arc<Self>) -> MetricsSnapshot {
        let mut sys = self.sys.lock().unwrap();
        let mut disks = self.disks.lock().unwrap();

        // Refresh system data
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        sys.refresh_processes(ProcessesToUpdate::Some(&[self.pid]), true);
        disks.refresh(true);

        let system_cpu = sys.global_cpu_usage();

        let (proc_cpu, proc_mem) =
            if let Some(proc) = sys.process(self.pid) {
                (
                    proc.cpu_usage(),
                    proc.memory(),
                )
            } else {
                (0.0, 0)
            };

        let disk_infos: Vec<DiskInfo> = disks
            .iter()
            .map(|d| DiskInfo {
                name: d.name().to_string_lossy().to_string(),
                mount_point: d.mount_point().to_string_lossy().to_string(),
                total_bytes: d.total_space(),
                available_bytes: d.available_space(),
                fs_type: d.file_system().to_string_lossy().to_string(),
            })
            .collect();

        let snapshot = MetricsSnapshot {
            uptime_secs: self.start_time.elapsed().as_secs(),
            process_cpu_percent: proc_cpu,
            process_memory_bytes: proc_mem,
            system_cpu_percent: system_cpu,
            system_memory_total: sys.total_memory(),
            system_memory_used: sys.used_memory(),
            system_swap_total: sys.total_swap(),
            system_swap_used: sys.used_swap(),
            disks: disk_infos,
        };

        // Update cache
        if let Ok(mut guard) = self.cache.lock() {
            *guard = Some(CachedMetrics {
                snapshot: snapshot.clone(),
                last_updated: Instant::now(),
            });
        }

        snapshot
    }
}
