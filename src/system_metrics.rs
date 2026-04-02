use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Pid, ProcessesToUpdate, System};

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
    pub process_disk_read_bytes: u64,
    pub process_disk_written_bytes: u64,
    pub system_cpu_percent: f32,
    pub system_memory_total: u64,
    pub system_memory_used: u64,
    pub system_swap_total: u64,
    pub system_swap_used: u64,
    pub disks: Vec<DiskInfo>,
}

pub struct SystemMetrics {
    snapshot: Mutex<MetricsSnapshot>,
}

impl SystemMetrics {
    pub fn new() -> Self {
        Self {
            snapshot: Mutex::new(MetricsSnapshot::default()),
        }
    }

    pub fn get_snapshot(&self) -> MetricsSnapshot {
        self.snapshot.lock().unwrap().clone()
    }
}

pub fn spawn_collector(metrics: Arc<SystemMetrics>) {
    tokio::spawn(async move {
        let start = Instant::now();
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        let mut disks = Disks::new();

        // Initial refresh to get baseline CPU readings
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        disks.refresh(true);

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            sys.refresh_cpu_usage();
            sys.refresh_memory();
            sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
            disks.refresh(true);

            let system_cpu = sys.global_cpu_usage();

            let (proc_cpu, proc_mem, proc_disk_read, proc_disk_written) =
                if let Some(proc) = sys.process(pid) {
                    (
                        proc.cpu_usage(),
                        proc.memory(),
                        proc.disk_usage().read_bytes,
                        proc.disk_usage().written_bytes,
                    )
                } else {
                    (0.0, 0, 0, 0)
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

            let snap = MetricsSnapshot {
                uptime_secs: start.elapsed().as_secs(),
                process_cpu_percent: proc_cpu,
                process_memory_bytes: proc_mem,
                process_disk_read_bytes: proc_disk_read,
                process_disk_written_bytes: proc_disk_written,
                system_cpu_percent: system_cpu,
                system_memory_total: sys.total_memory(),
                system_memory_used: sys.used_memory(),
                system_swap_total: sys.total_swap(),
                system_swap_used: sys.used_swap(),
                disks: disk_infos,
            };

            *metrics.snapshot.lock().unwrap() = snap;
        }
    });
}
