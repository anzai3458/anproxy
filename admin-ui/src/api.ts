const BASE = '/api';

async function request<T = unknown>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('auth:expired'));
    throw new Error('Session expired');
  }
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || 'Unknown error');
  return data.data as T;
}

export interface Target {
  host: string;
  backend: string;
}

export interface Stats {
  active_connections: number;
  total_requests: number;
  total_errors: number;
  bytes_sent: number;
  bytes_received: number;
  per_host_requests: Record<string, number>;
  per_host_last_request: Record<string, number>;
  proxy_port: number;
}

export interface CertInfo {
  cert_path: string;
  key_path: string;
  expiry: string;
  days_until_expiry: number;
  not_before: string;
  subject: string;
  issuer: string;
  serial: string;
  signature_algorithm: string;
  san_dns_names: string[];
}

export interface UploadResult {
  bytes: number;
  elapsed_ms: number;
  mbps: number;
}

export interface SystemMetrics {
  uptime_secs: number
  process_cpu_percent: number
  process_memory_bytes: number
  system_cpu_percent: number
  system_memory_total: number
  system_memory_used: number
  system_swap_total: number
  system_swap_used: number
  disks: DiskInfo[]
}

export interface DiskInfo {
  name: string
  mount_point: string
  total_bytes: number
  available_bytes: number
  fs_type: string
}

export interface LogEntry {
  timestamp_ms: number
  level: string
  target: string
  message: string
}

export const api = {
  login: (username: string, password: string) =>
    request('/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request('/logout', { method: 'POST' }),

  getTargets: () => request<Target[]>('/targets'),
  addTarget: (host: string, backend: string) =>
    request<Target>('/targets', { method: 'POST', body: JSON.stringify({ host, backend }) }),
  updateTarget: (host: string, backend: string) =>
    request<Target>(`/targets/${encodeURIComponent(host)}`, { method: 'PUT', body: JSON.stringify({ backend }) }),
  deleteTarget: (host: string) =>
    request(`/targets/${encodeURIComponent(host)}`, { method: 'DELETE' }),

  getStats: () => request<Stats>('/stats'),
  getCerts: () => request<CertInfo>('/certs'),
  reloadCerts: () => request('/certs/reload', { method: 'POST' }),

  speedTestPing: () => fetch(`${BASE}/speed-test/ping`),
  speedTestDownload: () => fetch(`${BASE}/speed-test/download`),
  speedTestUpload: (data: Blob) =>
    fetch(`${BASE}/speed-test/upload`, { method: 'POST', body: data }),

  getSystemMetrics: () => request<SystemMetrics>('/system'),
  getLogs: (lines = 200) => request<LogEntry[]>(`/logs?lines=${lines}`),
};
