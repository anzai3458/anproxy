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
  address: string;
}

export interface StaticDir {
  host: string;
  dir: string;
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

export const api = {
  login: (username: string, password: string) =>
    request('/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request('/logout', { method: 'POST' }),

  getTargets: () => request<Target[]>('/targets'),
  addTarget: (host: string, address: string) =>
    request<Target>('/targets', { method: 'POST', body: JSON.stringify({ host, address }) }),
  updateTarget: (host: string, address: string) =>
    request<Target>(`/targets/${encodeURIComponent(host)}`, { method: 'PUT', body: JSON.stringify({ address }) }),
  deleteTarget: (host: string) =>
    request(`/targets/${encodeURIComponent(host)}`, { method: 'DELETE' }),

  getStaticDirs: () => request<StaticDir[]>('/static-dirs'),
  addStaticDir: (host: string, dir: string) =>
    request<StaticDir>('/static-dirs', { method: 'POST', body: JSON.stringify({ host, dir }) }),
  updateStaticDir: (host: string, dir: string) =>
    request<StaticDir>(`/static-dirs/${encodeURIComponent(host)}`, { method: 'PUT', body: JSON.stringify({ dir }) }),
  deleteStaticDir: (host: string) =>
    request(`/static-dirs/${encodeURIComponent(host)}`, { method: 'DELETE' }),

  getStats: () => request<Stats>('/stats'),
  getCerts: () => request<CertInfo>('/certs'),
  reloadCerts: () => request('/certs/reload', { method: 'POST' }),

  speedTestPing: () => fetch(`${BASE}/speed-test/ping`),
  speedTestDownload: () => fetch(`${BASE}/speed-test/download`),
  speedTestUpload: (data: Blob) =>
    fetch(`${BASE}/speed-test/upload`, { method: 'POST', body: data }),
};
