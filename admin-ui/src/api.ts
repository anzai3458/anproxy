const BASE = '/api';

async function request(path: string, options?: RequestInit) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options?.headers },
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || 'Unknown error');
  return data.data;
}

export const api = {
  login: (username: string, password: string) =>
    request('/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request('/logout', { method: 'POST' }),

  getTargets: () => request('/targets'),
  addTarget: (host: string, address: string) =>
    request('/targets', { method: 'POST', body: JSON.stringify({ host, address }) }),
  updateTarget: (host: string, address: string) =>
    request(`/targets/${encodeURIComponent(host)}`, { method: 'PUT', body: JSON.stringify({ address }) }),
  deleteTarget: (host: string) =>
    request(`/targets/${encodeURIComponent(host)}`, { method: 'DELETE' }),

  getStaticDirs: () => request('/static-dirs'),
  addStaticDir: (host: string, dir: string) =>
    request('/static-dirs', { method: 'POST', body: JSON.stringify({ host, dir }) }),
  updateStaticDir: (host: string, dir: string) =>
    request(`/static-dirs/${encodeURIComponent(host)}`, { method: 'PUT', body: JSON.stringify({ dir }) }),
  deleteStaticDir: (host: string) =>
    request(`/static-dirs/${encodeURIComponent(host)}`, { method: 'DELETE' }),

  getStats: () => request('/stats'),
  getCerts: () => request('/certs'),
  reloadCerts: () => request('/certs/reload', { method: 'POST' }),

  speedTestPing: () => fetch(`${BASE}/speed-test/ping`),
  speedTestDownload: () => fetch(`${BASE}/speed-test/download`),
  speedTestUpload: (data: Blob) =>
    fetch(`${BASE}/speed-test/upload`, { method: 'POST', body: data }),
};
