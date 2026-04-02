import { useState, useEffect, useCallback } from 'react'
import { api, type Stats, type Target, type CertInfo } from '../api.ts'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

function formatTime(epochMs: number): string {
  if (!epochMs) return ''
  const d = new Date(epochMs)
  return d.toLocaleTimeString()
}

function StatCard({ label, value, sub, color }: { label: string; value: string; sub?: string; color?: string }) {
  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <div className="text-[10px] text-text-dim uppercase tracking-widest mb-2">{label}</div>
      <div className={`text-2xl font-bold ${color || 'text-text'}`}>{value}</div>
      {sub && <div className="text-[10px] text-text-muted mt-1">{sub}</div>}
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [targets, setTargets] = useState<Target[]>([])
  const [certs, setCerts] = useState<CertInfo | null>(null)

  const fetchAll = useCallback(async () => {
    const [s, t, c] = await Promise.allSettled([
      api.getStats(),
      api.getTargets(),
      api.getCerts(),
    ])
    if (s.status === 'fulfilled') setStats(s.value)
    if (t.status === 'fulfilled') setTargets(t.value)
    if (c.status === 'fulfilled') setCerts(c.value)
  }, [])

  useEffect(() => {
    fetchAll()
    const id = setInterval(async () => {
      try {
        const s = await api.getStats()
        setStats(s)
      } catch { /* ignore */ }
    }, 5000)
    return () => clearInterval(id)
  }, [fetchAll])

  const certColor = certs
    ? certs.days_until_expiry > 30 ? 'text-green' : certs.days_until_expiry > 7 ? 'text-yellow' : 'text-red'
    : undefined

  return (
    <div className="space-y-6 animate-fade-in">
      <h1 className="text-sm font-semibold text-text-dim">
        <span className="text-accent">~</span> overview
      </h1>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="connections" value={stats?.active_connections?.toString() ?? '—'} color="text-blue" />
        <StatCard label="requests" value={stats?.total_requests?.toLocaleString() ?? '—'} />
        <StatCard
          label="errors"
          value={stats?.total_errors?.toLocaleString() ?? '—'}
          color={stats && stats.total_errors > 0 ? 'text-red' : undefined}
        />
        <StatCard
          label="cert expiry"
          value={certs ? `${certs.days_until_expiry}d` : '—'}
          color={certColor}
          sub={certs?.expiry}
        />
      </div>

      {/* Bandwidth */}
      {stats && (
        <div className="grid grid-cols-2 gap-3">
          <StatCard label="sent" value={formatBytes(stats.bytes_sent)} color="text-green" />
          <StatCard label="received" value={formatBytes(stats.bytes_received)} color="text-accent" />
        </div>
      )}

      {/* Per-host traffic */}
      {stats && Object.keys(stats.per_host_requests).length > 0 && (
        <div>
          <h2 className="text-xs text-text-dim mb-3">
            <span className="text-accent">$</span> requests by host
          </h2>
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            {Object.entries(stats.per_host_requests)
              .sort(([, a], [, b]) => b - a)
              .map(([host, count]) => (
                <div key={host} className="flex items-center justify-between px-4 py-2.5 border-b border-border last:border-b-0 text-xs">
                  <span className="text-text truncate">{host}</span>
                  <div className="flex items-center gap-3 ml-3 shrink-0">
                    {stats.per_host_last_request?.[host] ? (
                      <span className="text-text-muted text-[10px]">{formatTime(stats.per_host_last_request[host])}</span>
                    ) : null}
                    <span className="text-text-dim">{count.toLocaleString()}</span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Quick view: targets */}
      <div>
        <h2 className="text-xs text-text-dim mb-3">
          <span className="text-accent">$</span> targets
          <span className="text-text-muted ml-2">{targets.length}</span>
        </h2>
        {targets.length === 0 ? (
          <p className="text-xs text-text-muted">no targets configured</p>
        ) : (
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            {targets.map((t) => (
              <div key={t.host} className="flex items-center justify-between px-4 py-2.5 border-b border-border last:border-b-0 text-xs">
                <a href={`https://${t.host}:${stats?.proxy_port ?? 443}`} target="_blank" rel="noopener noreferrer" className="text-text truncate hover:text-accent transition-colors">{t.host}</a>
                <span className="text-text-dim ml-3 shrink-0">{t.backend}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
