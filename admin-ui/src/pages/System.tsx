import { useState, useEffect, useCallback, useRef } from 'react'
import { api, type SystemMetrics, type LogEntry } from '../api.ts'
import { CircleTimer } from '../components/CircleTimer.tsx'

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  const parts: string[] = []
  if (d > 0) parts.push(`${d}d`)
  if (h > 0) parts.push(`${h}h`)
  if (m > 0) parts.push(`${m}m`)
  parts.push(`${s}s`)
  return parts.join(' ')
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

function UsageBar({ used, total, label, title }: { used: number; total: number; label: string; title?: string }) {
  const pct = total > 0 ? (used / total) * 100 : 0
  const color = pct > 90 ? 'bg-red' : pct > 70 ? 'bg-yellow' : 'bg-accent'
  return (
    <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border last:border-b-0">
      <span className="text-xs text-text w-32 truncate" title={title || label}>{label}</span>
      <div className="flex-1 h-2 bg-surface-alt rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      <span className="text-[10px] text-text-dim w-20 text-right">{formatBytes(total - (total > 0 ? (total - used) : 0))} / {formatBytes(total)}</span>
      <span className="text-[10px] text-text-muted w-12 text-right">{pct.toFixed(1)}%</span>
    </div>
  )
}

const LEVEL_COLORS: Record<string, string> = {
  ERROR: 'text-red',
  WARN: 'text-yellow',
  INFO: 'text-text',
  DEBUG: 'text-text-muted',
  TRACE: 'text-text-muted',
}

export default function System() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const logRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [levelFilter, setLevelFilter] = useState<string>('ALL')

  const fetchMetrics = useCallback(async () => {
    try { setMetrics(await api.getSystemMetrics()) } catch { /* ignore */ }
  }, [])

  const fetchLogs = useCallback(async () => {
    try { setLogs(await api.getLogs(200)) } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    fetchMetrics()
    fetchLogs()
    const metricsId = setInterval(fetchMetrics, 5000)
    const logsId = setInterval(fetchLogs, 3000)
    return () => { clearInterval(metricsId); clearInterval(logsId) }
  }, [fetchMetrics, fetchLogs])

  useEffect(() => {
    if (autoScroll && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  const handleLogScroll = () => {
    if (!logRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logRef.current
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 40)
  }

  const LOG_LEVELS = ['ALL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'] as const
  const LEVEL_PRIORITY: Record<string, number> = { ERROR: 0, WARN: 1, INFO: 2, DEBUG: 3, TRACE: 4 }

  const filteredLogs = levelFilter === 'ALL'
    ? logs
    : logs.filter(entry => (LEVEL_PRIORITY[entry.level] ?? 99) <= (LEVEL_PRIORITY[levelFilter] ?? 99))

  return (
    <div className="space-y-6 animate-fade-in">
      <h1 className="text-sm font-semibold text-text-dim flex items-center gap-2">
        <span className="text-accent">~</span> system
        <CircleTimer interval={5000} size={14} strokeWidth={1.5} className="text-accent" />
      </h1>

      {/* Uptime */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="uptime" value={metrics ? formatUptime(metrics.uptime_secs) : '—'} color="text-green" />
        <StatCard label="process cpu" value={metrics ? `${metrics.process_cpu_percent.toFixed(1)}%` : '—'} color="text-blue" />
        <StatCard label="process memory" value={metrics ? formatBytes(metrics.process_memory_bytes) : '—'} color="text-accent" />
        <StatCard label="system cpu" value={metrics ? `${metrics.system_cpu_percent.toFixed(1)}%` : '—'} color="text-yellow" />
      </div>

      {/* System memory & swap */}
      {metrics && (
        <div>
          <h2 className="text-xs text-text-dim mb-3">
            <span className="text-accent">$</span> memory
          </h2>
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            <UsageBar used={metrics.system_memory_used} total={metrics.system_memory_total} label="RAM" />
            {metrics.system_swap_total > 0 && (
              <UsageBar used={metrics.system_swap_used} total={metrics.system_swap_total} label="Swap" />
            )}
          </div>
        </div>
      )}

      {/* Disks */}
      {metrics && metrics.disks.length > 0 && (
        <div>
          <h2 className="text-xs text-text-dim mb-3">
            <span className="text-accent">$</span> disks
          </h2>
          <div className="bg-surface border border-border rounded-lg overflow-hidden">
            {metrics.disks.map((d, i) => (
              <UsageBar
                key={i}
                used={d.total_bytes - d.available_bytes}
                total={d.total_bytes}
                label={`${d.mount_point} (${d.fs_type})`}
                title={`${d.mount_point} (${d.fs_type})`}
              />
            ))}
          </div>
        </div>
      )}

      {/* Logs */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs text-text-dim">
            <span className="text-accent">$</span> logs
          </h2>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1">
              {LOG_LEVELS.map(level => (
                <button
                  key={level}
                  onClick={() => setLevelFilter(level)}
                  className={`text-[10px] px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
                    levelFilter === level
                      ? 'bg-accent text-bg font-medium'
                      : 'text-text-dim hover:text-accent'
                  }`}
                >
                  {level}
                </button>
              ))}
            </div>
            <button
              onClick={fetchLogs}
              className="text-[10px] text-text-dim hover:text-accent transition-colors cursor-pointer"
            >
              refresh
            </button>
          </div>
        </div>
        <div
          ref={logRef}
          onScroll={handleLogScroll}
          className="bg-surface border border-border rounded-lg p-3 h-80 overflow-y-auto font-mono text-[11px] leading-relaxed"
        >
          {filteredLogs.length === 0 ? (
            <div className="text-text-muted">no log entries</div>
          ) : (
            filteredLogs.map((entry, i) => {
              const time = new Date(entry.timestamp_ms).toLocaleTimeString()
              const levelColor = LEVEL_COLORS[entry.level] || 'text-text'
              return (
                <div key={i} className="flex gap-2 hover:bg-surface-alt rounded px-1">
                  <span className="text-text-muted shrink-0">{time}</span>
                  <span className={`shrink-0 w-12 ${levelColor}`}>{entry.level.padEnd(5)}</span>
                  <span className="text-text-dim shrink-0 max-w-32 truncate">{entry.target}</span>
                  <span className="text-text break-all">{entry.message}</span>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
