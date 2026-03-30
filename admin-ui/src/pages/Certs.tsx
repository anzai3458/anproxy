import { useState, useEffect } from 'react'
import { api, type CertInfo } from '../api.ts'

export default function Certs() {
  const [certs, setCerts] = useState<CertInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [reloading, setReloading] = useState(false)
  const [reloadMsg, setReloadMsg] = useState('')

  const fetchCerts = async () => {
    try {
      setCerts(await api.getCerts())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchCerts() }, [])

  const handleReload = async () => {
    setReloading(true)
    setReloadMsg('')
    try {
      await api.reloadCerts()
      setReloadMsg('certificates reloaded')
      await fetchCerts()
      setTimeout(() => setReloadMsg(''), 3000)
    } catch (e) {
      setReloadMsg(e instanceof Error ? e.message : 'Reload failed')
    } finally {
      setReloading(false)
    }
  }

  const expiryColor = certs
    ? certs.days_until_expiry > 30 ? 'text-green' : certs.days_until_expiry > 7 ? 'text-yellow' : 'text-red'
    : 'text-text'

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-text-dim">
          <span className="text-accent">~</span> certificates
        </h1>
        <button
          onClick={handleReload}
          disabled={reloading}
          className="text-xs bg-accent hover:bg-accent-hover disabled:opacity-50 text-bg font-semibold rounded px-3 py-1.5 transition-colors cursor-pointer"
        >
          {reloading ? 'reloading...' : 'reload'}
        </button>
      </div>

      {reloadMsg && (
        <div className={`text-xs rounded px-3 py-2 ${
          reloadMsg.includes('reloaded')
            ? 'text-green bg-green/10 border border-green/20'
            : 'text-red bg-red/10 border border-red/20'
        }`}>
          {reloadMsg}
        </div>
      )}

      {error && <div className="text-red text-xs">{error}</div>}

      {loading ? (
        <p className="text-xs text-text-dim">loading...</p>
      ) : certs ? (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <Row label="cert path" value={certs.cert_path} />
          <Row label="key path" value={certs.key_path} />
          <Row label="expiry" value={certs.expiry} />
          <Row label="days remaining" value={`${certs.days_until_expiry}`} valueClass={expiryColor} />
        </div>
      ) : (
        <p className="text-xs text-text-muted">no certificate info available</p>
      )}
    </div>
  )
}

function Row({ label, value, valueClass }: { label: string; value: string; valueClass?: string }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center px-4 py-3 border-b border-border last:border-b-0 text-xs gap-1 sm:gap-0">
      <span className="text-text-dim w-36 shrink-0">{label}</span>
      <span className={`text-text break-all ${valueClass || ''}`}>{value}</span>
    </div>
  )
}
