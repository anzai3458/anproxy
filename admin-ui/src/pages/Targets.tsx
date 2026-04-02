import { useState, useEffect, type FormEvent } from 'react'
import { api, type Target, type Stats } from '../api.ts'
import Modal from '../components/Modal.tsx'

export default function Targets() {
  const [items, setItems] = useState<Target[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<Target | null>(null)
  const [formHost, setFormHost] = useState('')
  const [formBackend, setFormBackend] = useState('')
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetch = async () => {
    try {
      const [targets, s] = await Promise.all([
        api.getTargets(),
        api.getStats()
      ])
      setItems(targets)
      setStats(s)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetch() }, [])

  const openAdd = () => {
    setEditing(null)
    setFormHost('')
    setFormBackend('')
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (t: Target) => {
    setEditing(t)
    setFormHost(t.host)
    setFormBackend(t.backend)
    setFormError('')
    setModalOpen(true)
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setFormError('')
    setSaving(true)
    try {
      if (editing) {
        await api.updateTarget(editing.host, formBackend)
      } else {
        await api.addTarget(formHost, formBackend)
      }
      setModalOpen(false)
      await fetch()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (host: string) => {
    if (!confirm(`Delete target "${host}"?`)) return
    setDeleting(host)
    try {
      await api.deleteTarget(host)
      await fetch()
    } catch { /* ignore */ } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-text-dim">
          <span className="text-accent">~</span> targets
        </h1>
        <button onClick={openAdd} className="text-xs bg-accent hover:bg-accent-hover text-bg font-semibold rounded px-3 py-1.5 transition-colors cursor-pointer">
          + add
        </button>
      </div>

      {error && <div className="text-red text-xs">{error}</div>}

      {loading ? (
        <p className="text-xs text-text-dim">loading...</p>
      ) : items.length === 0 ? (
        <p className="text-xs text-text-muted">no proxy targets configured</p>
      ) : (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          {/* Header */}
          <div className="hidden sm:grid sm:grid-cols-[1fr_1fr_auto] px-4 py-2 text-[10px] text-text-muted uppercase tracking-widest border-b border-border">
            <span>host</span>
            <span>backend</span>
            <span className="w-24 text-right">actions</span>
          </div>
          {items.map((t) => (
            <div key={t.host} className="sm:grid sm:grid-cols-[1fr_1fr_auto] px-4 py-3 border-b border-border last:border-b-0 text-xs items-center">
              <a href={`https://${t.host}:${stats?.proxy_port ?? 443}`} target="_blank" rel="noopener noreferrer" className="text-text font-medium truncate hover:text-accent transition-colors">{t.host}</a>
              <div className="text-text-dim truncate mt-0.5 sm:mt-0">{t.backend}</div>
              <div className="flex gap-3 justify-end mt-2 sm:mt-0 w-24">
                <button onClick={() => openEdit(t)} className="text-text-dim hover:text-accent transition-colors cursor-pointer">edit</button>
                <button
                  onClick={() => handleDelete(t.host)}
                  disabled={deleting === t.host}
                  className="text-text-dim hover:text-red transition-colors cursor-pointer disabled:opacity-50"
                >
                  {deleting === t.host ? '...' : 'del'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? 'edit target' : 'add target'}>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[10px] text-text-dim uppercase tracking-widest mb-1.5">host</label>
            <input
              type="text"
              value={formHost}
              onChange={(e) => setFormHost(e.target.value)}
              disabled={!!editing}
              required
              placeholder="example.com"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-accent transition-colors disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-[10px] text-text-dim uppercase tracking-widest mb-1.5">backend</label>
            <input
              type="text"
              value={formBackend}
              onChange={(e) => setFormBackend(e.target.value)}
              required
              placeholder="http://127.0.0.1:8080 or file:///var/www"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-accent transition-colors"
            />
            <p className="text-[10px] text-text-muted mt-1.5">
              Use http:// for proxy targets or file:/// for static file serving
            </p>
          </div>
          {formError && (
            <div className="text-red text-xs bg-red/10 border border-red/20 rounded px-3 py-2">{formError}</div>
          )}
          <div className="flex gap-3 justify-end">
            <button type="button" onClick={() => setModalOpen(false)} className="text-xs text-text-dim hover:text-text px-3 py-1.5 cursor-pointer">cancel</button>
            <button type="submit" disabled={saving} className="text-xs bg-accent hover:bg-accent-hover disabled:opacity-50 text-bg font-semibold rounded px-4 py-1.5 transition-colors cursor-pointer">
              {saving ? 'saving...' : 'save'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
