import { useState, useEffect, type FormEvent } from 'react'
import { api, type StaticDir } from '../api.ts'
import Modal from '../components/Modal.tsx'

export default function StaticDirs() {
  const [items, setItems] = useState<StaticDir[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<StaticDir | null>(null)
  const [formHost, setFormHost] = useState('')
  const [formDir, setFormDir] = useState('')
  const [formError, setFormError] = useState('')
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  const fetchData = async () => {
    try {
      setItems(await api.getStaticDirs())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  const openAdd = () => {
    setEditing(null)
    setFormHost('')
    setFormDir('')
    setFormError('')
    setModalOpen(true)
  }

  const openEdit = (s: StaticDir) => {
    setEditing(s)
    setFormHost(s.host)
    setFormDir(s.dir)
    setFormError('')
    setModalOpen(true)
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setFormError('')
    setSaving(true)
    try {
      if (editing) {
        await api.updateStaticDir(editing.host, formDir)
      } else {
        await api.addStaticDir(formHost, formDir)
      }
      setModalOpen(false)
      await fetchData()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (host: string) => {
    if (!confirm(`Delete static dir "${host}"?`)) return
    setDeleting(host)
    try {
      await api.deleteStaticDir(host)
      await fetchData()
    } catch { /* ignore */ } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-text-dim">
          <span className="text-accent">~</span> static dirs
        </h1>
        <button onClick={openAdd} className="text-xs bg-accent hover:bg-accent-hover text-bg font-semibold rounded px-3 py-1.5 transition-colors cursor-pointer">
          + add
        </button>
      </div>

      {error && <div className="text-red text-xs">{error}</div>}

      {loading ? (
        <p className="text-xs text-text-dim">loading...</p>
      ) : items.length === 0 ? (
        <p className="text-xs text-text-muted">no static directories configured</p>
      ) : (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <div className="hidden sm:grid sm:grid-cols-[1fr_1fr_auto] px-4 py-2 text-[10px] text-text-muted uppercase tracking-widest border-b border-border">
            <span>host</span>
            <span>directory</span>
            <span className="w-24 text-right">actions</span>
          </div>
          {items.map((s) => (
            <div key={s.host} className="sm:grid sm:grid-cols-[1fr_1fr_auto] px-4 py-3 border-b border-border last:border-b-0 text-xs items-center">
              <div className="text-text font-medium truncate">{s.host}</div>
              <div className="text-text-dim truncate mt-0.5 sm:mt-0">{s.dir}</div>
              <div className="flex gap-3 justify-end mt-2 sm:mt-0 w-24">
                <button onClick={() => openEdit(s)} className="text-text-dim hover:text-accent transition-colors cursor-pointer">edit</button>
                <button
                  onClick={() => handleDelete(s.host)}
                  disabled={deleting === s.host}
                  className="text-text-dim hover:text-red transition-colors cursor-pointer disabled:opacity-50"
                >
                  {deleting === s.host ? '...' : 'del'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editing ? 'edit static dir' : 'add static dir'}>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[10px] text-text-dim uppercase tracking-widest mb-1.5">host</label>
            <input
              type="text"
              value={formHost}
              onChange={(e) => setFormHost(e.target.value)}
              disabled={!!editing}
              required
              placeholder="static.example.com"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-accent transition-colors disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-[10px] text-text-dim uppercase tracking-widest mb-1.5">directory</label>
            <input
              type="text"
              value={formDir}
              onChange={(e) => setFormDir(e.target.value)}
              required
              placeholder="/var/www/html"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-accent transition-colors"
            />
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
