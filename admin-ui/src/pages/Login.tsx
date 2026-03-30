import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api.ts'
import { useAuth } from '../App.tsx'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { setAuthed } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await api.login(username, password)
      setAuthed(true)
      navigate('/', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-dvh flex items-center justify-center p-4 bg-bg">
      <div className="w-full max-w-sm animate-fade-in">
        <div className="mb-8">
          <div className="text-accent font-semibold text-lg tracking-wide">
            anproxy<span className="blink">_</span>
          </div>
          <p className="text-text-dim text-xs mt-2">https reverse proxy management</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[10px] text-text-dim uppercase tracking-widest mb-1.5">
              username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              required
              className="w-full bg-surface border border-border rounded px-3 py-2.5 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-accent transition-colors"
              placeholder="admin"
            />
          </div>
          <div>
            <label className="block text-[10px] text-text-dim uppercase tracking-widest mb-1.5">
              password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-surface border border-border rounded px-3 py-2.5 text-sm text-text placeholder:text-text-muted focus:outline-none focus:border-accent transition-colors"
              placeholder="********"
            />
          </div>

          {error && (
            <div className="text-red text-xs bg-red/10 border border-red/20 rounded px-3 py-2">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent hover:bg-accent-hover disabled:opacity-50 text-bg font-semibold text-sm rounded px-3 py-2.5 transition-colors cursor-pointer"
          >
            {loading ? 'connecting...' : 'login'}
          </button>
        </form>
      </div>
    </div>
  )
}
