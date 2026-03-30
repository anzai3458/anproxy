import { useState, useEffect, createContext, useContext, type ReactNode } from 'react'
import { HashRouter, Routes, Route, Navigate, useLocation, useNavigate, NavLink } from 'react-router-dom'
import { api } from './api.ts'
import Login from './pages/Login.tsx'
import Dashboard from './pages/Dashboard.tsx'
import Targets from './pages/Targets.tsx'
import StaticDirs from './pages/StaticDirs.tsx'
import Certs from './pages/Certs.tsx'
import SpeedTest from './pages/SpeedTest.tsx'

const AuthContext = createContext<{
  authed: boolean
  setAuthed: (v: boolean) => void
}>({ authed: false, setAuthed: () => {} })

export function useAuth() {
  return useContext(AuthContext)
}

const NAV = [
  { to: '/', label: 'overview' },
  { to: '/targets', label: 'targets' },
  { to: '/static', label: 'static' },
  { to: '/certs', label: 'certs' },
  { to: '/speed', label: 'speed' },
] as const

function Layout({ children }: { children: ReactNode }) {
  const { setAuthed } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const handleLogout = async () => {
    try { await api.logout() } catch { /* ignore */ }
    setAuthed(false)
    navigate('/login')
  }

  return (
    <div className="min-h-dvh flex flex-col md:flex-row">
      {/* Desktop sidebar */}
      <aside className="hidden md:flex flex-col w-52 shrink-0 border-r border-border bg-surface">
        <div className="p-5 pb-3">
          <span className="text-accent font-semibold text-sm tracking-wide">anproxy</span>
          <span className="blink text-accent ml-0.5">_</span>
        </div>
        <nav className="flex-1 px-2 py-2 flex flex-col gap-0.5">
          {NAV.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `block px-3 py-2 text-xs rounded transition-colors ${
                  isActive
                    ? 'bg-accent-glow text-accent'
                    : 'text-text-dim hover:text-text hover:bg-surface-alt'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <button
          onClick={handleLogout}
          className="mx-2 mb-4 px-3 py-2 text-xs text-text-dim hover:text-red rounded transition-colors text-left hover:bg-surface-alt cursor-pointer"
        >
          logout
        </button>
      </aside>

      {/* Main content */}
      <main className="flex-1 min-w-0 pb-16 md:pb-0">
        <div className="max-w-5xl mx-auto px-4 py-6 md:px-8 md:py-8">
          {children}
        </div>
      </main>

      {/* Mobile bottom nav */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 bg-surface border-t border-border flex items-center justify-around px-1 py-1 z-50">
        {NAV.map(({ to, label }) => {
          const active = to === '/' ? location.pathname === '/' : location.pathname.startsWith(to)
          return (
            <NavLink
              key={to}
              to={to}
              className={`flex-1 text-center py-2.5 text-[10px] rounded transition-colors ${
                active ? 'text-accent bg-accent-glow' : 'text-text-dim'
              }`}
            >
              {label}
            </NavLink>
          )
        })}
      </nav>
    </div>
  )
}

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { authed } = useAuth()
  if (!authed) return <Navigate to="/login" replace />
  return <Layout>{children}</Layout>
}

export default function App() {
  const [authed, setAuthed] = useState(() => {
    return sessionStorage.getItem('anproxy_authed') === '1'
  })

  useEffect(() => {
    if (authed) sessionStorage.setItem('anproxy_authed', '1')
    else sessionStorage.removeItem('anproxy_authed')
  }, [authed])

  useEffect(() => {
    const handler = () => setAuthed(false)
    window.addEventListener('auth:expired', handler)
    return () => window.removeEventListener('auth:expired', handler)
  }, [])

  return (
    <AuthContext value={{ authed, setAuthed }}>
      <HashRouter>
        <Routes>
          <Route path="/login" element={authed ? <Navigate to="/" replace /> : <Login />} />
          <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/targets" element={<ProtectedRoute><Targets /></ProtectedRoute>} />
          <Route path="/static" element={<ProtectedRoute><StaticDirs /></ProtectedRoute>} />
          <Route path="/certs" element={<ProtectedRoute><Certs /></ProtectedRoute>} />
          <Route path="/speed" element={<ProtectedRoute><SpeedTest /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </HashRouter>
    </AuthContext>
  )
}
