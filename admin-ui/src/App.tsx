import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import type { RootState } from './store';
import Sidebar from './components/Sidebar';
import BottomTabs from './components/BottomTabs';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Targets from './pages/Targets';
import StaticDirs from './pages/StaticDirs';
import Certs from './pages/Certs';
import SpeedTest from './pages/SpeedTest';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuth = useSelector((s: RootState) => s.auth.isAuthenticated);
  if (!isAuth) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <HashRouter>
      <div className="flex min-h-screen bg-gray-900 text-white">
        <Sidebar />
        <main className="flex-1 pb-16 md:pb-0">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
            <Route path="/targets" element={<ProtectedRoute><Targets /></ProtectedRoute>} />
            <Route path="/static-dirs" element={<ProtectedRoute><StaticDirs /></ProtectedRoute>} />
            <Route path="/certs" element={<ProtectedRoute><Certs /></ProtectedRoute>} />
            <Route path="/speed-test" element={<ProtectedRoute><SpeedTest /></ProtectedRoute>} />
          </Routes>
        </main>
        <BottomTabs />
      </div>
    </HashRouter>
  );
}
