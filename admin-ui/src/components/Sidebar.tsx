import { useSelector } from 'react-redux';
import { NavLink } from 'react-router-dom';
import type { RootState } from '../store';

const links = [
  { to: '/', label: 'Dashboard', icon: '\u25A6' },
  { to: '/targets', label: 'Targets', icon: '\u21C4' },
  { to: '/static-dirs', label: 'Static', icon: '\uD83D\uDCC1' },
  { to: '/certs', label: 'Certs', icon: '\uD83D\uDD12' },
  { to: '/speed-test', label: 'Speed', icon: '\u26A1' },
];

export default function Sidebar() {
  const isAuth = useSelector((s: RootState) => s.auth.isAuthenticated);
  if (!isAuth) return null;

  return (
    <nav className="hidden md:flex flex-col w-16 bg-gray-800 min-h-screen items-center py-4 gap-2">
      {links.map((l) => (
        <NavLink
          key={l.to}
          to={l.to}
          className={({ isActive }) =>
            `w-12 h-12 flex items-center justify-center rounded-lg text-lg ${isActive ? 'bg-blue-600 text-white' : 'text-gray-400 hover:bg-gray-700'}`
          }
          end={l.to === '/'}
          title={l.label}
        >
          {l.icon}
        </NavLink>
      ))}
    </nav>
  );
}
