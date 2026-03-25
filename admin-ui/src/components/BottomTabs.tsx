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

export default function BottomTabs() {
  const isAuth = useSelector((s: RootState) => s.auth.isAuthenticated);
  if (!isAuth) return null;

  return (
    <nav className="flex md:hidden fixed bottom-0 left-0 right-0 bg-gray-800 border-t border-gray-700 z-50">
      {links.map((l) => (
        <NavLink
          key={l.to}
          to={l.to}
          className={({ isActive }) =>
            `flex-1 flex flex-col items-center py-2 text-xs ${isActive ? 'text-blue-400' : 'text-gray-400'}`
          }
          end={l.to === '/'}
        >
          <span className="text-lg">{l.icon}</span>
          <span>{l.label}</span>
        </NavLink>
      ))}
    </nav>
  );
}
