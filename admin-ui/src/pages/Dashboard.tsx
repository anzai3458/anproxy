import { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import type { AppDispatch, RootState } from '../store';
import { fetchStats } from '../store/statsSlice';
import { fetchTargets } from '../store/targetsSlice';
import { fetchStaticDirs } from '../store/staticDirsSlice';
import StatsCard from '../components/StatsCard';
import DataTable from '../components/DataTable';

export default function Dashboard() {
  const dispatch = useDispatch<AppDispatch>();
  const stats = useSelector((s: RootState) => s.stats.data);
  const targets = useSelector((s: RootState) => s.targets.items);
  const staticDirs = useSelector((s: RootState) => s.staticDirs.items);

  useEffect(() => {
    dispatch(fetchStats());
    dispatch(fetchTargets());
    dispatch(fetchStaticDirs());
    const id = setInterval(() => dispatch(fetchStats()), 5000);
    return () => clearInterval(id);
  }, [dispatch]);

  const expiryColor = stats
    ? stats.cert_expiry_days > 30 ? 'text-green-400' : stats.cert_expiry_days > 7 ? 'text-yellow-400' : 'text-red-400'
    : undefined;

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-white mb-6">Dashboard</h1>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatsCard label="Active Connections" value={stats?.active_connections ?? '-'} />
        <StatsCard label="Total Requests" value={stats?.total_requests ?? '-'} />
        <StatsCard label="Errors" value={stats?.errors ?? '-'} color={stats && stats.errors > 0 ? 'text-red-400' : undefined} />
        <StatsCard label="Cert Expiry (days)" value={stats?.cert_expiry_days ?? '-'} color={expiryColor} />
      </div>
      <div className="grid lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-xl p-4">
          <h2 className="text-white font-bold mb-3">Proxy Targets</h2>
          <DataTable headers={['Host', 'Address']} rows={targets.map((t) => [t.host, t.address])} />
        </div>
        <div className="bg-gray-800 rounded-xl p-4">
          <h2 className="text-white font-bold mb-3">Static Dirs</h2>
          <DataTable headers={['Host', 'Directory']} rows={staticDirs.map((s) => [s.host, s.dir])} />
        </div>
      </div>
    </div>
  );
}
