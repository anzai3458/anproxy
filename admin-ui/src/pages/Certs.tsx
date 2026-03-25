import { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import type { AppDispatch, RootState } from '../store';
import { fetchCerts, reloadCerts } from '../store/certsSlice';

export default function Certs() {
  const dispatch = useDispatch<AppDispatch>();
  const { data, loading } = useSelector((s: RootState) => s.certs);

  useEffect(() => { dispatch(fetchCerts()); }, [dispatch]);

  const expiryColor = data
    ? data.days_until_expiry > 30 ? 'text-green-400' : data.days_until_expiry > 7 ? 'text-yellow-400' : 'text-red-400'
    : 'text-white';

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white">Certificates</h1>
        <button
          onClick={() => dispatch(reloadCerts())}
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-500"
        >
          Reload Certificates
        </button>
      </div>
      {loading ? (
        <div className="text-gray-400">Loading...</div>
      ) : data ? (
        <div className="bg-gray-800 rounded-xl p-6 space-y-4">
          <div>
            <span className="text-gray-400 text-sm">Certificate Path</span>
            <p className="text-white font-mono">{data.cert_path}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Key Path</span>
            <p className="text-white font-mono">{data.key_path}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Expiry Date</span>
            <p className="text-white">{data.expiry}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Days Until Expiry</span>
            <p className={`text-2xl font-bold ${expiryColor}`}>{data.days_until_expiry}</p>
          </div>
        </div>
      ) : (
        <div className="text-gray-500">No certificate data available</div>
      )}
    </div>
  );
}
