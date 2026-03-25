import { useDispatch, useSelector } from 'react-redux';
import type { AppDispatch, RootState } from '../store';
import { runSpeedTest } from '../store/speedTestSlice';
import StatsCard from '../components/StatsCard';

export default function SpeedTest() {
  const dispatch = useDispatch<AppDispatch>();
  const { phase, latency, downloadMbps, uploadMbps, error } = useSelector((s: RootState) => s.speedTest);

  const running = phase !== 'idle' && phase !== 'done';

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-white mb-6">Speed Test</h1>
      <button
        onClick={() => dispatch(runSpeedTest())}
        disabled={running}
        className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed mb-6 font-medium"
      >
        {running ? 'Running...' : 'Run Test'}
      </button>

      {running && (
        <div className="mb-6 text-gray-400">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
            {phase === 'ping' && 'Measuring latency...'}
            {phase === 'download' && 'Testing download speed...'}
            {phase === 'upload' && 'Testing upload speed...'}
          </div>
        </div>
      )}

      {error && <div className="bg-red-900/50 text-red-300 rounded p-3 mb-4">{error}</div>}

      {(latency != null || downloadMbps != null || uploadMbps != null) && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <StatsCard label="Latency" value={latency != null ? `${latency} ms` : '-'} />
          <StatsCard label="Download" value={downloadMbps != null ? `${downloadMbps} Mbps` : '-'} />
          <StatsCard label="Upload" value={uploadMbps != null ? `${uploadMbps} Mbps` : '-'} />
        </div>
      )}
    </div>
  );
}
