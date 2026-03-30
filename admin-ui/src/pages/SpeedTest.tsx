import { useState } from 'react'
import { api } from '../api.ts'

type Phase = 'idle' | 'ping' | 'download' | 'upload' | 'done'

export default function SpeedTest() {
  const [phase, setPhase] = useState<Phase>('idle')
  const [latency, setLatency] = useState<number | null>(null)
  const [download, setDownload] = useState<number | null>(null)
  const [upload, setUpload] = useState<number | null>(null)
  const [error, setError] = useState('')

  const run = async () => {
    setError('')
    setLatency(null)
    setDownload(null)
    setUpload(null)

    try {
      // Ping
      setPhase('ping')
      const pings: number[] = []
      for (let i = 0; i < 3; i++) {
        const t0 = performance.now()
        await api.speedTestPing()
        pings.push(performance.now() - t0)
      }
      setLatency(Math.round(Math.min(...pings)))

      // Download
      setPhase('download')
      const dlStart = performance.now()
      const dlRes = await api.speedTestDownload()
      const dlBlob = await dlRes.blob()
      const dlElapsed = (performance.now() - dlStart) / 1000
      const dlMbps = (dlBlob.size * 8) / (dlElapsed * 1_000_000)
      setDownload(Math.round(dlMbps * 100) / 100)

      // Upload
      setPhase('upload')
      const payload = new Blob([new Uint8Array(10 * 1024 * 1024)])
      const ulRes = await api.speedTestUpload(payload)
      const ulData = await ulRes.json()
      if (ulData.ok) {
        setUpload(Math.round(ulData.data.mbps * 100) / 100)
      }

      setPhase('done')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Test failed')
      setPhase('idle')
    }
  }

  const running = phase !== 'idle' && phase !== 'done'

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-text-dim">
          <span className="text-accent">~</span> speed test
        </h1>
        <button
          onClick={run}
          disabled={running}
          className="text-xs bg-accent hover:bg-accent-hover disabled:opacity-50 text-bg font-semibold rounded px-3 py-1.5 transition-colors cursor-pointer"
        >
          {running ? `testing ${phase}...` : 'run test'}
        </button>
      </div>

      {error && (
        <div className="text-red text-xs bg-red/10 border border-red/20 rounded px-3 py-2">{error}</div>
      )}

      <div className="grid grid-cols-3 gap-3">
        <ResultCard label="latency" value={latency !== null ? `${latency}` : '—'} unit="ms" active={phase === 'ping'} />
        <ResultCard label="download" value={download !== null ? `${download}` : '—'} unit="mbps" active={phase === 'download'} />
        <ResultCard label="upload" value={upload !== null ? `${upload}` : '—'} unit="mbps" active={phase === 'upload'} />
      </div>

      {/* Terminal-style log */}
      {phase !== 'idle' && (
        <div className="bg-surface border border-border rounded-lg p-4 text-xs space-y-1.5">
          <LogLine done text="initializing speed test" />
          <LogLine done={phase !== 'ping'} active={phase === 'ping'} text="measuring latency (3 pings)" />
          {latency !== null && <LogLine done text={`  latency: ${latency}ms`} dim />}
          {(phase === 'download' || phase === 'upload' || phase === 'done') && (
            <LogLine done={phase !== 'download'} active={phase === 'download'} text="downloading 10MB test file" />
          )}
          {download !== null && <LogLine done text={`  download: ${download} mbps`} dim />}
          {(phase === 'upload' || phase === 'done') && (
            <LogLine done={phase !== 'upload'} active={phase === 'upload'} text="uploading 10MB test file" />
          )}
          {upload !== null && <LogLine done text={`  upload: ${upload} mbps`} dim />}
          {phase === 'done' && <LogLine done text="test complete" accent />}
        </div>
      )}
    </div>
  )
}

function ResultCard({ label, value, unit, active }: { label: string; value: string; unit: string; active: boolean }) {
  return (
    <div className={`bg-surface border rounded-lg p-4 transition-colors ${active ? 'border-accent' : 'border-border'}`}>
      <div className="text-[10px] text-text-dim uppercase tracking-widest mb-2">{label}</div>
      <div className="text-xl font-bold text-text">{value}</div>
      <div className="text-[10px] text-text-muted mt-0.5">{unit}</div>
    </div>
  )
}

function LogLine({ done, active, text, dim, accent }: { done?: boolean; active?: boolean; text: string; dim?: boolean; accent?: boolean }) {
  const color = accent ? 'text-accent' : dim ? 'text-text-dim' : 'text-text'
  return (
    <div className={`flex items-center gap-2 ${color}`}>
      {active ? (
        <span className="text-accent blink">{'>'}</span>
      ) : done ? (
        <span className="text-green">{'>'}</span>
      ) : (
        <span className="text-text-muted">{'>'}</span>
      )}
      <span>{text}</span>
    </div>
  )
}
