import { useState } from 'react'
import './App.css'

function App() {
  const [view, setView] = useState<'dashboard' | 'scan' | 'logs' | 'status' | 'llm'>('dashboard')
  // Scan UI state
  const [scanTarget, setScanTarget] = useState('127.0.0.1')
  const [scanResult, setScanResult] = useState<string | null>(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)
  // Logs UI state
  const [logs, setLogs] = useState<string[] | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)
  const [logsError, setLogsError] = useState<string | null>(null)
  // Status UI state
  const [backendStatus, setBackendStatus] = useState<'unknown' | 'ok' | 'down'>('unknown')
  const [llmStatus, setLlmStatus] = useState<'unknown' | 'ok' | 'down'>('unknown')
  const [statusLoading, setStatusLoading] = useState(false)
  // LLM Analysis UI state
  const [llmInput, setLlmInput] = useState('')
  const [llmResult, setLlmResult] = useState<string | null>(null)
  const [llmLoading, setLlmLoading] = useState(false)
  const [llmError, setLlmError] = useState<string | null>(null)

  const handleScan = async () => {
    setScanLoading(true)
    setScanError(null)
    setScanResult(null)
    try {
      const res = await fetch('http://localhost:8080/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Scan failed')
      setScanResult(data.result)
    } catch (err: any) {
      setScanError(err.message)
    } finally {
      setScanLoading(false)
    }
  }

  const fetchLogs = async () => {
    setLogsLoading(true)
    setLogsError(null)
    setLogs(null)
    try {
      const res = await fetch('http://localhost:8080/api/logs')
      const data = await res.json()
      if (!res.ok) throw new Error('Failed to fetch logs')
      setLogs(Array.isArray(data) ? data : [])
    } catch (err: any) {
      setLogsError(err.message)
    } finally {
      setLogsLoading(false)
    }
  }

  const fetchStatus = async () => {
    setStatusLoading(true)
    setBackendStatus('unknown')
    setLlmStatus('unknown')
    try {
      // Backend health
      const backendRes = await fetch('http://localhost:8080/api/health')
      setBackendStatus(backendRes.ok ? 'ok' : 'down')
    } catch {
      setBackendStatus('down')
    }
    try {
      // LLM service health (placeholder, update port/path as needed)
      const llmRes = await fetch('http://localhost:8000/health')
      setLlmStatus(llmRes.ok ? 'ok' : 'down')
    } catch {
      setLlmStatus('down')
    }
    setStatusLoading(false)
  }

  const handleLlmAnalyze = async () => {
    setLlmLoading(true)
    setLlmError(null)
    setLlmResult(null)
    try {
      const res = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: llmInput })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'LLM analysis failed')
      setLlmResult(data.result)
    } catch (err: any) {
      setLlmError(err.message)
    } finally {
      setLlmLoading(false)
    }
  }

  return (
    <div className="ss-root">
      <header className="ss-header">
        <h1>SentinelSecure Dashboard</h1>
        <nav>
          <button onClick={() => setView('dashboard')}>Dashboard</button>
          <button onClick={() => setView('scan')}>Scan</button>
          <button onClick={() => { setView('logs'); fetchLogs(); }}>Logs</button>
          <button onClick={() => { setView('status'); fetchStatus(); }}>Status</button>
          <button onClick={() => setView('llm')}>LLM Analysis</button>
        </nav>
      </header>
      <main className="ss-main">
        {view === 'dashboard' && <div>Welcome to SentinelSecure! Select a feature above.</div>}
        {view === 'scan' && (
          <div>
            <h2>Run Vulnerability/Network Scan</h2>
            <input
              type="text"
              value={scanTarget}
              onChange={e => setScanTarget(e.target.value)}
              placeholder="Target IP or hostname"
              disabled={scanLoading}
            />
            <button onClick={handleScan} disabled={scanLoading || !scanTarget}>
              {scanLoading ? 'Scanning...' : 'Start Scan'}
            </button>
            {scanError && <div style={{ color: 'red' }}>Error: {scanError}</div>}
            {scanResult && (
              <pre style={{ background: '#222', color: '#0f0', padding: 10, marginTop: 10, maxHeight: 300, overflow: 'auto' }}>{scanResult}</pre>
            )}
          </div>
        )}
        {view === 'logs' && (
          <div>
            <h2>System Logs</h2>
            <button onClick={fetchLogs} disabled={logsLoading} style={{ marginBottom: 8 }}>
              {logsLoading ? 'Refreshing...' : 'Refresh Logs'}
            </button>
            {logsError && <div style={{ color: 'red' }}>Error: {logsError}</div>}
            {logs && logs.length === 0 && <div>No logs found.</div>}
            {logs && logs.length > 0 && (
              <ul style={{ background: '#222', color: '#fff', padding: 10, maxHeight: 300, overflow: 'auto' }}>
                {logs.map((log, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>{log}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        {view === 'status' && (
          <div>
            <h2>System Status</h2>
            <button onClick={fetchStatus} disabled={statusLoading} style={{ marginBottom: 8 }}>
              {statusLoading ? 'Refreshing...' : 'Refresh Status'}
            </button>
            <div>Backend API: <b style={{ color: backendStatus === 'ok' ? 'lime' : 'red' }}>{backendStatus}</b></div>
            <div>LLM Service: <b style={{ color: llmStatus === 'ok' ? 'lime' : 'red' }}>{llmStatus}</b></div>
            <div style={{ fontSize: 12, color: '#888', marginTop: 8 }}>
              (LLM service health is a placeholder; update port/path as needed)
            </div>
          </div>
        )}
        {view === 'llm' && (
          <div>
            <h2>LLM Threat Analysis</h2>
            <textarea
              value={llmInput}
              onChange={e => setLlmInput(e.target.value)}
              placeholder="Paste suspicious text, logs, or threat data here..."
              rows={6}
              style={{ width: '100%', background: '#222', color: '#eee', border: '1px solid #444', borderRadius: 4, padding: 8, fontSize: '1rem', marginBottom: 8 }}
              disabled={llmLoading}
            />
            <button onClick={handleLlmAnalyze} disabled={llmLoading || !llmInput}>
              {llmLoading ? 'Analyzing...' : 'Analyze'}
            </button>
            {llmError && <div style={{ color: 'red' }}>Error: {llmError}</div>}
            {llmResult && (
              <pre style={{ background: '#222', color: '#0ff', padding: 10, marginTop: 10, maxHeight: 300, overflow: 'auto' }}>{llmResult}</pre>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

export default App
