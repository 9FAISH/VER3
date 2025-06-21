import { useState } from 'react'
import './App.css'
// import jsPDF from 'jspdf' // Uncomment if jsPDF is installed

// Types for structured scan report
interface Finding {
  Phase: string
  Category: string
  Target: string
  Port: number
  Service: string
  Description: string
  Data: Record<string, string>
  Severity: string
}
interface PhaseResult {
  PhaseName: string
  Findings: Finding[]
  RawOutput: string
  Success: boolean
  Error: string
}
interface ScanReport {
  Target: string
  Timestamp: string
  PhaseResults: PhaseResult[]
  LLMAnalysis: string
}

function App() {
  const [view, setView] = useState<'dashboard' | 'scan' | 'logs' | 'status' | 'llm'>('dashboard')
  // Scan UI state
  const [scanTarget, setScanTarget] = useState('127.0.0.1')
  const [scanResult, setScanResult] = useState<ScanReport | null>(null)
  const [scanRaw, setScanRaw] = useState<string | null>(null)
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
  // Filtering/search state
  const [findingFilter, setFindingFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('')
  const [phaseFilter, setPhaseFilter] = useState<string>('')

  const handleScan = async () => {
    setScanLoading(true)
    setScanError(null)
    setScanResult(null)
    setScanRaw(null)
    try {
      const res = await fetch('http://localhost:8080/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget })
      })
      const text = await res.text()
      setScanRaw(text)
      let data: ScanReport | null = null
      try {
        data = JSON.parse(text)
      } catch (e) {
        // fallback: not a valid JSON
      }
      if (!res.ok) throw new Error((data as any)?.error || 'Scan failed')
      setScanResult(data)
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

  // Helper for severity color
  const severityColor = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return '#ff1744'
      case 'high': return '#ff9100'
      case 'medium': return '#ffd600'
      case 'low': return '#00b0ff'
      default: return '#bdbdbd'
    }
  }

  // Export as JSON
  const handleExportJSON = () => {
    if (!scanResult) return
    const blob = new Blob([JSON.stringify(scanResult, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentinelsecure_report_${scanResult.Target || 'scan'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }
  // Export as PDF (stub, requires jsPDF)
  const handleExportPDF = () => {
    // TODO: Implement PDF export using jsPDF or similar
    alert('PDF export coming soon!')
  }

  // Filtering logic
  const filterFindings = (findings: Finding[]) => {
    return findings.filter(f => {
      const matchesText = findingFilter === '' ||
        f.Description.toLowerCase().includes(findingFilter.toLowerCase()) ||
        f.Category.toLowerCase().includes(findingFilter.toLowerCase()) ||
        f.Service.toLowerCase().includes(findingFilter.toLowerCase()) ||
        Object.values(f.Data || {}).some(v => v.toLowerCase().includes(findingFilter.toLowerCase()))
      const matchesSeverity = !severityFilter || f.Severity.toLowerCase() === severityFilter.toLowerCase()
      const matchesPhase = !phaseFilter || f.Phase.toLowerCase() === phaseFilter.toLowerCase()
      return matchesText && matchesSeverity && matchesPhase
    })
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
            {scanResult && Array.isArray(scanResult.PhaseResults) ? (
              <div style={{ marginTop: 16 }}>
                <h3>Scan Report for <span style={{ color: '#8be9fd' }}>{scanResult.Target}</span></h3>
                <div style={{ fontSize: 13, color: '#888', marginBottom: 8 }}>Scan started: {scanResult.Timestamp || '(time not set)'}</div>
                {/* Export and filter controls */}
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12, flexWrap: 'wrap' }}>
                  <button onClick={handleExportJSON} style={{ background: '#444', color: '#fff', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer' }}>Export JSON</button>
                  <button onClick={handleExportPDF} style={{ background: '#444', color: '#fff', border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer' }}>Export PDF</button>
                  <input
                    type="text"
                    placeholder="Search findings..."
                    value={findingFilter}
                    onChange={e => setFindingFilter(e.target.value)}
                    style={{ background: '#222', color: '#eee', border: '1px solid #444', borderRadius: 4, padding: '6px 10px', minWidth: 180 }}
                  />
                  <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} style={{ background: '#222', color: '#eee', border: '1px solid #444', borderRadius: 4, padding: '6px 10px' }}>
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Info">Info</option>
                  </select>
                  <select value={phaseFilter} onChange={e => setPhaseFilter(e.target.value)} style={{ background: '#222', color: '#eee', border: '1px solid #444', borderRadius: 4, padding: '6px 10px' }}>
                    <option value="">All Phases</option>
                    {scanResult.PhaseResults.map((p, i) => <option key={i} value={p.PhaseName}>{p.PhaseName}</option>)}
                  </select>
                </div>
                {/* Accordion for phases */}
                <div>
                  {scanResult.PhaseResults.map((phase, idx) => (
                    <details key={idx} open={phase.PhaseName === 'LLMAnalysis' || !phase.Success} style={{ marginBottom: 12, border: '1px solid #333', borderRadius: 6, background: phase.PhaseName === 'LLMAnalysis' ? '#222a' : '#181818' }}>
                      <summary style={{ fontWeight: 600, color: phase.Success ? '#8be9fd' : '#ff1744', cursor: 'pointer', padding: 6 }}>
                        {phase.PhaseName} {phase.Success ? '✔️' : '❌'} ({filterFindings(phase.Findings).length} findings)
                        {phase.Error && <span style={{ color: '#ff1744', marginLeft: 8 }}>Error: {phase.Error}</span>}
                      </summary>
                      {/* Findings table */}
                      {filterFindings(phase.Findings).length > 0 && (
                        <table style={{ width: '100%', marginTop: 8, fontSize: 14, borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ background: '#222' }}>
                              <th style={{ textAlign: 'left', padding: 4 }}>Category</th>
                              <th style={{ textAlign: 'left', padding: 4 }}>Description</th>
                              <th style={{ textAlign: 'left', padding: 4 }}>Service</th>
                              <th style={{ textAlign: 'left', padding: 4 }}>Port</th>
                              <th style={{ textAlign: 'left', padding: 4 }}>Severity</th>
                              <th style={{ textAlign: 'left', padding: 4 }}>Tool/Data</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filterFindings(phase.Findings).map((f, i) => (
                              <tr key={i} style={{ background: i % 2 ? '#181818' : '#232323' }}>
                                <td style={{ padding: 4 }}>{f.Category}</td>
                                <td style={{ padding: 4 }}>{f.Description}</td>
                                <td style={{ padding: 4 }}>{f.Service}</td>
                                <td style={{ padding: 4 }}>{f.Port}</td>
                                <td style={{ padding: 4, color: severityColor(f.Severity), fontWeight: 600 }}>{f.Severity}</td>
                                <td style={{ padding: 4 }}>{Object.entries(f.Data || {}).map(([k, v]) => <div key={k}><b>{k}:</b> {v}</div>)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                      {/* Raw output for debugging */}
                      {phase.RawOutput && (
                        <details style={{ marginTop: 8 }}>
                          <summary style={{ color: '#888', cursor: 'pointer' }}>Raw Output</summary>
                          <pre style={{ background: '#111', color: '#eee', padding: 8, borderRadius: 4, maxHeight: 200, overflow: 'auto' }}>{phase.RawOutput}</pre>
                        </details>
                      )}
                    </details>
                  ))}
                </div>
                {/* LLM Analysis highlight */}
                {scanResult.PhaseResults.some(p => p.PhaseName === 'LLMAnalysis') && (
                  <div style={{ background: '#0ff2', color: '#111', borderRadius: 8, padding: 16, marginTop: 18, boxShadow: '0 2px 8px #0ff4' }}>
                    <h3 style={{ color: '#0ff', margin: 0 }}>LLM Recommendations</h3>
                    <div style={{ whiteSpace: 'pre-wrap', fontSize: 16 }}>
                      {scanResult.PhaseResults.find(p => p.PhaseName === 'LLMAnalysis')?.Findings[0]?.Description}
                    </div>
                  </div>
                )}
                {/* Raw JSON fallback/debug */}
                <details style={{ marginTop: 18 }}>
                  <summary style={{ color: '#888', cursor: 'pointer' }}>Raw JSON Report</summary>
                  <pre style={{ background: '#111', color: '#eee', padding: 8, borderRadius: 4, maxHeight: 300, overflow: 'auto' }}>{scanRaw}</pre>
                </details>
              </div>
            ) : scanError ? (
              <div style={{ color: 'red', marginTop: 16 }}>Error: {scanError}</div>
            ) : scanRaw ? (
              <div style={{ color: 'red', marginTop: 16 }}>Scan failed or invalid report format.</div>
            ) : null}
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
