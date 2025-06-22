import { useState } from 'react'
import './App.css'

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
  Findings: Finding[] | null
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
      let warning: string | null = null
      try {
        const parsed = JSON.parse(text)
        if (parsed && parsed.PhaseResults && Array.isArray(parsed.PhaseResults)) {
          data = parsed
        } else if (parsed.result) {
          // Backend returned a string result with a warning
          warning = parsed.warning || null
        }
      } catch (e) {
        // fallback: not a valid JSON
      }
      if (!res.ok) throw new Error((data as any)?.error || 'Scan failed')
      setScanResult(data)
      if (warning) setScanError(warning)
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
      // LLM service health
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

  // Export as PDF (stub)
  const handleExportPDF = () => {
    alert('PDF export coming soon!')
  }

  // Filtering logic
  const filterFindings = (findings: Finding[] | null) => {
    if (!findings) return []
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

  const getSeverityClass = (severity: string) => {
    return `ss-severity ${severity.toLowerCase()}`
  }

  const getStatusClass = (status: string) => {
    return `ss-status ${status}`
  }

  return (
    <div className="ss-root">
      <header className="ss-header">
        <div className="ss-header-content">
          <h1>SentinelSecure</h1>
          <nav>
            <button 
              className={`ss-nav-button ${view === 'dashboard' ? 'active' : ''}`}
              onClick={() => setView('dashboard')}
            >
              <span className="nav-icon">🏠</span>
              <span className="nav-text">Dashboard</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'scan' ? 'active' : ''}`}
              onClick={() => setView('scan')}
            >
              <span className="nav-icon">🔍</span>
              <span className="nav-text">Scan</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'logs' ? 'active' : ''}`}
              onClick={() => { setView('logs'); fetchLogs(); }}
            >
              <span className="nav-icon">📋</span>
              <span className="nav-text">Logs</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'status' ? 'active' : ''}`}
              onClick={() => { setView('status'); fetchStatus(); }}
            >
              <span className="nav-icon">⚡</span>
              <span className="nav-text">Status</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'llm' ? 'active' : ''}`}
              onClick={() => setView('llm')}
            >
              <span className="nav-icon">🤖</span>
              <span className="nav-text">AI Analysis</span>
            </button>
          </nav>
        </div>
      </header>

      <main className="ss-main">
        {view === 'dashboard' && (
          <div className="ss-welcome">
            <h2>Welcome to SentinelSecure</h2>
            <p>
              Advanced cybersecurity scanning platform powered by AI. 
              Discover vulnerabilities, analyze threats, and secure your infrastructure.
            </p>
            <div className="ss-feature-grid">
              <div className="ss-feature-card" onClick={() => setView('scan')}>
                <div className="ss-feature-icon">🔍</div>
                <h3>Network Scanning</h3>
                <p>Comprehensive vulnerability assessment and network reconnaissance</p>
              </div>
              <div className="ss-feature-card" onClick={() => setView('llm')}>
                <div className="ss-feature-icon">🤖</div>
                <h3>AI Analysis</h3>
                <p>Intelligent threat analysis powered by advanced language models</p>
              </div>
              <div className="ss-feature-card" onClick={() => setView('status')}>
                <div className="ss-feature-icon">⚡</div>
                <h3>System Status</h3>
                <p>Monitor service health and system performance in real-time</p>
              </div>
              <div className="ss-feature-card" onClick={() => setView('logs')}>
                <div className="ss-feature-icon">📋</div>
                <h3>Activity Logs</h3>
                <p>Track system activities and security events</p>
              </div>
            </div>
          </div>
        )}

        {view === 'scan' && (
          <div className="ss-card">
            <h2>🔍 Vulnerability Scanner</h2>
            <div className="ss-input-group">
              <input
                type="text"
                className="ss-input"
                value={scanTarget}
                onChange={e => setScanTarget(e.target.value)}
                placeholder="Enter target IP or hostname"
                disabled={scanLoading}
              />
              <button 
                className="ss-button" 
                onClick={handleScan} 
                disabled={scanLoading || !scanTarget}
              >
                {scanLoading ? (
                  <span className="ss-loading">
                    <div className="ss-spinner"></div>
                    <span>Scanning...</span>
                  </span>
                ) : (
                  'Start Scan'
                )}
              </button>
            </div>

            {scanError && (
              <div className="ss-error">
                <strong>Error:</strong> {scanError}
              </div>
            )}

            {scanResult && Array.isArray(scanResult.PhaseResults) && (
              <div>
                <div className="flex items-center justify-between mb-3" style={{ flexWrap: 'wrap', gap: '1rem' }}>
                  <div>
                    <h3 className="mb-1">Scan Report: <span style={{ color: '#00d4ff' }}>{scanResult.Target}</span></h3>
                    <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>
                      Started: {new Date(scanResult.Timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div className="ss-actions">
                    <button className="ss-button-secondary" onClick={handleExportJSON}>
                      📄 Export JSON
                    </button>
                    <button className="ss-button-secondary" onClick={handleExportPDF}>
                      📑 Export PDF
                    </button>
                  </div>
                </div>

                {/* Filters */}
                <div className="ss-filters">
                  <input
                    type="text"
                    className="ss-input"
                    placeholder="Search findings..."
                    value={findingFilter}
                    onChange={e => setFindingFilter(e.target.value)}
                  />
                  <select 
                    className="ss-select" 
                    value={severityFilter} 
                    onChange={e => setSeverityFilter(e.target.value)}
                  >
                    <option value="">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Info">Info</option>
                  </select>
                  <select 
                    className="ss-select" 
                    value={phaseFilter} 
                    onChange={e => setPhaseFilter(e.target.value)}
                  >
                    <option value="">All Phases</option>
                    {scanResult.PhaseResults.map((p, i) => (
                      <option key={i} value={p.PhaseName}>{p.PhaseName}</option>
                    ))}
                  </select>
                </div>

                {/* Phase Results */}
                <div>
                  {scanResult.PhaseResults.map((phase, idx) => (
                    <div key={idx} className="ss-phase-card">
                      <details open={phase.PhaseName === 'LLMAnalysis' || !phase.Success}>
                        <summary className="ss-phase-summary">
                          <div className="flex items-center gap-2" style={{ flexWrap: 'wrap' }}>
                            <span>{phase.Success ? '✅' : '❌'}</span>
                            <span>{phase.PhaseName}</span>
                            <span className="ss-status ok" style={{ fontSize: '0.75rem' }}>
                              {filterFindings(phase.Findings).length} findings
                            </span>
                          </div>
                          {phase.Error && (
                            <span className="ss-error" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                              {phase.Error}
                            </span>
                          )}
                        </summary>
                        
                        <div className="ss-phase-content">
                          {filterFindings(phase.Findings).length > 0 && (
                            <div className="ss-table-wrapper">
                              <table className="ss-table">
                                <thead>
                                  <tr>
                                    <th>Category</th>
                                    <th>Description</th>
                                    <th>Service</th>
                                    <th>Port</th>
                                    <th>Severity</th>
                                    <th>Details</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {filterFindings(phase.Findings).map((finding, i) => (
                                    <tr key={i}>
                                      <td>{finding.Category}</td>
                                      <td style={{ maxWidth: '300px' }}>{finding.Description}</td>
                                      <td>{finding.Service}</td>
                                      <td>{finding.Port || '-'}</td>
                                      <td>
                                        <span className={getSeverityClass(finding.Severity)}>
                                          {finding.Severity}
                                        </span>
                                      </td>
                                      <td>
                                        {Object.entries(finding.Data || {}).map(([k, v]) => (
                                          <div key={k} style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>
                                            <strong>{k}:</strong> {v}
                                          </div>
                                        ))}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}

                          {phase.RawOutput && (
                            <details style={{ marginTop: '1rem' }}>
                              <summary style={{ color: '#94a3b8', cursor: 'pointer', marginBottom: '0.5rem' }}>
                                Raw Output
                              </summary>
                              <pre className="ss-code">{phase.RawOutput}</pre>
                            </details>
                          )}
                        </div>
                      </details>
                    </div>
                  ))}
                </div>

                {/* LLM Analysis Highlight */}
                {scanResult.PhaseResults.some(p => p.PhaseName === 'LLMAnalysis') && (
                  <div className="ss-llm-analysis">
                    <h3>🤖 AI Security Analysis</h3>
                    <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>
                      {scanResult.PhaseResults.find(p => p.PhaseName === 'LLMAnalysis')?.Findings?.[0]?.Description}
                    </div>
                  </div>
                )}

                {/* Raw JSON Debug */}
                <details style={{ marginTop: '2rem' }}>
                  <summary style={{ color: '#94a3b8', cursor: 'pointer' }}>
                    Raw JSON Report (Debug)
                  </summary>
                  <pre className="ss-code" style={{ marginTop: '1rem' }}>{scanRaw}</pre>
                </details>
              </div>
            )}
          </div>
        )}

        {view === 'logs' && (
          <div className="ss-card">
            <h2>📋 System Logs</h2>
            <button 
              className="ss-button-secondary mb-3" 
              onClick={fetchLogs} 
              disabled={logsLoading}
            >
              {logsLoading ? (
                <span className="ss-loading">
                  <div className="ss-spinner"></div>
                  <span>Refreshing...</span>
                </span>
              ) : (
                '🔄 Refresh Logs'
              )}
            </button>

            {logsError && (
              <div className="ss-error">
                <strong>Error:</strong> {logsError}
              </div>
            )}

            {logs && logs.length === 0 && (
              <div className="text-center" style={{ color: '#94a3b8', padding: '2rem' }}>
                No logs found.
              </div>
            )}

            {logs && logs.length > 0 && (
              <div className="ss-code" style={{ maxHeight: '400px', overflow: 'auto' }}>
                {logs.map((log, i) => (
                  <div key={i} style={{ marginBottom: '0.5rem', padding: '0.25rem 0' }}>
                    <span style={{ color: '#00d4ff' }}>[{i + 1}]</span> {log}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {view === 'status' && (
          <div className="ss-card">
            <h2>⚡ System Status</h2>
            <button 
              className="ss-button-secondary mb-3" 
              onClick={fetchStatus} 
              disabled={statusLoading}
            >
              {statusLoading ? (
                <span className="ss-loading">
                  <div className="ss-spinner"></div>
                  <span>Checking...</span>
                </span>
              ) : (
                '🔄 Refresh Status'
              )}
            </button>

            <div className="ss-feature-grid">
              <div className="ss-feature-card">
                <div className="ss-feature-icon">🔧</div>
                <h3>Backend API</h3>
                <div className={getStatusClass(backendStatus)}>
                  {backendStatus === 'ok' && '✅ Online'}
                  {backendStatus === 'down' && '❌ Offline'}
                  {backendStatus === 'unknown' && '❓ Unknown'}
                </div>
              </div>
              <div className="ss-feature-card">
                <div className="ss-feature-icon">🤖</div>
                <h3>LLM Service</h3>
                <div className={getStatusClass(llmStatus)}>
                  {llmStatus === 'ok' && '✅ Online'}
                  {llmStatus === 'down' && '❌ Offline'}
                  {llmStatus === 'unknown' && '❓ Unknown'}
                </div>
              </div>
            </div>
          </div>
        )}

        {view === 'llm' && (
          <div className="ss-card">
            <h2>🤖 AI Threat Analysis</h2>
            <textarea
              className="ss-input"
              value={llmInput}
              onChange={e => setLlmInput(e.target.value)}
              placeholder="Paste suspicious text, logs, or threat data here for AI analysis..."
              rows={8}
              style={{ 
                width: '100%', 
                minHeight: '200px', 
                resize: 'vertical',
                fontFamily: 'monospace'
              }}
              disabled={llmLoading}
            />
            <button 
              className="ss-button mt-2" 
              onClick={handleLlmAnalyze} 
              disabled={llmLoading || !llmInput}
            >
              {llmLoading ? (
                <span className="ss-loading">
                  <div className="ss-spinner"></div>
                  <span>Analyzing...</span>
                </span>
              ) : (
                '🔍 Analyze with AI'
              )}
            </button>

            {llmError && (
              <div className="ss-error">
                <strong>Error:</strong> {llmError}
              </div>
            )}

            {llmResult && (
              <div className="ss-llm-analysis">
                <h3>Analysis Results</h3>
                <pre style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6, color: '#e0e6ed' }}>
                  {llmResult}
                </pre>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

export default App