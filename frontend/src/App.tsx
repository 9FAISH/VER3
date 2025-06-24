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

// Utility: Parse log string to object { timestamp, type, message }
function parseLog(log: string) {
  // Example log: "2024-05-01 12:34:56 [ERROR] Something failed"
  const match = log.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(INFO|WARNING|ERROR)\] (.*)$/i)
  if (match) {
    return {
      timestamp: match[1],
      type: match[2].toLowerCase(),
      message: match[3],
    }
  }
  return { timestamp: '', type: 'info', message: log }
}

function App() {
  const [view, setView] = useState<'dashboard' | 'scan' | 'logs' | 'status'>('dashboard')
  const [navOpen, setNavOpen] = useState(false)
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
  // Logs table state
  const [logSearch, setLogSearch] = useState('')
  const [logTypeFilter, setLogTypeFilter] = useState('')
  const [logPage, setLogPage] = useState(1)
  const logsPerPage = 12
  // Derived: parsed, filtered, searched logs
  const parsedLogs = (logs || []).map(parseLog)
  const filteredLogs = parsedLogs.filter(l =>
    (!logTypeFilter || l.type === logTypeFilter) &&
    (logSearch === '' || l.message.toLowerCase().includes(logSearch.toLowerCase()))
  )
  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / logsPerPage))
  const paginatedLogs = filteredLogs.slice((logPage-1)*logsPerPage, logPage*logsPerPage)
  // Icon and color for log type
  const logTypeIcon = (type: string) => {
    if (type === 'error') return <span style={{color:'#ef4444'}} title="Error">⛔</span>
    if (type === 'warning') return <span style={{color:'#f59e0b'}} title="Warning">⚠️</span>
    return <span style={{color:'#00d4ff'}} title="Info">ℹ️</span>
  }
  const logTypeClass = (type: string) => {
    if (type === 'error') return 'ss-severity critical'
    if (type === 'warning') return 'ss-severity high'
    return 'ss-severity info'
  }
  // Status UI state
  const [backendStatus, setBackendStatus] = useState<'unknown' | 'ok' | 'down'>('unknown')
  const [statusLoading, setStatusLoading] = useState(false)

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
    try {
      // Backend health
      const backendRes = await fetch('http://localhost:8080/api/health')
      setBackendStatus(backendRes.ok ? 'ok' : 'down')
    } catch {
      setBackendStatus('down')
    }
    setStatusLoading(false)
  }

  return (
    <div className="ss-root">
      <header className="ss-header">
        <div className="ss-header-content">
          <h1>SentinelSecure</h1>
          {/* Hamburger for mobile */}
          <button
            className="ss-hamburger"
            aria-label={navOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={navOpen}
            aria-controls="main-nav"
            onClick={() => setNavOpen(v => !v)}
            style={{ display: 'none' }}
          >
            <span className="ss-hamburger-bar"></span>
            <span className="ss-hamburger-bar"></span>
            <span className="ss-hamburger-bar"></span>
          </button>
          <nav
            id="main-nav"
            aria-label="Main navigation"
            role="navigation"
            className={navOpen ? 'open' : ''}
          >
            <button 
              className={`ss-nav-button ${view === 'dashboard' ? 'active' : ''}`}
              onMouseDown={() => {
                setView('dashboard');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              onTouchStart={() => {
                setView('dashboard');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              aria-current={view === 'dashboard' ? 'page' : undefined}
              tabIndex={0}
            >
              <span className="nav-icon" aria-hidden="true">🏠</span>
              <span className="nav-text">Dashboard</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'scan' ? 'active' : ''}`}
              onMouseDown={() => {
                setView('scan');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              onTouchStart={() => {
                setView('scan');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              aria-current={view === 'scan' ? 'page' : undefined}
              tabIndex={0}
            >
              <span className="nav-icon" aria-hidden="true">🔍</span>
              <span className="nav-text">Scan</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'logs' ? 'active' : ''}`}
              onMouseDown={() => {
                setView('logs');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              onTouchStart={() => {
                setView('logs');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              aria-current={view === 'logs' ? 'page' : undefined}
              tabIndex={0}
            >
              <span className="nav-icon" aria-hidden="true">📋</span>
              <span className="nav-text">Logs</span>
            </button>
            <button 
              className={`ss-nav-button ${view === 'status' ? 'active' : ''}`}
              onMouseDown={() => {
                setView('status');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              onTouchStart={() => {
                setView('status');
                if (window.innerWidth <= 768) setNavOpen(false);
              }}
              aria-current={view === 'status' ? 'page' : undefined}
              tabIndex={0}
            >
              <span className="nav-icon" aria-hidden="true">⚡</span>
              <span className="nav-text">Status</span>
            </button>
          </nav>
        </div>
      </header>

      <main className="ss-main" id="main-content">
        {view === 'dashboard' && (
          <section className="ss-welcome" aria-labelledby="welcome-heading">
            <h2 id="welcome-heading">Welcome to SentinelSecure</h2>
            <p>
              Advanced cybersecurity scanning platform powered by AI. 
              Discover vulnerabilities, analyze threats, and secure your infrastructure.
            </p>
            <div className="ss-feature-grid" role="list">
              <div className="ss-feature-card" tabIndex={0} role="listitem" aria-label="Network Scanning: Comprehensive vulnerability assessment and network reconnaissance">
                <span className="ss-feature-icon" aria-hidden="true">🔍</span>
                <h3>Network Scanning</h3>
                <p>Comprehensive vulnerability assessment and network reconnaissance</p>
              </div>
              <div className="ss-feature-card" tabIndex={0} role="listitem" aria-label="System Status: Monitor service health and system performance in real-time">
                <span className="ss-feature-icon" aria-hidden="true">⚡</span>
                <h3>System Status</h3>
                <p>Monitor service health and system performance in real-time</p>
              </div>
              <div className="ss-feature-card" tabIndex={0} role="listitem" aria-label="Activity Logs: Track system activities and security events">
                <span className="ss-feature-icon" aria-hidden="true">📋</span>
                <h3>Activity Logs</h3>
                <p>Track system activities and security events</p>
              </div>
            </div>
          </section>
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
                              {phase.Findings && phase.Findings.length} findings
                            </span>
                          </div>
                          {phase.Error && (
                            <span className="ss-error" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                              {phase.Error}
                            </span>
                          )}
                      </summary>
                        <div className="ss-phase-content">
                          {(!phase.Findings || phase.Findings.length === 0) && (
                            <div style={{ color: '#94a3b8', padding: '1rem 0' }}>No findings for this phase.</div>
                          )}
                          {phase.Findings && phase.Findings.length > 0 && (
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
                                  {phase.Findings.map((finding, i) => {
                                    // Helper to check if output is long
                                    const isLong = (str: string) => str && str.length > 200;
                                    // Truncate helper
                                    const truncate = (str: string) => str && str.length > 200 ? str.slice(0, 200) + '...' : str;
                                    // For details, show only first key/value if long, else all
                                    const detailsKeys = finding.Data ? Object.keys(finding.Data) : [];
                                    return (
                                      <tr key={i}>
                                        <td>{finding.Category}</td>
                                        <td>
                                          {isLong(finding.Description) ? (
                                            <>
                                              {truncate(finding.Description)}
                                              <details style={{ marginTop: '0.5rem' }}>
                                                <summary style={{ color: '#00d4ff', cursor: 'pointer' }}>View Full Output</summary>
                                                <pre className="ss-code" style={{ whiteSpace: 'pre-wrap', marginTop: '0.5rem' }}>{finding.Description}</pre>
                                              </details>
                                            </>
                                          ) : (
                                            finding.Description
                                          )}
                                        </td>
                                        <td>{finding.Service}</td>
                                        <td>{finding.Port || '-'}</td>
                                        <td>
                                          <span className={getSeverityClass(finding.Severity)}>
                                            {finding.Severity}
                                          </span>
                                        </td>
                                        <td>
                                          {detailsKeys.length === 0 ? (
                                            <span style={{ color: '#64748b' }}>-</span>
                                          ) : (
                                            detailsKeys.map((k, idx) => {
                                              const v = finding.Data[k];
                                              return isLong(v) ? (
                                                <div key={k} style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>
                                                  <strong>{k}:</strong> {truncate(v)}
                                                  <details style={{ marginTop: '0.25rem' }}>
                                                    <summary style={{ color: '#00d4ff', cursor: 'pointer' }}>View Full Output</summary>
                                                    <pre className="ss-code" style={{ whiteSpace: 'pre-wrap', marginTop: '0.25rem' }}>{v}</pre>
                                                  </details>
                                                </div>
                                              ) : (
                                                <div key={k} style={{ fontSize: '0.75rem', marginBottom: '0.25rem' }}>
                                                  <strong>{k}:</strong> {v}
                                                </div>
                                              );
                                            })
                                          )}
                                        </td>
                              </tr>
                                    );
                                  })}
                          </tbody>
                        </table>
                            </div>
                      )}
                          {/* Show tool errors or important raw output if present */}
                          {phase.RawOutput && phase.RawOutput.toLowerCase().includes('not found') && (
                            <div className="ss-error" style={{ marginTop: '1rem', fontSize: '0.95rem' }}>
                              {phase.RawOutput}
                            </div>
                          )}
                          {/* Optionally, show raw output toggle for advanced users */}
                          {phase.RawOutput && !phase.RawOutput.toLowerCase().includes('not found') && (
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
            <div className="ss-input-group" style={{marginBottom:'1rem', flexWrap:'wrap', gap:'0.5rem'}}>
              <input
                className="ss-input"
                type="text"
                placeholder="Search logs..."
                value={logSearch}
                onChange={e => { setLogSearch(e.target.value); setLogPage(1); }}
                style={{minWidth:'180px'}}
                disabled={logsLoading}
              />
              <select
                className="ss-select"
                value={logTypeFilter}
                onChange={e => { setLogTypeFilter(e.target.value); setLogPage(1); }}
                disabled={logsLoading}
                style={{minWidth:'140px'}}
              >
                <option value="">All Types</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
              </select>
              <button 
                className="ss-button-secondary"
                onClick={fetchLogs}
                disabled={logsLoading}
                style={{marginLeft:'auto'}}
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
            </div>
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
              <div className="ss-table-wrapper">
                <table className="ss-table">
                  <thead>
                    <tr>
                      <th></th>
                      <th>Timestamp</th>
                      <th>Type</th>
                      <th>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedLogs.map((log, i) => (
                      <tr key={i}>
                        <td>{logTypeIcon(log.type)}</td>
                        <td style={{whiteSpace:'nowrap',color:'#94a3b8'}}>{log.timestamp}</td>
                        <td><span className={logTypeClass(log.type)}>{log.type.toUpperCase()}</span></td>
                        <td style={{maxWidth:'480px',wordBreak:'break-word'}}>{log.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {/* Pagination controls */}
                <div style={{display:'flex',justifyContent:'center',alignItems:'center',gap:'1rem',margin:'1rem 0'}}>
                  <button className="ss-button-secondary" onClick={()=>setLogPage(p=>Math.max(1,p-1))} disabled={logPage===1}>Prev</button>
                  <span style={{color:'#00d4ff'}}>Page {logPage} of {totalPages}</span>
                  <button className="ss-button-secondary" onClick={()=>setLogPage(p=>Math.min(totalPages,p+1))} disabled={logPage===totalPages}>Next</button>
                </div>
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
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

export default App