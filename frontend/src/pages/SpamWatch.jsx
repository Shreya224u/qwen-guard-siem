import { useEffect, useMemo, useState } from 'react'
import { ShieldAlert, Search, Ban, CheckCircle2 } from 'lucide-react'
import { logsApi } from '../api'
import { formatTimestamp } from '../utils/dateTime'

export default function SpamWatch({ events, onStatusChange, token, activeFilename, onSelectFile }) {
  const [query, setQuery] = useState('')
  const [files, setFiles] = useState([])
  const [filesLoading, setFilesLoading] = useState(true)
  const [filesError, setFilesError] = useState('')
  useEffect(() => {
    let current = true
    logsApi.uploads(token)
      .then(items => { if (current) setFiles(items) })
      .catch(error => { if (current) setFilesError(error.message || 'Could not load uploaded files.') })
      .finally(() => { if (current) setFilesLoading(false) })
    return () => { current = false }
  }, [token])
  const alerts = useMemo(() => events.filter(e => /spam|phish|mail|email|bulk/i.test(`${e.type} ${e.message}`)), [events])
  const visible = alerts.filter(e => `${e.id} ${e.source} ${e.type} ${e.message}`.toLowerCase().includes(query.toLowerCase()))
  return <div className="page-stack">
    <div className="page-heading"><div><div className="eyebrow">THREAT MONITORING / ALERT CATEGORIES</div><h1>Spam watch</h1><p>Review SIEM alerts categorized by suspicious message indicators and severity.</p></div></div>
    <section className="panel spam-scan-panel"><div className="spam-scan-copy"><strong>Filter alerts by uploaded file</strong><span>Choose a file to show only alerts generated from that upload.</span></div><div className="spam-scan-controls"><select className="select-control" value={activeFilename} disabled={filesLoading || !files.length} onChange={event => onSelectFile?.(event.target.value)}><option value="">{filesLoading ? 'Loading uploaded files…' : files.length ? 'Select an uploaded file' : 'No uploaded files'}</option>{files.map(file => <option key={file.filename} value={file.filename}>{file.filename} ({file.logs_count.toLocaleString()} logs)</option>)}</select></div></section>
    {filesError && <div className="notice error" role="alert">{filesError}</div>}
    {!activeFilename && <div className="info-banner"><ShieldAlert size={15}/> Select one uploaded file above. Spam alerts will be limited to that file.</div>}
    <div className="kpi-grid three"><article className="kpi-card"><div className="kpi-top">Matching alerts<span className="kpi-icon orange"><ShieldAlert size={17}/></span></div><div className="kpi-value">{alerts.length}</div><div className="kpi-bottom">Returned by the SIEM API</div></article><article className="kpi-card"><div className="kpi-top">Open review<span className="kpi-icon red"><Ban size={17}/></span></div><div className="kpi-value">{alerts.filter(e => !['Resolved', 'False positive'].includes(e.status)).length}</div><div className="kpi-bottom">Awaiting review</div></article><article className="kpi-card"><div className="kpi-top">Resolved<span className="kpi-icon green"><CheckCircle2 size={17}/></span></div><div className="kpi-value">{alerts.filter(e => e.status === 'Resolved').length}</div><div className="kpi-bottom">Stored alert status</div></article></div>
    <section className="panel table-panel"><div className="panel-header padded"><div><h3>Alert review</h3><p>Matching alerts from the SIEM service</p></div><label className="table-search"><Search size={15}/><input placeholder="Search alerts..." value={query} onChange={e => setQuery(e.target.value)}/></label></div>
      <div className="spam-list">{visible.map(e => <article className="spam-row" key={e.id}><div className={`spam-symbol ${e.severity.toLowerCase()}`}><ShieldAlert size={19}/></div><div className="spam-main"><div><strong>{e.type}</strong><span className={`severity-badge ${e.severity.toLowerCase()}`}>{e.severity}</span></div><p>{e.message}</p><small>{e.id} · {e.source} · {e.time ? formatTimestamp(e.time) : 'Timestamp unavailable'}</small></div><div className="spam-actions"><span className={`status-pill ${e.status.toLowerCase().replaceAll(' ', '-')}`}>{e.status}</span>{e.status !== 'Resolved' && <button className="secondary-button compact" onClick={() => onStatusChange?.(e, 'Resolved')}><CheckCircle2 size={14}/> Resolve</button>}</div></article>)}
      {!visible.length && <div className="empty-state"><ShieldAlert size={24}/><strong>No matching alerts</strong><span>Try another search or check the Alert Queue.</span></div>}</div>
    </section>
  </div>
}
