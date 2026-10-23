import { useEffect, useMemo, useState } from 'react'
import { Search, SlidersHorizontal, Download, Eye, CheckCheck, ArrowUpRight } from 'lucide-react'
import Modal from '../components/Modal'
import { formatTimestamp, timestampIso } from '../utils/dateTime'

const severityClass = s => `severity-badge ${String(s).toLowerCase()}`
export default function Alerts({ events, onStatusChange, onOpenInvestigation, globalQuery, focusEventId }) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('All')
  const [status, setStatus] = useState('All')
  const [selected, setSelected] = useState(null)
  useEffect(() => {
    if (!focusEventId) return undefined
    setQuery('')
    setSeverity('All')
    setStatus('All')
    let secondFrame = 0
    const frame = window.requestAnimationFrame(() => {
      secondFrame = window.requestAnimationFrame(() => {
        const row = [...document.querySelectorAll('[data-alert-event-id]')]
          .find(item => item.dataset.alertEventId === String(focusEventId))
        if (!row) return
        row.scrollIntoView({ behavior: 'smooth', block: 'center' })
        row.classList.add('alert-target-row')
        window.setTimeout(() => row.classList.remove('alert-target-row'), 3500)
      })
    })
    return () => { window.cancelAnimationFrame(frame); window.cancelAnimationFrame(secondFrame) }
  }, [focusEventId])
  const filtered = useMemo(() => events.filter(e => {
    const q = `${e.id} ${e.source} ${e.type} ${e.message}`.toLowerCase()
    const isFocusedEvent = String(e.id) === String(focusEventId)
    const matchesSearch = isFocusedEvent || q.includes(`${globalQuery || ''} ${query}`.trim().toLowerCase())
    return matchesSearch && (isFocusedEvent || severity === 'All' || e.severity === severity) && (isFocusedEvent || status === 'All' || e.status === status)
  }), [events, query, globalQuery, severity, status, focusEventId])
  const updateStatus = async (event, next) => {
    const updated = await onStatusChange?.(event, next)
    if (updated) setSelected(prev => prev?.id === event.id ? { ...prev, status: next } : prev)
    return updated
  }
  const selectedIsBruteForce = /brute[ _-]?force/i.test(selected?.type || '')
  const hasMitreMapping = Boolean(selected?.mitreTechniqueId || selected?.raw?.mitre_technique_id || selectedIsBruteForce)
  const mitreId = selected?.mitreTechniqueId || selected?.raw?.mitre_technique_id || 'T1110'
  const mitreName = selected?.mitreTechniqueName || selected?.raw?.mitre_technique_name || 'Brute Force'
  const mitreTactic = selected?.mitreTactic || selected?.raw?.mitre_tactic || 'Credential Access'
  const exportCsv = () => {
    const rows = [['ID','Time (UTC)','Source','Type','Severity','Status','Message'], ...filtered.map(e => [e.id,timestampIso(e.time),e.source,e.type,e.severity,e.status,e.message])]
    const csv = rows.map(r => r.map(v => `"${String(v ?? '').replaceAll('"','""')}"`).join(',')).join('\n')
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' })); a.download = 'siem-alerts.csv'; a.click(); URL.revokeObjectURL(a.href)
  }
  return <div className="page-stack">
    <div className="page-heading"><div><div className="eyebrow">INVESTIGATION / ALERT MANAGEMENT</div><h1>Alert queue</h1><p>Review alerts generated and stored by the SIEM service.</p></div><button className="primary-button" onClick={exportCsv} disabled={!filtered.length}><Download size={15}/> Export results</button></div>
    <div className="mini-stats"><div><span>Total shown</span><strong>{filtered.length}</strong></div><div><span>Critical</span><strong className="text-red">{filtered.filter(e => e.severity === 'Critical').length}</strong></div><div><span>Open</span><strong>{filtered.filter(e => e.status === 'Open').length}</strong></div><div><span>Investigating</span><strong>{filtered.filter(e => e.status === 'Investigating').length}</strong></div></div>
    <section className="panel table-panel">
      <div className="table-toolbar"><label className="table-search"><Search size={16}/><input placeholder="Search alerts..." value={query} onChange={e => setQuery(e.target.value)} /></label><div className="filter-group"><SlidersHorizontal size={15}/><select className="select-control" value={severity} onChange={e => setSeverity(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Unknown</option></select><select className="select-control" value={status} onChange={e => setStatus(e.target.value)}><option>All</option><option>Open</option><option>Investigating</option><option>Confirmed threat</option><option>False positive</option><option>Resolved</option></select></div></div>
      <div className="table-wrap"><table><thead><tr><th>Event ID</th><th>Event / source</th><th>Severity</th><th>Status</th><th>Timestamp</th><th>Action</th></tr></thead><tbody>
        {filtered.map(e => <tr key={e.id} data-alert-event-id={e.id}><td><span className="event-id">{e.id}</span></td><td><div className="event-name">{e.type}</div><div className="event-source">{e.source}</div></td><td><span className={severityClass(e.severity)}>{e.severity}</span></td><td><select className={`status-select ${e.status.toLowerCase().replaceAll(' ', '-')}`} value={e.status} onChange={ev => updateStatus(e, ev.target.value)} disabled={e.status === 'Resolved'}><option>Open</option><option>Investigating</option><option>Confirmed threat</option><option>False positive</option><option>Resolved</option></select></td><td className="timestamp-cell">{e.time ? formatTimestamp(e.time) : 'Not provided in log'}</td><td><button type="button" className="row-action" onClick={() => setSelected(e)} title="Open alert actions" aria-label={`Open actions for ${e.id}`}><Eye size={16}/><span>Actions</span></button></td></tr>)}
        {!filtered.length && <tr><td colSpan="6"><div className="empty-state"><Search size={24}/><strong>No matching events</strong><span>Try changing the search term or filters.</span></div></td></tr>}
      </tbody></table></div>
      <div className="table-footer"><span>Showing {filtered.length} of {events.length} loaded alerts</span><span><CheckCheck size={14}/> Status changes are stored by the SIEM API</span></div>
    </section>
    {selected && <Modal className="alert-details-modal" title={`Event details · ${selected.id}`} onClose={() => setSelected(null)}>
      <div className="detail-grid"><div><span>Severity</span><strong><span className={severityClass(selected.severity)}>{selected.severity}</span></strong></div><div><span>Status</span><strong>{selected.status}</strong></div><div><span>Source</span><strong>{selected.source}</strong></div><div><span>Timestamp</span><strong>{selected.time ? formatTimestamp(selected.time) : 'Not provided in log'}</strong></div></div>
      {hasMitreMapping
        ? <div className="detail-mitre"><span className="detail-mitre-label">MITRE ATT&CK</span><div className="detail-mitre-box"><div className="detail-mitre-mapping"><strong>{mitreId} · {mitreName}</strong><small>{mitreTactic}</small></div><div className="detail-message"><strong>{selected.type}</strong><p>{selected.message}</p></div></div></div>
        : <div className="detail-message"><strong>{selected.type}</strong><p>{selected.message}</p></div>}
      <button className="primary-button" type="button" onClick={() => onOpenInvestigation?.(selected)}>Open investigation <ArrowUpRight size={15}/></button>
    </Modal>}
  </div>
}
