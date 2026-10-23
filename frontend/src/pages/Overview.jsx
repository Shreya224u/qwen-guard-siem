import { useMemo } from 'react'
import { Activity, ShieldAlert, ShieldCheck, Database, RefreshCw, Download, Info } from 'lucide-react'
import { EventsLineChart, SeverityDonut, AttackBarChart } from '../components/Charts'
import { formatTimestamp } from '../utils/dateTime'

function Kpi({ icon: Icon, label, value, color, sub }) {
  return <article className="kpi-card"><div className="kpi-top"><span>{label}</span><span className={`kpi-icon ${color}`}><Icon size={17}/></span></div><div className="kpi-value">{value}</div><div className="kpi-bottom">{sub}</div></article>
}

export default function Overview({ events, timeline, activityUnavailable, severity, attacks, onRefresh, onExport, eventsCount, alertsCount, openAlerts, range, onRangeChange }) {
  const critical = events.filter(e => e.recordType === 'alert' && e.severity === 'Critical').length
  const sources = new Set(events.filter(e => e.recordType === 'log').map(e => e.raw?.source || e.raw?.platform).filter(Boolean)).size
  const chartData = useMemo(() => timeline, [timeline])
  const hasActivityData = chartData.some(bucket => bucket.events || bucket.threats)
  const rangeLabel = { '24h': 'last 24 hours', '7d': 'last 7 days', '30d': 'last 30 days', all: 'all available data' }[range] || 'selected range'
  const intervalLabel = { '24h': '3-hour', '7d': 'daily', '30d': 'daily', all: 'daily' }[range] || 'time'
  return <div className="page-stack">
    <div className="page-heading"><div><div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div><h1>Security overview</h1><p>Review records and alerts stored by your SIEM service.</p></div><div className="heading-actions"><button className="secondary-button" onClick={onRefresh}><RefreshCw size={15}/> Refresh</button><button className="primary-button" onClick={onExport} disabled={!events.length}><Download size={15}/> Export CSV</button></div></div>
    <div className="info-banner"><Info size={15}/> Counts and charts are based on records returned by the connected SIEM API.</div>
    <div className="kpi-grid"><Kpi icon={Activity} label="Logs stored" value={eventsCount.toLocaleString()} color="blue" sub="records in SIEM database"/><Kpi icon={ShieldAlert} label="Alerts" value={alertsCount.toLocaleString()} color="orange" sub={`${openAlerts.toLocaleString()} unresolved`}/><Kpi icon={ShieldCheck} label="Critical alerts" value={critical.toLocaleString()} color="red" sub="in the current result set"/><Kpi icon={Database} label="Log sources" value={sources.toLocaleString()} color="green" sub="sources in loaded logs"/></div>
    <div className="chart-grid"><section className="panel chart-panel chart-wide"><div className="panel-header"><div><h3>Event activity</h3><p>Solid lines use source event time; dashed lines show records with missing source timestamps by ingestion time.</p></div><select className="select-control" value={range} onChange={e => onRangeChange(e.target.value)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="all">All available data</option></select></div>{activityUnavailable ? <div className="chart-empty">Activity data could not be loaded from the SIEM API.</div> : hasActivityData ? <EventsLineChart data={chartData}/> : <div className="chart-empty"><span>No records were found in {rangeLabel}.</span>{range !== 'all' && <button className="secondary-button" type="button" onClick={() => onRangeChange('all')}>View all available data</button>}</div>}<div className="chart-legend"><span><i className="legend-dot blue"/> Logs · event time</span><span><i className="legend-dot red"/> Alerts · event time</span><span style={{ color: '#ffc857' }}>- - Logs · ingestion time</span><span style={{ color: '#bc8cff' }}>- - Alerts · ingestion time</span></div></section>
      <section className="panel chart-panel"><div className="panel-header"><div><h3>Severity distribution</h3><p>Hover a segment for meaning and detected values</p></div></div><SeverityDonut data={severity}/></section></div>
    <div className="lower-grid"><section className="panel chart-panel"><div className="panel-header"><div><h3>Alert categories</h3><p>Most frequent categories in loaded alerts</p></div></div><AttackBarChart data={attacks}/></section>
      <section className="panel chart-panel"><div className="panel-header"><div><h3>Latest records</h3><p>Most recent results from the SIEM API</p></div></div>{events.slice(0, 5).map(event => <div className="model-row" key={`${event.recordType}-${event.id}`}><span className={`severity-dot ${event.severity.toLowerCase()}`}/><div className="model-info"><strong>{event.type}</strong><small>{event.source} · {event.time ? formatTimestamp(event.time) : 'Timestamp not present in source'}</small><span className="model-state">{event.recordType === 'alert' ? event.status : 'Log record'}</span></div></div>)}{!events.length && <div className="empty-state"><Activity size={22}/><strong>No records returned</strong><span>Upload logs to begin processing.</span></div>}</section></div>
  </div>
}
