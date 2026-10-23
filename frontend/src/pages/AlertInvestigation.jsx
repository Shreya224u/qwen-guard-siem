import { useEffect, useMemo, useState } from 'react'
import { ArrowLeft, CheckCircle2, Clock3, Crosshair, Globe2, LoaderCircle, ShieldAlert, TerminalSquare } from 'lucide-react'
import { logsApi } from '../api'
import { formatTimestamp } from '../utils/dateTime'

const show = value => value === undefined || value === null || value === '' ? 'Not available' : String(value)
const sourceIdFrom = raw => {
  const candidates = [raw?.source_id, raw?.source_ip, raw?.src_ip, raw?.ip_address]
  return candidates.find(value => {
    const normalized = String(value || '').trim()
    return normalized && normalized !== '0.0.0.0'
  }) || null
}
const destinationFrom = raw => {
  const log = String(raw?.raw_log || '')
  const match = log.match(/(?:destination(?:_ip|_id)?|dst(?:_ip)?|remote_addr|target_ip)[=: ]+([\w.:/-]+)/i)
  return raw?.destination_id || raw?.destination_ip || raw?.dst_ip || match?.[1] || null
}
const diagnosis = alert => {
  const category = `${alert.type || ''} ${alert.message || ''} ${alert.raw?.rule_name || ''}`.toLowerCase()
  if (/brute|failed login|authentication/.test(category)) return {
    issue: 'This alert indicates repeated or unusual authentication activity. It may be an attempt to guess credentials, but the event log alone does not confirm whether an account was accessed.',
    steps: ['Check the source address and the affected account against nearby authentication events.', 'Confirm whether any login succeeded after the failures.', 'If activity is unauthorized, block or limit the source and reset affected credentials; enable multi-factor authentication where available.'],
  }
  if (/port scan|scan|reconnaissance/.test(category)) return {
    issue: 'This alert indicates probing or scanning behavior against a host or service. The available event identifies the signal, but further logs are needed to confirm whether a service was reached or exploited.',
    steps: ['Review the destination host and ports contacted, then check firewall and service logs for successful connections.', 'If the source is not authorized, block or rate-limit it at the network boundary.', 'Confirm exposed services are expected and patched, then monitor for follow-up activity.'],
  }
  if (/malware|ransom|virus/.test(category)) return {
    issue: 'This alert indicates activity classified as potentially malicious software. Treat the affected host as at risk until endpoint evidence confirms what executed and whether it spread.',
    steps: ['Isolate the affected host if active malicious behavior is confirmed.', 'Review endpoint detection results, process activity, and related events to identify persistence or spread.', 'Remove the malicious artifact, restore from a trusted source if needed, and verify the host before reconnecting it.'],
  }
  if (/spam|phish|email/.test(category)) return {
    issue: 'This alert indicates a potentially unwanted or phishing message. The event by itself does not prove that a recipient opened a link or submitted credentials.',
    steps: ['Review the sender, URLs, attachments, and recipient activity.', 'Quarantine the message and search for copies sent to other users.', 'If anyone interacted with it, reset affected credentials and review sign-in activity.'],
  }
  return {
    issue: `The SIEM raised this ${show(alert.type).toLowerCase()} alert based on the event details below. The alert describes a potential security issue; the supplied event data should be reviewed before treating the activity as confirmed malicious.`,
    steps: ['Validate the source and destination against expected activity for this system.', 'Review related events around the detection time to confirm impact and identify affected accounts or services.', 'Apply the appropriate containment or remediation for the confirmed cause, then verify no related activity remains.'],
  }
}

export default function AlertInvestigation({ alert, onBack, onResolve }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [relatedLog, setRelatedLog] = useState(null)
  const raw = { ...(alert.raw || {}), ...(relatedLog || {}) }
  useEffect(() => {
    if (raw.raw_log || !raw.log_id) return undefined
    let active = true
    logsApi.list({ limit: 500 }).then(result => {
      const log = result.logs?.find(item => Number(item.id) === Number(raw.log_id))
      if (active && log) setRelatedLog(log)
    }).catch(() => {})
    return () => { active = false }
  }, [raw.log_id, raw.raw_log])
  const guide = useMemo(() => diagnosis(alert), [alert])
  const isResolved = alert.status === 'Resolved'
  const resolve = async () => {
    setBusy(true); setError('')
    try { const ok = await onResolve(alert); if (!ok) setError('The alert could not be resolved. Check the server connection and try again.') }
    catch { setError('The alert could not be resolved. Check the server connection and try again.') }
    finally { setBusy(false) }
  }
  return <div className="page-stack investigation-page">
    <div className="page-heading"><div><div className="eyebrow">ALERT QUEUE / INVESTIGATION</div><h1>Alert investigation</h1><p>Review the evidence, understand the signal, and record the alert outcome.</p></div><button type="button" className="secondary-button" onClick={onBack}><ArrowLeft size={15}/> Back to alert queue</button></div>
    <section className="investigation-hero panel"><div className="investigation-hero-icon"><ShieldAlert size={21}/></div><div className="investigation-hero-copy"><span>{show(alert.id)} <i>·</i> {show(alert.type)}</span><h2>{show(alert.message || raw.description || raw.rule_name)}</h2><p>Detected {alert.time ? formatTimestamp(alert.time) : 'time not provided'} <i>·</i> {show(alert.source)}</p></div><span className={`severity-badge ${String(alert.severity).toLowerCase()}`}>{alert.severity}</span></section>
    <div className="investigation-facts">
      <div className="investigation-fact panel"><span><Globe2 size={14}/> Source ID</span><strong>{show(sourceIdFrom(raw))}</strong></div>
      <div className="investigation-fact panel"><span><Crosshair size={14}/> Destination ID</span><strong>{show(destinationFrom(raw))}</strong></div>
      <div className="investigation-fact panel"><span><Clock3 size={14}/> Resolution time</span><strong>{raw.resolved_at ? formatTimestamp(raw.resolved_at) : isResolved ? 'Recorded; refresh to load timestamp' : 'Not resolved'}</strong></div>
      <div className="investigation-fact panel"><span><TerminalSquare size={14}/> MITRE ATT&amp;CK</span><strong>{raw.mitre_technique_id ? `${raw.mitre_technique_id} · ${raw.mitre_technique_name || 'Technique'}` : 'No technique mapped'}</strong><small>{raw.mitre_tactic || ''}</small></div>
    </div>
    <div className="investigation-columns">
      <section className="panel investigation-content"><div className="panel-header"><div><h3>What happened</h3><p>Plain-language assessment in English</p></div></div><p>{raw.investigation_reason || guide.issue}</p><div className="investigation-evidence"><strong>Event evidence</strong><pre>{show(raw.raw_log || alert.message)}</pre></div></section>
      <section className="panel investigation-content"><div className="panel-header"><div><h3>Recommended resolution</h3><p>Validate these steps against your environment</p></div></div><ol className="resolution-steps">{(raw.recommended_action ? [raw.recommended_action, ...guide.steps.slice(1)] : guide.steps).map((step, index) => <li key={index}><span>{index + 1}</span><p>{step}</p></li>)}</ol></section>
    </div>
    <section className="panel resolution-panel"><div className="resolution-panel-copy"><span className="eyebrow">RESPONSE</span><h3>{isResolved ? 'Alert resolved' : 'Resolve this alert'}</h3><p>{isResolved ? `This alert is marked resolved${raw.resolved_at ? ` at ${formatTimestamp(raw.resolved_at)}` : ''}.` : 'After validating and applying the appropriate remediation, mark this alert as resolved. The SIEM records the status and resolution time.'}</p>{error && <small className="resolution-error">{error}</small>}</div><button type="button" className="primary-button" onClick={resolve} disabled={busy || isResolved}>{busy ? <LoaderCircle className="investigation-spinner" size={15}/> : <CheckCircle2 size={15}/>} {busy ? 'Saving…' : isResolved ? 'Resolved' : 'Mark as resolved'}</button></section>
  </div>
}
