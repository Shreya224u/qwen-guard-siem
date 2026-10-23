export function normalizeAlert(alert) {
  const states = { NEW: 'Open', UNDER_INVESTIGATION: 'Investigating', CONFIRMED_THREAT: 'Confirmed threat', FALSE_POSITIVE: 'False positive', RESOLVED: 'Resolved' }
  return {
    id: alert.event_id || `EVT-${alert.log_id || alert.id}`,
    apiId: alert.id,
    recordType: 'alert',
    time: alert.has_event_timestamp ? alert.event_timestamp : null,
    source: alert.event_source && !['network', 'windows', 'unknown'].includes(String(alert.event_source).toLowerCase())
      ? alert.event_source
      : alert.ip_address && alert.ip_address !== '0.0.0.0' ? alert.ip_address : alert.event_source || 'Unknown source',
    type: alert.alert_type || alert.event_type || alert.rule_name,
    severity: normalizeSeverity(alert.severity),
    status: states[alert.status] || alert.status,
    mitreTechniqueId: alert.mitre_technique_id || '',
    mitreTechniqueName: alert.mitre_technique_name || '',
    mitreTactic: alert.mitre_tactic || '',
    message: alert.description || alert.rule_name || '',
    raw: alert,
  }
}

export function normalizeLog(log) {
  return {
    id: `LOG-${log.id}`,
    apiId: log.id,
    recordType: 'log',
    time: log.timestamp,
    source: log.ip_address || log.source || log.device || 'Unknown source',
    type: log.event_type || log.platform || 'Log event',
    severity: normalizeSeverity(log.severity),
    status: 'Recorded',
    message: log.raw_log || `${log.event_type || 'Log event'} · ${log.username || log.source || ''}`,
    raw: log,
  }
}

export function normalizeSeverity(value) {
  const severity = String(value || '').toLowerCase()
  if (severity.includes('critical') || severity.includes('severe')) return 'Critical'
  if (severity.includes('high')) return 'High'
  if (severity.includes('medium') || severity.includes('moderate')) return 'Medium'
  if (severity.includes('low') || severity.includes('info')) return 'Low'
  return 'Unknown'
}

export const statusToApi = status => ({
  Open: 'NEW',
  Investigating: 'UNDER_INVESTIGATION',
  'Confirmed threat': 'CONFIRMED_THREAT',
  'False positive': 'FALSE_POSITIVE',
  Resolved: 'RESOLVED',
})[status] || status
