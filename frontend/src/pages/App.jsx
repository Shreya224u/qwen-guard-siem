import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import Sidebar from '../components/Sidebar'
import Topbar from '../components/Topbar'
import ChatAssistant from '../components/ChatAssistant'
import PopupMessage from '../components/PopupMessage'
import Login from './Login'
const Overview = lazy(() => import('./Overview'))
const Alerts = lazy(() => import('./Alerts'))
const AlertInvestigation = lazy(() => import('./AlertInvestigation'))
const SpamWatch = lazy(() => import('./SpamWatch'))
const Ingestion = lazy(() => import('./Ingestion'))
const Mitre = lazy(() => import('./Mitre'))
const AccountCenter = lazy(() => import('./AccountCenter'))
const Settings = lazy(() => import('./Settings'))
const Feedback = lazy(() => import('./Feedback'))
const Admin = lazy(() => import('./Admin'))
import CyberParticleBackground from '../components/CyberParticleBackground'
import { alertsApi, authApi, logsApi, normalizeAlert, normalizeLog, statusToApi } from '../api'
import { useAppState } from '../state/AppStateContext'
import { formatTimestamp, parseTimestamp, timestampValue } from '../utils/dateTime'

const titles = { overview: 'Overview', alerts: 'Alert Queue', investigation: 'Alert Investigation', spam: 'Spam Watch', ingestion: 'Log Ingestion', mitre: 'Attack Framework', account: 'Account Center', settings: 'Settings', feedback: 'Feedback', admin: 'Admin' }
const pageOrder = ['overview', 'ingestion', 'alerts', 'investigation', 'spam', 'mitre', 'account', 'settings', 'feedback', 'admin']
const colors = { Critical: '#ff5576', High: '#ff9f43', Medium: '#f6cf58', Low: '#31d6a0', Unknown: '#8290a8' }
const isSpamAlert = alert => /spam|phish|mail/i.test(`${alert.type || ''} ${alert.message || ''}`)
const isSessionExpiryMessage = value => /your sign-in session expired|sign-in session expired/i.test(String(value || ''))
const isAuthenticationFailure = value => /\b401\b|unauthorized|not authenticated/i.test(String(value || ''))
const friendlyError = value => {
  const message = String(value || '').trim()
  if (/failed to fetch|networkerror|fetch failed|connection refused|econnrefused/i.test(message)) return 'Cannot connect to the server. Start the backend and try again.'
  if (/\b(500|internal server error)\b/i.test(message)) return 'The server ran into a problem. Please try again shortly.'
  if (/\b(502|503|504)\b|service unavailable|bad gateway/i.test(message)) return 'The server is currently unavailable. Check the backend and try again.'
  if (isAuthenticationFailure(message)) return ''
  if (/\b403\b|forbidden/i.test(message)) return 'Your account does not have permission to do this.'
  if (/\b404\b|not found/i.test(message)) return 'The requested item was not found. Refresh the page and try again.'
  const clean = message.replace(/^request failed\s*\(?\s*\d+\s*\)?\s*:?[\s-]*/i, '').replace(/[_\s]+/g, ' ').replace(/\s+/g, ' ').trim()
  return clean ? clean.charAt(0).toUpperCase() + clean.slice(1) : 'Something went wrong. Please try again shortly.'
}
const makeAlertNotification = alert => {
  const type = String(alert.type || 'Security event')
  const detail = friendlyError(alert.message || type)
  if (isSessionExpiryMessage(alert.message) || isAuthenticationFailure(alert.message)) return null
  const category = /spam|phish|mail/i.test(`${type} ${alert.message || ''}`) ? 'SPAM ALERT'
    : /malware|ransom|virus/i.test(`${type} ${alert.message || ''}`) ? 'MALWARE ALERT'
      : /login|auth|credential|brute/i.test(`${type} ${alert.message || ''}`) ? 'AUTH ALERT' : 'SECURITY ALERT'
  return {
    id: `alert-${alert.id}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    kind: 'security-alert',
    eventId: alert.id,
    severity: String(alert.severity || 'Unknown').toLowerCase(),
    label: category === 'SPAM ALERT' ? 'SPAM' : 'ERROR',
    detail: category === 'SPAM ALERT' ? '' : detail,
  }
}
const makeSpamNotification = alerts => ({
  id: `spam-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
  severity: String(alerts[alerts.length - 1]?.severity || 'High').toLowerCase(),
  label: 'SPAM',
  count: alerts.length,
  detail: alerts[alerts.length - 1]?.message || 'Potential spam or phishing activity was detected. Review the findings in Spam Watch.',
})

export default function App() {
  const { theme, setTheme, token, user, userRole, setUserRole, signIn, signOut } = useAppState()
  const [page, setPage] = useState('overview')
  const [investigationAlert, setInvestigationAlert] = useState(null)
  const [accountNotice, setAccountNotice] = useState('')
  const [loginNotice, setLoginNotice] = useState('')
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [logsTotal, setLogsTotal] = useState(0)
  const [alertsTotal, setAlertsTotal] = useState(0)
  const [activityRange, setActivityRange] = useState('all')
  const [activityTimeline, setActivityTimeline] = useState([])
  const [activityUnavailable, setActivityUnavailable] = useState(false)
  const [query, setQuery] = useState('')
  const [collapsed, setCollapsed] = useState(false)
  const [notifications, setNotifications] = useState([])
  const [focusAlertId, setFocusAlertId] = useState('')
  const [welcomeUser, setWelcomeUser] = useState('')
  const [loading, setLoading] = useState(false)
  const [apiConnected, setApiConnected] = useState(false)
  const [activeFilename, setActiveFilename] = useState(() => sessionStorage.getItem('siem-active-alert-file') || '')
  const mainContentRef = useRef(null)
  const pendingScrollDirection = useRef(0)
  const pageTurnLock = useRef(false)
  const wheelGestureTimer = useRef(null)
  const seenAlertIds = useRef(null)
  const uploadedThisSession = useRef(Boolean(activeFilename))
  const activeAlertFilename = useRef(activeFilename)
  const lastNotifiedError = useRef('')

  useEffect(() => {
    if (!token) { setUserRole(''); return undefined }
    let active = true
    authApi.me(token).then(profile => {
      if (active) setUserRole(String(profile.role || '').toLowerCase())
    }).catch(error => {
      if (!active) return
      setUserRole('')
      if (isAuthenticationFailure(error.message)) {
        logout('Your sign-in session could not be validated. Please sign in again.')
      }
    })
    return () => { active = false }
  }, [token])
  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1))
    const linkedProvider = params.get('oauth_link')
    const linkError = params.get('oauth_link_error')
    if (!linkedProvider && !linkError) return
    setPage('account')
    setAccountNotice(linkedProvider
      ? `${linkedProvider === 'github' ? 'GitHub' : 'Google'} account connected successfully.`
      : linkError === 'already_linked'
        ? 'That social account is already linked to another SIEM AI account.'
        : 'Could not connect the social account. Please try again.')
    window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`)
  }, [])
  useEffect(() => {
    const focusGlobalSearch = event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        document.getElementById('global-event-search')?.focus()
      }
    }
    window.addEventListener('keydown', focusGlobalSearch)
    return () => window.removeEventListener('keydown', focusGlobalSearch)
  }, [])
  useEffect(() => {
    const direction = pendingScrollDirection.current
    if (!direction) return
    const frame = window.requestAnimationFrame(() => {
      const content = mainContentRef.current
      if (!content) return
      const target = direction > 0 ? 0 : content.scrollHeight
      content.style.scrollBehavior = 'auto'
      content.scrollTo(0, target)
      window.requestAnimationFrame(() => {
        content.style.scrollBehavior = ''
        pendingScrollDirection.current = 0
      })
    })
    return () => window.cancelAnimationFrame(frame)
  }, [page])
  useEffect(() => () => window.clearTimeout(wheelGestureTimer.current), [])
  useEffect(() => { document.documentElement.classList.toggle('compact-mode', localStorage.getItem('siem-compact') === 'true') }, [])
  const logout = (message = '') => { setLoginNotice(typeof message === 'string' ? message : ''); signOut(); setEvents([]); setAlerts([]); setNotifications([]); setLogsTotal(0); setAlertsTotal(0); seenAlertIds.current = null; uploadedThisSession.current = false; activeAlertFilename.current = ''; setActiveFilename(''); sessionStorage.removeItem('siem-active-alert-file'); lastNotifiedError.current = ''; setPage('overview') }
  const login = result => { setLoginNotice(''); seenAlertIds.current = null; uploadedThisSession.current = false; activeAlertFilename.current = ''; setActiveFilename(''); sessionStorage.removeItem('siem-active-alert-file'); signIn(result); setWelcomeUser(result.username) }
  const refreshLogin = result => signIn(result)

  const refresh = useCallback(async () => {
    if (!token) return
    setLoading(true)
    try {
      // Keep historical alerts hidden until this signed-in session uploads a
      // file. Uploading is the only operation that runs alert generation.
      const shouldLoadAlerts = uploadedThisSession.current && activeAlertFilename.current
      const [logResult, alertResult] = await Promise.all([
        logsApi.list({ limit: 100, token }),
        shouldLoadAlerts
          ? alertsApi.list({ limit: 500, sourceFile: activeAlertFilename.current, token })
          : Promise.resolve({ alerts: [], total: 0 }),
      ])
      const nextAlerts = (alertResult.alerts || []).map(normalizeAlert)
      const nextLogs = (logResult.logs || []).map(normalizeLog)
      lastNotifiedError.current = ''
      const nextIds = new Set(nextAlerts.map(alert => String(alert.id)))
      if (seenAlertIds.current === null) seenAlertIds.current = nextIds
      else {
        const freshAlerts = nextAlerts.filter(alert => !seenAlertIds.current.has(String(alert.id)))
        seenAlertIds.current = new Set([...seenAlertIds.current, ...nextIds])
        if (freshAlerts.length) {
          const spamAlerts = freshAlerts.filter(isSpamAlert)
      const otherAlerts = freshAlerts.filter(alert => !isSpamAlert(alert) && !isSessionExpiryMessage(alert.message) && !isAuthenticationFailure(alert.message))
          setNotifications(current => {
            const pendingSpam = current.find(notification => notification.label === 'SPAM')
            const spamNotification = spamAlerts.length
              ? { ...makeSpamNotification(spamAlerts), count: spamAlerts.length + (pendingSpam?.count || 0) }
              : pendingSpam
            return [
              ...(spamNotification ? [spamNotification] : []),
              ...(otherAlerts.length ? [makeAlertNotification(otherAlerts[otherAlerts.length - 1])] : []),
            ]
          })
        }
      }
      setAlerts(nextAlerts); setLogsTotal(logResult.total || 0); setAlertsTotal(alertResult.total || 0); setApiConnected(true)
      const loadedEvents = [...nextAlerts, ...nextLogs].sort((a, b) => timestampValue(b.time) - timestampValue(a.time))
      setEvents(loadedEvents)
      try {
        const activityResult = await logsApi.activity(activityRange, shouldLoadAlerts ? activeAlertFilename.current : '', token)
        setActivityUnavailable(false)
        setActivityTimeline((activityResult.buckets || []).map(bucket => ({
          ...bucket,
          time: formatTimestamp(bucket.timestamp, activityRange === 'all'
            ? { month: 'short', day: 'numeric' }
            : activityRange === '7d' || activityRange === '30d'
            ? { year: undefined, month: 'short', day: 'numeric', hour: undefined, minute: undefined }
            : { year: undefined, month: undefined, day: undefined, hour: '2-digit', minute: '2-digit' }),
        })))
      } catch {
        // Do not infer event time from the latest-record list; its timestamp
        // may be an ingestion-time fallback rather than the source event time.
        setActivityUnavailable(true)
        setActivityTimeline([])
      }
    } catch (error) {
      setActivityUnavailable(true)
      setActivityTimeline([])
      const message = error.message || 'Unable to load records from the SIEM API.'
      if (isAuthenticationFailure(message)) {
        setApiConnected(false)
        logout('Your sign-in session could not be validated. Please sign in again.')
        return
      }
      if (message !== lastNotifiedError.current) {
        lastNotifiedError.current = message
        setNotifications([{ id: `error-${Date.now()}`, kind: 'system-error', severity: 'error', label: 'ERROR', detail: friendlyError(message) }])
      }
      setApiConnected(false)
    } finally { setLoading(false) }
  }, [token, activityRange])

  const onLogsImported = useCallback(result => {
    uploadedThisSession.current = true
    activeAlertFilename.current = result?.filename || ''
    setActiveFilename(activeAlertFilename.current)
    sessionStorage.setItem('siem-active-alert-file', activeAlertFilename.current)
    return refresh()
  }, [refresh])
  const onUploadDeleted = useCallback(filename => {
    if (activeAlertFilename.current === filename) {
      activeAlertFilename.current = ''
      setActiveFilename('')
      sessionStorage.removeItem('siem-active-alert-file')
    }
    return refresh()
  }, [refresh])
  const onSelectAlertFile = useCallback(filename => {
    uploadedThisSession.current = Boolean(filename)
    activeAlertFilename.current = filename || ''
    setActiveFilename(activeAlertFilename.current)
    if (activeAlertFilename.current) sessionStorage.setItem('siem-active-alert-file', activeAlertFilename.current)
    else sessionStorage.removeItem('siem-active-alert-file')
    return refresh()
  }, [refresh])

  useEffect(() => { if (token) refresh() }, [token, refresh])
  useEffect(() => {
    if (!token || !apiConnected) return undefined
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') refresh()
    }, 30000)
    return () => window.clearInterval(timer)
  }, [token, apiConnected, refresh])
  const normalizedQuery = query.trim().toLowerCase()
  const matchesQuery = event => `${event.id} ${event.type} ${event.source} ${event.message} ${event.time} ${event.severity} ${event.status}`.toLowerCase().includes(normalizedQuery)
  const filteredEvents = useMemo(() => normalizedQuery ? events.filter(matchesQuery) : events, [events, normalizedQuery])
  const filteredAlerts = useMemo(() => normalizedQuery ? alerts.filter(matchesQuery) : alerts, [alerts, normalizedQuery])
  const timeline = activityTimeline
  const severity = useMemo(() => {
    const counts = Object.keys(colors).map(name => ({ name, count: filteredEvents.filter(e => e.severity === name).length, color: colors[name] }))
    const total = counts.reduce((sum, item) => sum + item.count, 0)
    return counts.map(({ count, ...item }) => ({ ...item, count, value: total ? Math.round(count / total * 100) : 0 }))
  }, [filteredEvents])
  const attacks = useMemo(() => {
    const names = [...new Set(filteredAlerts.map(e => e.type))]
    return names.slice(0, 5).map(name => ({ name: name.length > 16 ? `${name.slice(0, 14)}…` : name, count: filteredAlerts.filter(e => e.type === name).length }))
  }, [filteredAlerts])
  const openAlerts = filteredAlerts.filter(event => !['Resolved', 'False positive'].includes(event.status)).length
  const unresolvedAlertCount = alerts.filter(event => !['Resolved', 'False positive'].includes(event.status)).length
  const exportCsv = () => {
    const rows = [['ID', 'Time (UTC)', 'Source', 'Type', 'Severity', 'Status', 'Message'], ...filteredEvents.map(e => [e.id, e.time ? parseTimestamp(e.time)?.toISOString() || '' : '', e.source, e.type, e.severity, e.status, e.message])]
    const csv = rows.map(row => row.map(value => `"${String(value ?? '').replaceAll('"', '""')}"`).join(',')).join('\n')
    const link = document.createElement('a'); link.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' })); link.download = 'siem-events.csv'; link.click(); URL.revokeObjectURL(link.href)
  }
  const changeAlertStatus = async (event, status) => {
    try { await alertsApi.setStatus(event.apiId, statusToApi(status)); await refresh(); return true }
    catch (error) {
      const detail = error.message || 'Could not update alert status.'
      if (isAuthenticationFailure(detail)) { logout(); return false }
      setNotifications([{ id: `error-${Date.now()}`, kind: 'system-error', severity: 'error', label: 'ERROR', detail: friendlyError(detail) }])
      return false
    }
  }
  const dismissNotification = id => setNotifications(current => current.filter(notification => notification.id !== id))
  const openSpamWatch = id => { setPage('spam'); dismissNotification(id) }
  const openAlert = (eventId, notificationId) => {
    setFocusAlertId(eventId)
    setPage('alerts')
    dismissNotification(notificationId)
  }
  const handleWorkspaceWheel = event => {
    if (!event.target.closest('.sidebar nav')) return
    if (pageTurnLock.current) {
      event.preventDefault()
      window.clearTimeout(wheelGestureTimer.current)
      wheelGestureTimer.current = window.setTimeout(() => { pageTurnLock.current = false }, 250)
      return
    }
    const direction = event.deltaY > 0 ? 1 : event.deltaY < 0 ? -1 : 0
    if (!direction) return
    const index = pageOrder.indexOf(page)
    const nextPage = pageOrder[index + direction]
    if (!nextPage) return
    event.preventDefault()
    pageTurnLock.current = true
    window.clearTimeout(wheelGestureTimer.current)
    wheelGestureTimer.current = window.setTimeout(() => { pageTurnLock.current = false }, 250)
    pendingScrollDirection.current = direction
    setPage(nextPage)
  }
  if (!token || !user) return <Login onLogin={login} theme={theme} setTheme={setTheme} initialNotice={loginNotice} clearInitialNotice={setLoginNotice}/>
  const currentNotification = welcomeUser ? null : notifications[0]

  return <div className="app-shell" onWheel={handleWorkspaceWheel}>
    {welcomeUser && <PopupMessage key={`welcome-${welcomeUser}`} variant="welcome" title={`Welcome back, ${welcomeUser}`} message="Your security operations workspace is ready. Tap Enter workspace to continue." actionLabel="Enter workspace" onAction={() => setWelcomeUser('')} onClose={() => setWelcomeUser('')}/>}
    <CyberParticleBackground/>
    <Sidebar page={page === 'investigation' ? 'alerts' : page} setPage={nextPage => { if (nextPage !== 'admin' || userRole === 'admin') setPage(nextPage) }} collapsed={collapsed} setCollapsed={setCollapsed} alertCount={unresolvedAlertCount} isAdmin={userRole === 'admin'}/>
    <div className="main-shell">
      <Topbar theme={theme} setTheme={setTheme} query={query} setQuery={setQuery} onLogout={logout} onToggleSidebar={() => setCollapsed(v => !v)} user={user}/>
      <main className="main-content" ref={mainContentRef}>
        <div className="breadcrumbs"><span>SIEM Workspace</span><ChevronRight size={13}/><strong>{titles[page]}</strong></div>
        {loading && !events.length && <div className="notice info">Loading records from the SIEM API…</div>}
        <div className="workspace-screen" key={page}>
          <Suspense fallback={<div className="notice info">Loading page…</div>}>
          {page === 'overview' && <Overview events={filteredEvents} timeline={timeline} activityUnavailable={activityUnavailable} severity={severity} attacks={attacks} onRefresh={refresh} onExport={exportCsv} eventsCount={normalizedQuery ? filteredEvents.filter(e => e.recordType === 'log').length : logsTotal} alertsCount={normalizedQuery ? filteredAlerts.length : alertsTotal} openAlerts={openAlerts} range={activityRange} onRangeChange={setActivityRange} />}
          {page === 'alerts' && <Alerts events={alerts} onStatusChange={changeAlertStatus} onOpenInvestigation={alert => { setInvestigationAlert(alert); setPage('investigation') }} globalQuery={query} focusEventId={focusAlertId}/>}
          {page === 'investigation' && investigationAlert && <AlertInvestigation alert={investigationAlert} onBack={() => setPage('alerts')} onResolve={async alert => { const updated = await changeAlertStatus(alert, 'Resolved'); if (updated) setInvestigationAlert(current => ({ ...current, status: 'Resolved', raw: { ...current.raw, status: 'RESOLVED', resolved_at: new Date().toISOString() } })); return updated }}/>}
          {page === 'spam' && <SpamWatch events={filteredAlerts} onStatusChange={changeAlertStatus} token={token} activeFilename={activeFilename} onSelectFile={onSelectAlertFile}/>}
          {page === 'ingestion' && <Ingestion onImported={onLogsImported} onDeleted={onUploadDeleted} onAnalyzeUploadedFile={filename => { onSelectAlertFile(filename); setPage('spam') }} token={token}/>}
          {page === 'mitre' && <Mitre token={token}/>}
          {page === 'account' && <AccountCenter token={token} onLogout={logout} onTokenRefresh={refreshLogin} initialNotice={accountNotice} clearInitialNotice={setAccountNotice}/>}
          {page === 'settings' && <Settings theme={theme} setTheme={setTheme} user={user} onLogout={logout}/>}
          {page === 'feedback' && <Feedback token={token} user={user}/>}
          {page === 'admin' && userRole === 'admin' && <Admin token={token}/>}
          </Suspense>
        </div>
        <footer className="app-footer"><span><img className="footer-brand-mark" src="/siem-ai-logo.png" alt=""/> SIEM AI</span><span><i className="pulse-dot" style={{ background: apiConnected ? 'var(--success)' : 'var(--danger)' }}/> {apiConnected ? 'CONNECTED TO SIEM API' : 'SIEM API UNAVAILABLE'}</span></footer>
      </main>
    </div>
    {currentNotification && <PopupMessage
      key={currentNotification.id}
      variant="alert"
      title={currentNotification.label === 'SPAM'
        ? `${currentNotification.count} spam alert${currentNotification.count === 1 ? '' : 's'}`
        : currentNotification.kind === 'security-alert' ? 'Security service alert' : 'Something went wrong'}
      message={currentNotification.detail || (currentNotification.kind === 'security-alert'
        ? 'A security event needs your attention.'
        : 'Sorry, something went wrong. Please try again.')}
      actionLabel={currentNotification.label === 'SPAM' ? 'Open Spam Watch' : currentNotification.kind === 'security-alert' ? 'Review alert' : 'Try again'}
      onAction={() => {
        if (currentNotification.label === 'SPAM') openSpamWatch(currentNotification.id)
        else if (currentNotification.kind === 'security-alert') openAlert(currentNotification.eventId, currentNotification.id)
        else { dismissNotification(currentNotification.id); refresh() }
      }}
      onClose={() => dismissNotification(currentNotification.id)}
    />}
    <ChatAssistant events={events} logsTotal={logsTotal} alertsTotal={alertsTotal} apiConnected={apiConnected} currentPage={page}/>
  </div>
}
