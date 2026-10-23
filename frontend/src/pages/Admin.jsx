import { useCallback, useEffect, useMemo, useState } from 'react'
import { Activity, RefreshCw, Search, ShieldCheck, Users } from 'lucide-react'
import { adminApi } from '../api'
import { formatDate, formatTimestamp } from '../utils/dateTime'

export default function Admin({ token }) {
  const [users, setUsers] = useState([])
  const [activity, setActivity] = useState([])
  const [query, setQuery] = useState('')
  const [section, setSection] = useState('users')
  const [loading, setLoading] = useState(true)
  const [savingUserId, setSavingUserId] = useState(null)
  const [error, setError] = useState('')

  const loadUsers = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const result = await adminApi.users(token)
      setUsers(Array.isArray(result) ? result : result.users || [])
    } catch (requestError) {
      setError(requestError.message || 'Could not load user accounts.')
    } finally {
      setLoading(false)
    }
  }, [token])

  const loadActivity = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const result = await adminApi.activity(100, token)
      setActivity(Array.isArray(result) ? result : [])
    } catch (requestError) {
      setError(requestError.message || 'Could not load account activity.')
    } finally {
      setLoading(false)
    }
  }, [token])

  const loadCurrentSection = section === 'activity' ? loadActivity : loadUsers
  useEffect(() => { loadCurrentSection() }, [loadCurrentSection])

  const updateRole = async account => {
    const role = account.role === 'admin' ? 'analyst' : 'admin'
    setSavingUserId(account.id)
    setError('')
    try {
      const updated = await adminApi.updateRole(account.id, role, token)
      setUsers(current => current.map(user => user.id === updated.id ? updated : user))
    } catch (requestError) {
      setError(requestError.message || 'Could not update this account role.')
    } finally {
      setSavingUserId(null)
    }
  }

  const visibleUsers = useMemo(() => {
    const term = query.trim().toLowerCase()
    if (!term) return users
    return users.filter(user => `${user.username || ''} ${user.email || ''} ${user.phone || ''} ${user.role || ''}`.toLowerCase().includes(term))
  }, [users, query])

  const activityByUser = useMemo(() => {
    const groups = new Map()
    activity.forEach(entry => {
      const username = entry.user || 'Unknown user'
      if (!groups.has(username)) groups.set(username, [])
      groups.get(username).push(entry)
    })
    return Array.from(groups, ([username, actions]) => ({ username, actions }))
  }, [activity])

  return <div className="page-stack admin-page">
    <div className="page-heading">
      <div><span className="eyebrow">ACCOUNT MANAGEMENT</span><h1>Admin</h1><p>Review registered SIEM AI accounts and their access roles.</p></div>
      <button className="secondary-button" type="button" onClick={loadCurrentSection} disabled={loading}><RefreshCw size={14} className={loading ? 'admin-refreshing' : ''}/>Refresh</button>
    </div>
    <div className="admin-summary panel"><span className="admin-summary-icon"><Users size={18}/></span><div><small>Registered accounts</small><strong>{users.length.toLocaleString()}</strong></div><span className="admin-summary-note"><ShieldCheck size={14}/> Admin-only controls</span></div>
    <div className="admin-tabs" role="tablist" aria-label="Admin sections">
      <button type="button" role="tab" aria-selected={section === 'users'} className={section === 'users' ? 'active' : ''} onClick={() => setSection('users')}><Users size={14}/> User access</button>
      <button type="button" role="tab" aria-selected={section === 'activity'} className={section === 'activity' ? 'active' : ''} onClick={() => setSection('activity')}><Activity size={14}/> Activity log</button>
    </div>
    {error && <div className="notice error" role="alert">{error.includes('404') || /not found/i.test(error) ? 'The requested protected admin API is not available on the backend.' : error}</div>}
    {section === 'users' && <>
    <section className="panel admin-users-panel">
      <div className="admin-users-toolbar"><div><h2>User accounts</h2><p>Manage account roles. Passwords and sign-in secrets are never displayed.</p></div><label className="admin-search"><Search size={16}/><input value={query} onChange={event => setQuery(event.target.value)} placeholder="Search users…" aria-label="Search user accounts"/></label></div>
      {loading && <div className="admin-empty">Loading user accounts…</div>}
      {!loading && !error && visibleUsers.length === 0 && <div className="admin-empty">{users.length ? 'No accounts match your search.' : 'No user accounts found.'}</div>}
      {!loading && !error && visibleUsers.length > 0 && <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Username</th><th>Email</th><th>Mobile</th><th>Role</th><th>Created</th><th>Access</th></tr></thead><tbody>{visibleUsers.map(account => <tr key={account.id}><td><strong>{account.username || '—'}</strong></td><td>{account.email || '—'}</td><td>{account.phone || 'Not provided'}</td><td><span className={`admin-role role-${String(account.role || 'analyst').toLowerCase()}`}>{account.role || 'analyst'}</span></td><td>{account.created_at ? formatDate(account.created_at) : '—'}</td><td><button className="secondary-button admin-role-button" type="button" disabled={savingUserId === account.id} onClick={() => updateRole(account)}>{savingUserId === account.id ? 'Saving…' : account.role === 'admin' ? 'Make analyst' : 'Make admin'}</button></td></tr>)}</tbody></table></div>}
    </section>
    </>}
    {section === 'activity' && <section className="panel admin-users-panel">
      <div className="admin-users-toolbar"><div><h2>Recent activity</h2><p>Sign-ins, security operations, and administrative role changes.</p></div></div>
      {loading && <div className="admin-empty">Loading activity…</div>}
      {!loading && !error && activity.length === 0 && <div className="admin-empty">No recorded activity yet.</div>}
      {!loading && !error && activityByUser.length > 0 && <div className="admin-activity-groups">{activityByUser.map(({ username, actions }) => <details className="admin-activity-user" key={username}>
        <summary><strong>{username}</strong><span>{actions.length} {actions.length === 1 ? 'action' : 'actions'}</span></summary>
        <ul className="admin-activity-list">{actions.map(entry => <li key={entry.id}>
          <time>{entry.timestamp ? formatTimestamp(entry.timestamp) : '—'}</time>
          <strong>{String(entry.action || '').replaceAll('_', ' ')}</strong>
          {entry.target && <span>{entry.target}</span>}
        </li>)}</ul>
      </details>)}</div>}
    </section>}
  </div>
}
