import { useCallback, useEffect, useState } from 'react'
import {
  AlertTriangle, Check, Github, KeyRound, Laptop, Link2, LockKeyhole,
  BadgeCheck, CalendarDays, Fingerprint, Mail, Monitor, ShieldCheck, Smartphone, Unlink, UserRound, X,
} from 'lucide-react'
import { accountApi, authApi } from '../api'
import { formatDate, formatTimestamp } from '../utils/dateTime'

const providers = [
  { id: 'google', label: 'Google' },
  { id: 'github', label: 'GitHub' },
]

function deviceLabel(userAgent = '') {
  if (/android/i.test(userAgent)) return 'Android device'
  if (/iphone|ipad|ipod/i.test(userAgent)) return 'Apple mobile device'
  if (/windows/i.test(userAgent)) return 'Windows computer'
  if (/macintosh|mac os/i.test(userAgent)) return 'Mac computer'
  if (/linux/i.test(userAgent)) return 'Linux computer'
  return userAgent ? 'Unknown device' : 'Device details unavailable'
}

function browserLabel(userAgent = '') {
  if (/edg\//i.test(userAgent)) return 'Microsoft Edge'
  if (/opr\//i.test(userAgent)) return 'Opera'
  if (/firefox\//i.test(userAgent)) return 'Firefox'
  if (/chrome\//i.test(userAgent) && !/edg\//i.test(userAgent)) return 'Chrome'
  if (/safari\//i.test(userAgent) && !/chrome\//i.test(userAgent)) return 'Safari'
  return 'Browser'
}

function dateLabel(value) {
  return value ? formatTimestamp(value) : 'Unknown'
}

export default function AccountCenter({ token, onLogout, onTokenRefresh, initialNotice, clearInitialNotice }) {
  const [account, setAccount] = useState(null)
  const [sessions, setSessions] = useState([])
  const [providersReady, setProvidersReady] = useState({})
  const [trackingCurrentSession, setTrackingCurrentSession] = useState(true)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [password, setPassword] = useState({ current: '', next: '', confirm: '' })
  const [passwordResetLink, setPasswordResetLink] = useState('')
  const [emailChallenge, setEmailChallenge] = useState(null)
  const [emailCode, setEmailCode] = useState('')
  const [pendingTwoFactorState, setPendingTwoFactorState] = useState(null)
  const [confirmRevokeAll, setConfirmRevokeAll] = useState(false)

  const loadAccount = useCallback(async () => {
    setError('')
    try {
      const [profile, sessionResult, oauthProviders] = await Promise.all([
        accountApi.overview(token),
        accountApi.sessions(token),
        authApi.oauthProviders(),
      ])
      setAccount(profile)
      setSessions(sessionResult.sessions || [])
      setTrackingCurrentSession(sessionResult.tracking_current_session)
      setProvidersReady(oauthProviders)
    } catch (requestError) {
      setError(requestError.message || 'Could not load account details.')
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => { loadAccount() }, [loadAccount])
  useEffect(() => {
    if (!initialNotice) return
    setNotice(initialNotice)
    clearInitialNotice()
  }, [initialNotice, clearInitialNotice])

  const connectProvider = async provider => {
    setBusy(true)
    setError('')
    try {
      const result = await accountApi.linkProvider(provider, token)
      if (!result.authorization_url) throw new Error('The account linking service returned no authorization URL.')
      window.location.assign(result.authorization_url)
    } catch (requestError) {
      setError(requestError.message || `Could not connect ${provider}.`)
      setBusy(false)
    }
  }

  const requestPasswordReset = async () => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const result = await authApi.requestPasswordReset({ email: account.email })
      setPasswordResetLink(result.development_reset_url || '')
      setNotice(result.message || 'If the email belongs to an account, a reset link has been sent.')
    } catch (requestError) {
      setError(requestError.message || 'Could not request a password reset.')
    } finally {
      setBusy(false)
    }
  }

  const changePassword = async event => {
    event.preventDefault()
    setError('')
    setNotice('')
    if (password.next !== password.confirm) {
      setError('The new passwords do not match.')
      return
    }
    setBusy(true)
    try {
      const result = await accountApi.changePassword({ current_password: password.current, new_password: password.next }, token)
      onTokenRefresh(result)
      setPassword({ current: '', next: '', confirm: '' })
      setNotice('Password updated. Other signed-in devices have been signed out.')
    } catch (requestError) {
      setError(requestError.message || 'Could not update the password.')
    } finally {
      setBusy(false)
    }
  }

  const sendTwoFactorCode = async enabled => {
    setError('')
    setNotice('')
    setEmailChallenge(null)
    setEmailCode('')
    setBusy(true)
    try {
      const result = await accountApi.sendEmailTwoFactor(token)
      setEmailChallenge(result)
      setPendingTwoFactorState(enabled)
      setNotice(`A verification code was sent to ${account.email}.${result.development_code ? ` Local development code: ${result.development_code}` : ''}`)
    } catch (requestError) {
      setError(requestError.message || 'Could not send the security verification code.')
    } finally {
      setBusy(false)
    }
  }

  const confirmTwoFactor = async event => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await accountApi.confirmEmailTwoFactor({
          challenge_id: emailChallenge.challenge_id,
          code: emailCode.trim(),
          enabled: pendingTwoFactorState,
        }, token)
      setEmailChallenge(null)
      setEmailCode('')
      setPendingTwoFactorState(null)
      setNotice(pendingTwoFactorState
        ? 'Email two-factor authentication is enabled.'
        : 'Email two-factor authentication is disabled.')
      await loadAccount()
    } catch (requestError) {
      setError(requestError.message || 'Could not update two-factor authentication.')
    } finally {
      setBusy(false)
    }
  }

  const revokeSession = async session => {
    setError('')
    setBusy(true)
    try {
      const result = await accountApi.revokeSession(session.id, token)
      if (result.current_session_revoked) {
        onLogout()
        return
      }
      setNotice('That device has been signed out.')
      await loadAccount()
    } catch (requestError) {
      setError(requestError.message || 'Could not sign out that device.')
    } finally {
      setBusy(false)
    }
  }

  const revokeOtherSessions = async () => {
    setError('')
    setBusy(true)
    try {
      const result = await accountApi.revokeOtherSessions(token)
      setNotice(`${result.revoked_count} other device session${result.revoked_count === 1 ? '' : 's'} signed out.`)
      setConfirmRevokeAll(false)
      await loadAccount()
    } catch (requestError) {
      setError(requestError.message || 'Could not sign out other devices.')
    } finally {
      setBusy(false)
    }
  }

  const revokeAllSessions = async () => {
    setError('')
    setBusy(true)
    try {
      await accountApi.revokeAllSessions(token)
      onLogout()
    } catch (requestError) {
      setError(requestError.message || 'Could not sign out all devices.')
      setBusy(false)
    }
  }

  return <div className="page-stack account-center-page">
    <div className="page-heading">
      <div><div className="eyebrow">WORKSPACE / ACCOUNT</div><h1>Account Center</h1><p>Manage your profile, sign-in methods, security, and active devices.</p></div>
      <span className="account-center-heading-icon"><UserRound size={21}/></span>
    </div>

    {!loading && account && <section className="account-profile-banner" aria-label="Account profile summary">
      <div className="account-profile-avatar" aria-hidden="true">{account.username.slice(0, 2).toUpperCase()}</div>
      <div className="account-profile-identity">
        <span className="account-profile-eyebrow"><span className="pulse-dot"/> SECURITY PROFILE</span>
        <h2>{account.username}</h2>
        <p><Mail size={14}/>{account.email}</p>
      </div>
      <div className="account-profile-badges">
        <span className="account-profile-badge"><ShieldCheck size={14}/>{account.role}</span>
        <span className={`account-profile-badge ${account.email_two_factor_enabled ? 'secured' : ''}`}>
          <Fingerprint size={14}/>{account.email_two_factor_enabled ? '2FA enabled' : '2FA not enabled'}
        </span>
      </div>
      <div className="account-profile-meta">
        <div><span>ACCOUNT ID</span><strong>#{account.id}</strong></div>
        <div><span>MEMBER SINCE</span><strong><CalendarDays size={13}/>{formatDate(account.created_at, { day: undefined })}</strong></div>
        <div><span>EMAIL STATUS</span><strong className="account-profile-email-status"><BadgeCheck size={14}/> Account email</strong></div>
      </div>
    </section>}

    {error && <div className="notice error account-center-notice" role="alert"><AlertTriangle size={16}/><span>{error}</span></div>}
    {notice && <div className="notice info account-center-notice" role="status"><Check size={16}/><span>{notice}</span><button type="button" aria-label="Dismiss message" onClick={() => setNotice('')}><X size={15}/></button></div>}
    {loading && <div className="notice info">Loading account details…</div>}
    {!loading && account && <>
      <section className="panel account-center-card">
        <div className="account-center-card-icon"><UserRound size={18}/></div>
        <div className="account-center-card-content">
          <div className="account-center-card-heading"><div><h2>Account details</h2><p>Your SIEM AI account information.</p></div><span className="settings-section-label">PROFILE</span></div>
          <div className="account-detail-grid">
            <div><span>Name</span><strong>{account.username}</strong></div>
            <div><span>Email</span><strong>{account.email}</strong></div>
            <div><span>Mobile</span><strong>{account.phone || 'Not added'}</strong></div>
            <div><span>Role</span><strong>{account.role}</strong></div>
            <div><span>Account ID</span><strong>{account.id}</strong></div>
            <div><span>Account created</span><strong>{dateLabel(account.created_at)}</strong></div>
          </div>
        </div>
      </section>

      <section className="panel account-center-card">
        <div className="account-center-card-icon account-provider-icon"><Link2 size={18}/></div>
        <div className="account-center-card-content">
          <div className="account-center-card-heading"><div><h2>Connected accounts</h2><p>Link Google or GitHub to use it as an additional sign-in option.</p></div><span className="settings-section-label">SOCIAL SIGN-IN</span></div>
          <div className="account-provider-list">{providers.map(provider => {
            const linked = account.linked_providers.includes(provider.id)
            const Icon = provider.id === 'github' ? Github : Mail
            return <div className="account-provider-row" key={provider.id}>
              <span className={`account-provider-logo ${provider.id}`}>{provider.id === 'google' ? <b>G</b> : <Icon size={17}/>}</span>
              <div className="account-provider-copy"><strong>{provider.label}</strong><small>{linked ? 'Connected to this account' : providersReady[provider.id] ? 'Not connected' : 'Sign-in is not configured by the administrator'}</small></div>
              {linked
                ? <span className="account-connected"><Check size={14}/> Connected</span>
                : <button type="button" className="secondary-button" onClick={() => connectProvider(provider.id)} disabled={busy || !providersReady[provider.id]}><Link2 size={14}/> Connect</button>}
            </div>
          })}</div>
        </div>
      </section>

      <section className="panel account-center-card">
        <div className="account-center-card-icon account-security-icon"><ShieldCheck size={18}/></div>
        <div className="account-center-card-content">
          <div className="account-center-card-heading"><div><h2>Password & security</h2><p>Update your password and require email verification for phone and social sign-ins.</p></div><span className="settings-section-label">SECURITY</span></div>
          <form className="account-password-form" onSubmit={changePassword}>
            <h3><KeyRound size={15}/> Change password</h3>
            <div className="account-password-fields">
              <label>Current password<input className="form-input" type="password" autoComplete="current-password" value={password.current} onChange={event => setPassword({ ...password, current: event.target.value })} required/></label>
              <label>New password<input className="form-input" type="password" autoComplete="new-password" minLength={8} value={password.next} onChange={event => setPassword({ ...password, next: event.target.value })} required/></label>
              <label>Confirm new password<input className="form-input" type="password" autoComplete="new-password" minLength={8} value={password.confirm} onChange={event => setPassword({ ...password, confirm: event.target.value })} required/></label>
              <button className="secondary-button" type="submit" disabled={busy || !password.current || !password.next || !password.confirm}>Update password</button>
            </div>
            <button className="account-text-button" type="button" disabled={busy} onClick={requestPasswordReset}>Forgot your current password? Send a reset link to your email</button>
            {passwordResetLink && <a className="account-reset-link" href={passwordResetLink}>Open local password reset link</a>}
          </form>
          <div className="account-security-row">
            <span className="account-security-row-icon"><Mail size={16}/></span>
            <div className="account-provider-copy"><strong>Email two-factor authentication</strong><small>{account.email_two_factor_enabled ? `Enabled for ${account.email}` : 'Require an email code for phone and social sign-ins.'}</small></div>
            <button type="button" className={account.email_two_factor_enabled ? 'secondary-button' : 'primary-button'} disabled={busy} onClick={() => sendTwoFactorCode(!account.email_two_factor_enabled)}>{account.email_two_factor_enabled ? 'Turn off' : 'Turn on'}</button>
          </div>
          {emailChallenge && <form className="account-two-factor-form" onSubmit={confirmTwoFactor}>
            <label htmlFor="account-two-factor-code">Enter the 6-digit code sent to {account.email}</label>
            <div><input className="form-input" id="account-two-factor-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={emailCode} onChange={event => setEmailCode(event.target.value.replace(/\D/g, '').slice(0, 6))} required/><button type="submit" className="primary-button" disabled={busy || emailCode.length !== 6}>Verify & {pendingTwoFactorState ? 'enable' : 'disable'}</button></div>
          </form>}
        </div>
      </section>

      <section className="panel account-center-card">
        <div className="account-center-card-icon account-devices-icon"><Laptop size={18}/></div>
        <div className="account-center-card-content">
          <div className="account-center-card-heading"><div><h2>Manage account</h2><p>See where you’re logged in and sign out active SIEM AI devices.</p></div><span className="settings-section-label">DEVICES</span></div>
          {!trackingCurrentSession && <div className="account-session-tracking-note">This browser session started before device tracking was enabled. Sign out and sign back in to manage it here.</div>}
          {!sessions.length && <p className="account-empty-sessions">No active tracked sessions were found.</p>}
          {!!sessions.length && <div className="account-session-list">{sessions.map(session => <article className="account-session-row" key={session.id}>
            <span className="account-session-device-icon">{/mobile|android|iphone|ipad/i.test(session.user_agent) ? <Smartphone size={18}/> : <Monitor size={18}/>}</span>
            <div className="account-session-details"><strong>{deviceLabel(session.user_agent)} · {browserLabel(session.user_agent)} {session.current && <span className="account-current-badge">This device</span>}</strong><small>{session.ip_address || 'IP unavailable'} · Last active {dateLabel(session.last_seen_at)}</small><small>Signed in {dateLabel(session.created_at)} · Expires {dateLabel(session.expires_at)}</small></div>
            <button type="button" className={session.current ? 'danger-button' : 'secondary-button'} disabled={busy} onClick={() => revokeSession(session)}>{session.current ? 'Sign out' : 'Remove'}</button>
          </article>)}</div>}
          <div className="account-session-actions">
            {sessions.some(session => !session.current) && <button type="button" className="secondary-button" disabled={busy} onClick={revokeOtherSessions}><Unlink size={14}/> Sign out other devices</button>}
            {!confirmRevokeAll
              ? <button type="button" className="danger-button" disabled={busy || !sessions.length} onClick={() => setConfirmRevokeAll(true)}>Sign out all devices</button>
              : <div className="account-revoke-confirm"><span>This will sign out every device, including this one.</span><button type="button" className="danger-button" disabled={busy} onClick={revokeAllSessions}>Confirm sign out</button><button type="button" className="secondary-button" onClick={() => setConfirmRevokeAll(false)}>Cancel</button></div>}
          </div>
          <div className="account-saved-login-note"><LockKeyhole size={14}/><span>Saved logins here mean remembered active device sessions. SIEM AI never stores your browser’s saved passwords.</span></div>
        </div>
      </section>
    </>}
  </div>
}
