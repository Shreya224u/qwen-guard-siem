import { useEffect, useState } from 'react'
import { Eye, EyeOff, ArrowRight, Activity, LockKeyhole, Fingerprint, Github, Phone, AlertTriangle } from 'lucide-react'
import CyberParticleBackground from '../components/CyberParticleBackground'
import { apiUrl, authApi } from '../api'

const formatPhone = value => {
  const input = String(value || '').trim()
  const digits = input.replace(/\D/g, '')
  if (input.startsWith('+')) return `+${digits}`
  if (input.startsWith('00')) return `+${digits.slice(2)}`
  return `+91${digits.startsWith('91') && digits.length > 10 ? digits.slice(2) : digits}`
}
const isValidPhone = value => /^\+[1-9]\d{7,14}$/.test(formatPhone(value))

export default function Login({ onLogin, theme, setTheme, initialNotice = '', clearInitialNotice = () => {} }) {
  const [mode, setMode] = useState(() => new URLSearchParams(window.location.search).has('reset_token') ? 'reset' : 'login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [resetToken, setResetToken] = useState(() => new URLSearchParams(window.location.search).get('reset_token') || '')
  const [phone, setPhone] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [emailCode, setEmailCode] = useState('')
  const [phoneCode, setPhoneCode] = useState('')
  const [phoneDevelopmentCode, setPhoneDevelopmentCode] = useState('')
  const [emailChallenge, setEmailChallenge] = useState('')
  const [phoneChallenge, setPhoneChallenge] = useState('')
  const [emailVerificationToken, setEmailVerificationToken] = useState('')
  const [phoneVerificationToken, setPhoneVerificationToken] = useState('')
  const [emailCodeSent, setEmailCodeSent] = useState(false)
  const [phoneCodeSent, setPhoneCodeSent] = useState(false)
  const [email2faChallenge, setEmail2faChallenge] = useState('')
  const [email2faCode, setEmail2faCode] = useState('')
  const [email2faDevelopmentCode, setEmail2faDevelopmentCode] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [emailError, setEmailError] = useState('')
  const [phoneError, setPhoneError] = useState('')
  const [emailNotice, setEmailNotice] = useState('')
  const [phoneNotice, setPhoneNotice] = useState('')
  const [usernameError, setUsernameError] = useState('')
  const [passwordError, setPasswordError] = useState('')
  const [confirmPasswordError, setConfirmPasswordError] = useState('')
  const [passwordResetLink, setPasswordResetLink] = useState('')
  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1))
    const token = params.get('oauth_token')
    if (token && params.get('oauth_user')) {
      window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`)
      onLogin({ access_token: token, username: params.get('oauth_user'), role: params.get('oauth_role') || 'analyst' })
      return
    }
    const emailChallenge = params.get('email_2fa_challenge')
    if (emailChallenge) {
      setMode('login')
      setEmail2faChallenge(emailChallenge)
      setEmail2faDevelopmentCode(params.get('email_2fa_code') || '')
      setNotice(`Enter the verification code sent to your account email.${params.get('email_2fa_code') ? ` Local development code: ${params.get('email_2fa_code')}` : ''}`)
      window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`)
      return
    }
    const linkError = params.get('oauth_link_error')
    if (params.has('oauth_link') || linkError) {
      window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`)
      setError(linkError === 'already_linked'
        ? 'That social account is already linked to another SIEM AI account.'
        : 'Sign in to manage linked social accounts.')
      return
    }
    const oauthError = params.get('oauth_error')
    if (oauthError) {
      window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`)
      const messages = {
        expired_state: 'Sign-in took too long. Please try again.',
        provider_cancelled: 'Sign-in was cancelled at the provider. Please try again.',
        provider_rejected: 'The provider rejected this sign-in. Check the OAuth client secret and exact callback URL in the provider settings.',
        provider_unavailable: 'Could not reach the sign-in provider. Check your internet connection and try again.',
        verified_email_required: 'Add a verified primary email to your GitHub account, then try again.',
        sign_in_failed: 'The backend could not complete sign-in. Check the API log for the OAuth callback error.',
      }
      setError(messages[oauthError] || 'Google/GitHub sign-in failed. Please try again.')
    }
  }, [])
  useEffect(() => {
    if (!initialNotice) return
    setNotice(initialNotice)
    clearInitialNotice()
  }, [initialNotice, clearInitialNotice])
  const requestCode = async channel => {
    setError(''); setNotice('')
    const setInlineError = channel === 'email' ? setEmailError : setPhoneError
    const setInlineNotice = channel === 'email' ? setEmailNotice : setPhoneNotice
    setInlineError(''); setInlineNotice('')
    const value = channel === 'email' ? email.trim() : formatPhone(phone)
    if (!value || (channel === 'email' && !email.trim())) { setInlineError(`Enter your ${channel === 'email' ? 'email address' : 'mobile number'} first.`); return }
    if (channel === 'phone' && !isValidPhone(phone)) { setInlineError('Enter a valid mobile number with country code, such as +91 98765 43210.'); return }
    setBusy(true)
    try {
      const result = await authApi.sendVerification(channel, channel === 'email' ? { email: value } : { phone: value })
      const challenge = result.challenge_id || ''
      const devCodeNotice = result.development_code ? ` Local development code: ${result.development_code}` : ''
      if (channel === 'email') { setEmailChallenge(challenge); setEmailCodeSent(true); setEmailVerificationToken(''); setEmailNotice(`A verification code was ${result.delivery_mode === 'development' ? 'created for local testing.' : 'sent to your email.'}${devCodeNotice}`) }
      else { setPhoneChallenge(challenge); setPhoneCodeSent(true); setPhoneVerificationToken(''); setPhoneDevelopmentCode(result.development_code || ''); setPhoneNotice(`A verification code was ${result.delivery_mode === 'development' ? 'created for local testing.' : 'sent to your mobile number.'}${devCodeNotice}`) }
    } catch (err) { setInlineError(err.message || 'Could not send the verification code.') }
    finally { setBusy(false) }
  }
  const verifyCode = async channel => {
    setError(''); setNotice('')
    const setInlineError = channel === 'email' ? setEmailError : setPhoneError
    const setInlineNotice = channel === 'email' ? setEmailNotice : setPhoneNotice
    setInlineError(''); setInlineNotice('')
    const value = channel === 'email' ? email.trim() : formatPhone(phone)
    const code = channel === 'email' ? emailCode.trim() : phoneCode.trim()
    const challenge = channel === 'email' ? emailChallenge : phoneChallenge
    if (!code) { setInlineError('Enter the verification code.'); return }
    setBusy(true)
    try {
      const result = await authApi.verifyCode(channel, channel === 'email' ? { email: value, code, challenge_id: challenge } : { phone: value, code, challenge_id: challenge })
      if (!result.verification_token) throw new Error('Verification service returned no verification token.')
      if (channel === 'email') { setEmailVerificationToken(result.verification_token); setEmailNotice('Email verified successfully.') }
      else { setPhoneVerificationToken(result.verification_token); setPhoneNotice('Mobile number verified successfully.') }
    } catch (err) { setInlineError(err.message || 'That code could not be verified. Try again.') }
    finally { setBusy(false) }
  }
  const finishLogin = async (user, pass) => {
    const form = new URLSearchParams({ username: user, password: pass })
    const result = await authApi.login(form)
    onLogin(result)
  }
  const submit = async e => {
    e.preventDefault(); setError(''); setNotice('')
    if (mode === 'forgot') {
      if (!email.trim()) { setEmailError('Enter the email address linked to your account.'); return }
      setBusy(true)
      try {
        const result = await authApi.requestPasswordReset({ email: email.trim() })
        setPasswordResetLink(result.development_reset_url || '')
        setNotice(result.development_reset_url
          ? result.message
          : 'Reset request received. If this email is linked to an account, the link was sent. Check your Inbox and Spam/Junk folders.')
      } catch (err) { setEmailError(err.message || 'Could not request a password reset.') }
      finally { setBusy(false) }
      return
    }
    if (mode === 'reset') {
      if (password.length < 8) { setPasswordError('Choose a password with at least 8 characters.'); return }
      setBusy(true)
      try {
        const result = await authApi.confirmPasswordReset({ token: resetToken, new_password: password })
        window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.hash}`)
        setResetToken(''); setPassword('')
        if (result.access_token) onLogin(result)
        else { setMode('login'); setNotice(result.message || 'Password reset successfully. Please sign in again.') }
      } catch (err) { setError(err.message || 'Could not reset the password.') }
      finally { setBusy(false) }
      return
    }
    if (mode === 'phone') {
      if (email2faChallenge) {
        setBusy(true)
        try {
          const result = await authApi.verifyEmailChallenge({ challenge_id: email2faChallenge, code: email2faCode.trim() })
          setEmail2faChallenge(''); setEmail2faCode(''); onLogin(result)
        } catch (err) { setPhoneError(err.message || 'That email verification code could not sign you in.') }
        finally { setBusy(false) }
        return
      }
      if (!phoneCodeSent) { await requestCode('phone'); return }
      if (!phoneCode.trim()) { setPhoneError('Enter the verification code.'); return }
      setBusy(true)
      try {
        const result = await authApi.phoneLogin({ phone: formatPhone(phone), code: phoneCode.trim(), challenge_id: phoneChallenge })
        if (result.requires_email_verification) {
          setEmail2faChallenge(result.challenge_id)
          setEmail2faDevelopmentCode(result.development_code || '')
          setNotice(`Your password-free sign-in was verified. Enter the email code to continue.${result.development_code ? ` Local development code: ${result.development_code}` : ''}`)
        } else onLogin(result)
      } catch (err) { setPhoneError(err.message || 'That code could not sign you in.') }
      finally { setBusy(false) }
      return
    }
    setBusy(true)
    try {
      if (mode === 'register') {
        setUsernameError(''); setPasswordError(''); setConfirmPasswordError(''); setEmailError(''); setPhoneError('')
        if (!username.trim()) { setUsernameError('Enter a username.'); setBusy(false); return }
        if (!email.trim()) { setEmailError('Enter your email address.'); setBusy(false); return }
        if (!password) { setPasswordError('Enter a password.'); setBusy(false); return }
        if (!confirmPassword) { setConfirmPasswordError('Confirm your password.'); setBusy(false); return }
        if (password !== confirmPassword) { setConfirmPasswordError('Passwords do not match.'); setBusy(false); return }
        if (!emailVerificationToken) { setEmailError('Verify your email address before creating your account.'); setBusy(false); return }
        if (phone.trim() && !isValidPhone(phone)) { setPhoneError('Enter a valid mobile number with country code, such as +91 98765 43210.'); setBusy(false); return }
        if (phone.trim() && !phoneVerificationToken) { setPhoneError('Verify this mobile number or leave it blank to continue with email only.'); setBusy(false); return }
        const registration = { username: username.trim(), email: email.trim(), email_verification_token: emailVerificationToken, password, role: 'analyst' }
        if (phone.trim()) {
          registration.phone = formatPhone(phone)
          registration.phone_verification_token = phoneVerificationToken
        }
        await authApi.register(registration)
        await finishLogin(username.trim(), password)
      } else if (mode === 'login') {
        if (email2faChallenge) {
          if (!email2faCode.trim()) throw new Error('Enter the email verification code.')
          const result = await authApi.verifyEmailChallenge({ challenge_id: email2faChallenge, code: email2faCode.trim() })
          setEmail2faChallenge(''); setEmail2faCode(''); onLogin(result)
        } else {
          if (!username.trim() || !password) throw new Error('Enter your username or email and password.')
          const form = new URLSearchParams({ username: username.trim(), password })
          const result = await authApi.login(form)
          if (result.requires_email_verification) {
            setEmail2faChallenge(result.challenge_id)
            setEmail2faDevelopmentCode(result.development_code || '')
            setNotice(`Enter the verification code sent to your account email.${result.development_code ? ` Local development code: ${result.development_code}` : ''}`)
          } else onLogin(result)
        }
      } else {
        if (!username.trim() || !password) throw new Error('Enter your username or email and password.')
        await finishLogin(username.trim(), password)
      }
    } catch (err) {
      const message = err.message || 'Could not connect to the authentication server.'
      if (mode === 'register' && /email|mail/i.test(message)) setEmailError(message)
      else if (mode === 'register' && /phone|mobile/i.test(message)) setPhoneError(message)
      else if (mode === 'register' && /username/i.test(message)) setUsernameError(message)
      else if (mode === 'register' && /password/i.test(message)) setPasswordError(message)
      else setError(message)
    }
    finally { setBusy(false) }
  }
  const switchMode = next => { setMode(next); if (next === 'phone' && !phone.trim()) setPhone('+91 '); if (next === 'register' && !phoneVerificationToken) setPhone(''); setError(''); setNotice(''); setPhoneCodeSent(false); setPhoneCode(''); setPhoneChallenge(''); setPhoneDevelopmentCode(''); setEmail2faChallenge(''); setEmail2faCode(''); setEmail2faDevelopmentCode('') }
  const startOAuth = async provider => {
    setError(''); setNotice(''); setBusy(true)
    try {
      const providers = await authApi.oauthProviders()
      if (!providers[provider]) {
        setNotice(`${provider === 'google' ? 'Google' : 'GitHub'} sign-in is not configured on the backend yet.`)
        return
      }
      window.location.assign(apiUrl(`/auth/oauth/${provider}/start?frontend_origin=${encodeURIComponent(window.location.origin)}`))
    } catch (err) { setError(err.message || 'Could not reach the sign-in service.') }
    finally { setBusy(false) }
  }
  const passwordResetNotice = () => { setMode('forgot'); setError(''); setNotice(''); setEmail('') }
  return <div className="login-screen">
    <CyberParticleBackground/>
    <header className="login-top"><div className="brand-mark"><img src="/siem-ai-logo.png" alt="SIEM AI logo" /></div><div className="login-brand">SIEM <span>AI</span></div><button className="theme-switch" type="button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>{theme === 'dark' ? '☼ Light mode' : '☾ Dark mode'}</button></header>
    <div className="login-layout">
      <div className="login-copy"><div className="login-copy-brand"><span className="login-copy-logo"><img src="/siem-ai-logo.png" alt="SIEM AI security logo"/></span><div><strong>SIEM <span>AI</span></strong><small>SECURITY OPERATIONS PLATFORM</small></div></div><div className="eyebrow login-copy-eyebrow"><span className="pulse-dot"/> BUILT FOR SECURITY TEAMS</div><h1>See the signal.<br/><span>Stop the threat.</span></h1><p>Sign in to review security events and investigate alerts from your connected SIEM workspace.</p><div className="login-metrics"><div><Activity size={17}/><strong>Event visibility</strong><small>Centralized logs</small></div><div><Fingerprint size={17}/><strong>Threat detection</strong><small>Rules and analytics</small></div><div><LockKeyhole size={17}/><strong>Protected access</strong><small>Account-based sign in</small></div></div></div>
      <form className="login-card" onSubmit={submit}>
        <div className="login-card-brand"><span className="login-card-icon"><img src="/siem-ai-logo.png" alt="" /></span><span><strong>SIEM AI</strong><small>SECURITY INTELLIGENCE</small></span></div>
        <div className="eyebrow login-card-eyebrow">SECURITY OPERATIONS CENTER</div><h2>{mode === 'register' ? 'Create an account' : mode === 'phone' ? 'Sign in with mobile' : mode === 'forgot' ? 'Reset your password' : mode === 'reset' ? 'Choose a new password' : 'Welcome back'}</h2><p className="muted">{mode === 'register' ? 'Verify your email to create an account. Mobile number is optional.' : mode === 'phone' ? 'We will text a one-time sign-in code to your phone.' : mode === 'forgot' ? 'We will email you a secure link to reset your password.' : mode === 'reset' ? 'Enter a new password for your SIEM AI account.' : 'Sign in to access your security dashboard.'}</p>
        {mode === 'forgot' && <><label className="field-label">Email address</label><input className="form-input" type="email" autoComplete="email" value={email} onChange={e => { setEmail(e.target.value); setEmailError('') }} placeholder="you@example.com"/>{emailError && <p className="field-message error" role="alert">{emailError}</p>}{notice && <p className="field-message success" role="status">{notice}</p>}{passwordResetLink && <a className="password-reset-dev-link" href={passwordResetLink}>Open password reset link</a>}</>}
        {mode === 'reset' && <><label className="field-label">New password</label><div className="password-field"><input className="form-input" autoComplete="new-password" type={showPassword ? 'text' : 'password'} value={password} onChange={e => { setPassword(e.target.value); setPasswordError('') }} placeholder="At least 8 characters"/><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={17}/> : <Eye size={17}/>}</button></div>{passwordError && <p className="field-message error" role="alert">{passwordError}</p>}</>}
        {mode === 'register' && <>
          <label className="field-label">Email address</label>
          <div className="verification-contact"><input className="form-input" type="email" autoComplete="email" value={email} onChange={e => { setEmail(e.target.value); setEmailError(''); setEmailNotice(''); setEmailCodeSent(false); setEmailVerificationToken(''); setEmailChallenge(''); setEmailCode('') }} placeholder="you@example.com"/><button type="button" className="secondary-button" onClick={() => requestCode('email')} disabled={busy || !!emailVerificationToken}>{emailVerificationToken ? 'Verified' : emailCodeSent ? 'Resend code' : 'Send code'}</button></div>
          {emailCodeSent && !emailVerificationToken && <div className="verification-code-row"><input className="form-input" inputMode="numeric" autoComplete="one-time-code" value={emailCode} onChange={e => { setEmailCode(e.target.value); setEmailError('') }} placeholder="Email verification code"/><button type="button" className="secondary-button" onClick={() => verifyCode('email')} disabled={busy}>Verify</button></div>}
          {emailError && <p className="field-message error" role="alert">{emailError}</p>}
          {emailNotice && <p className="field-message success" role="status">{emailNotice}</p>}
          <label className="field-label">Mobile number <span className="muted">(optional)</span></label>
          <div className="verification-contact"><input className="form-input" autoComplete="tel" type="tel" value={phone} onChange={e => { setPhone(e.target.value); setPhoneError(''); setPhoneNotice(''); setPhoneCodeSent(false); setPhoneVerificationToken(''); setPhoneChallenge(''); setPhoneCode(''); setPhoneDevelopmentCode('') }} placeholder="+country code and number"/><button type="button" className="secondary-button" onClick={() => requestCode('phone')} disabled={busy || !!phoneVerificationToken}>{phoneVerificationToken ? 'Verified' : phoneCodeSent ? 'Resend code' : 'Send code'}</button></div>
          {phoneCodeSent && !phoneVerificationToken && <div className="verification-code-row"><input className="form-input" inputMode="numeric" autoComplete="one-time-code" value={phoneCode} onChange={e => { setPhoneCode(e.target.value); setPhoneError('') }} placeholder="SMS verification code"/><button type="button" className="secondary-button" onClick={() => verifyCode('phone')} disabled={busy}>Verify</button></div>}
          {phoneCodeSent && phoneDevelopmentCode && <p className="local-dev-code">Local development OTP: <strong>{phoneDevelopmentCode}</strong></p>}
          {phoneError && <p className="field-message error" role="alert">{phoneError}</p>}
          {phoneNotice && <p className="field-message success" role="status">{phoneNotice}</p>}
          <label className="field-label">Username</label><input className="form-input" autoComplete="username" value={username} onChange={e => { setUsername(e.target.value); setUsernameError('') }} placeholder="Your username"/>{usernameError && <p className="field-message error" role="alert">{usernameError}</p>}
          <div className="login-password-label"><label className="field-label">Password</label></div><div className="password-field"><input className="form-input" autoComplete="new-password" type={showPassword ? 'text' : 'password'} value={password} onChange={e => { setPassword(e.target.value); setPasswordError(''); setConfirmPasswordError('') }} placeholder="Password"/><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={17}/> : <Eye size={17}/>}</button></div>{passwordError && <p className="field-message error" role="alert">{passwordError}</p>}
          <div className="login-password-label"><label className="field-label">Confirm password</label></div><div className="password-field"><input className="form-input" autoComplete="new-password" type={showConfirmPassword ? 'text' : 'password'} value={confirmPassword} onChange={e => { setConfirmPassword(e.target.value); setConfirmPasswordError('') }} placeholder="Re-enter password"/><button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)} aria-label="Toggle confirm password visibility">{showConfirmPassword ? <EyeOff size={17}/> : <Eye size={17}/>}</button></div>{confirmPasswordError && <p className="field-message error" role="alert">{confirmPasswordError}</p>}
        </>}
        {mode === 'phone' && <>{!email2faChallenge && <><label className="field-label">Mobile number</label><input className="form-input" autoComplete="tel" type="tel" value={phone} onChange={e => { setPhone(e.target.value); setPhoneError(''); setPhoneCodeSent(false); setPhoneChallenge(''); setPhoneCode(''); setPhoneDevelopmentCode('') }} placeholder="+country code and number"/>{phoneCodeSent && <><label className="field-label">Verification code</label><input className="form-input" inputMode="numeric" autoComplete="one-time-code" value={phoneCode} onChange={e => { setPhoneCode(e.target.value); setPhoneError('') }} placeholder="Enter SMS code"/><p className="local-dev-code">{phoneDevelopmentCode ? <>Local development OTP: <strong>{phoneDevelopmentCode}</strong></> : 'Check your mobile for the SMS code.'}</p></>}</>}{email2faChallenge && <><label className="field-label">Email verification code</label><input className="form-input" inputMode="numeric" autoComplete="one-time-code" value={email2faCode} onChange={e => { setEmail2faCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setPhoneError('') }} placeholder="Enter the 6-digit email code"/>{email2faDevelopmentCode && <p className="local-dev-code">Local development code: <strong>{email2faDevelopmentCode}</strong></p>}</>}{phoneError && <p className="field-message error" role="alert">{phoneError}</p>}{phoneNotice && <p className="field-message success" role="status">{phoneNotice}</p>}</>}
        {mode === 'login' && <><label className="field-label">Username or email</label><input className="form-input" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} placeholder="Your username or email"/>{!email2faChallenge && <><div className="login-password-label"><label className="field-label">Password</label><button type="button" onClick={passwordResetNotice}>Forgot password?</button></div><div className="password-field"><input className="form-input" autoComplete="current-password" type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)} placeholder="Password"/><button type="button" onClick={() => setShowPassword(!showPassword)} aria-label="Toggle password visibility">{showPassword ? <EyeOff size={17}/> : <Eye size={17}/>}</button></div></>}{email2faChallenge && <><label className="field-label">Email verification code</label><input className="form-input" inputMode="numeric" autoComplete="one-time-code" value={email2faCode} onChange={e => { setEmail2faCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setError('') }} placeholder="Enter the 6-digit email code"/>{email2faDevelopmentCode && <p className="local-dev-code">Local development code: <strong>{email2faDevelopmentCode}</strong></p>}</>}</>}
        {error && (mode === 'login' || mode === 'phone') && <div className="form-error" role="alert"><span className="form-error-icon"><AlertTriangle size={17}/></span><div><strong>Oops!</strong><p>{error}</p></div></div>}
        {error && mode !== 'forgot' && mode !== 'phone' && mode !== 'login' && <div className="form-error" role="alert"><span className="form-error-icon"><AlertTriangle size={17}/></span><div><strong>Oops!</strong><p>{error}</p></div></div>}
        {notice && mode !== 'forgot' && mode !== 'register' && mode !== 'phone' && <p className="auth-notice" role="status">{notice}</p>}
        {mode === 'register' && !emailVerificationToken && <p className="verification-hint">Verify your email to create the account. Phone verification is only needed if you add a mobile number.</p>}
        <button className="primary-button login-submit" type="submit" disabled={busy || (mode === 'register' && (!emailVerificationToken || (!!phone.trim() && !phoneVerificationToken)))}>{busy ? 'Please wait…' : mode === 'register' ? 'Create account' : mode === 'phone' ? email2faChallenge ? 'Verify & sign in' : phoneCodeSent ? 'Verify & sign in' : 'Send sign-in code' : mode === 'forgot' ? 'Send reset link' : mode === 'reset' ? 'Update password' : email2faChallenge ? 'Verify & sign in' : 'Sign in'} <ArrowRight size={17}/></button>
        {mode === 'login' && <>
          <div className="login-divider"><span>or continue with</span></div>
          <div className="social-signin"><button type="button" className="social-button" onClick={() => startOAuth('google')} disabled={busy}><span className="google-mark">G</span>Google</button><button type="button" className="social-button" onClick={() => startOAuth('github')} disabled={busy}><Github size={15}/>GitHub</button></div>
          <button className="social-button phone-signin" type="button" onClick={() => switchMode('phone')}><Phone size={15}/> Continue with mobile number</button>
        </>}
        <p className="signup-prompt">{mode === 'register' ? 'Already have an account?' : mode === 'phone' ? 'Want to use your password?' : mode === 'forgot' || mode === 'reset' ? 'Remember your password?' : 'New to SIEM AI?'} <button type="button" onClick={() => { setMode(mode === 'register' || mode === 'phone' || mode === 'forgot' || mode === 'reset' ? 'login' : 'register'); setError(''); setNotice('') }}>{mode === 'register' || mode === 'phone' || mode === 'forgot' || mode === 'reset' ? 'Back to sign in' : 'Create an account'}</button></p>
        <div className="login-legal">Secure access to your Security Intelligence Platform</div>
      </form>
    </div>
    <footer className="login-footer"><span>SIEM AI</span><span><b className="text-green">●</b> ACCOUNT AUTHENTICATION</span></footer>
  </div>
}
