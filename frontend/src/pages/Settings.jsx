import { useState } from 'react'
import { Settings as SettingsIcon, Palette, Database, ShieldCheck, Info, Sun, Moon, Minimize2, UserRound, RotateCcw, Check } from 'lucide-react'

export default function Settings({ theme, setTheme, user, onLogout }) {
  const [compact, setCompact] = useState(localStorage.getItem('siem-compact') === 'true')
  const [toast, setToast] = useState('')

  const toggleCompact = event => {
    const enabled = event.target.checked
    setCompact(enabled)
    localStorage.setItem('siem-compact', String(enabled))
    document.documentElement.classList.toggle('compact-mode', enabled)
    setToast(enabled ? 'Compact interface enabled.' : 'Comfortable spacing restored.')
  }

  const clear = () => {
    localStorage.removeItem('siem-theme')
    localStorage.removeItem('siem-compact')
    setTheme('dark')
    setCompact(false)
    document.documentElement.classList.remove('compact-mode')
    setToast('Display preferences reset to defaults.')
  }

  return <div className="page-stack settings-page">
    <div className="page-heading"><div><div className="eyebrow">WORKSPACE / PREFERENCES</div><h1>Settings</h1><p>Make your SIEM workspace feel right for you.</p></div><span className="settings-heading-icon"><SettingsIcon size={21}/></span></div>
    {toast && <div className="notice info settings-toast"><Check size={16}/><p>{toast}</p></div>}

    <section className="panel settings-card settings-appearance">
      <div className="settings-section-icon appearance-icon"><Palette size={19}/></div>
      <div className="settings-content">
        <div className="settings-card-heading"><div><h3>Appearance</h3><p>Choose how your workspace looks and feels.</p></div><span className="settings-section-label">DISPLAY</span></div>
        <div className="settings-option setting-row">
          <div className="settings-option-copy"><strong>Color theme</strong><small>Pick a theme for the dashboard.</small></div>
          <div className="theme-choice" role="group" aria-label="Color theme">
            <button type="button" className={theme === 'light' ? 'selected' : ''} aria-pressed={theme === 'light'} onClick={() => setTheme('light')}><Sun size={15}/> Light</button>
            <button type="button" className={theme === 'dark' ? 'selected' : ''} aria-pressed={theme === 'dark'} onClick={() => setTheme('dark')}><Moon size={15}/> Dark</button>
          </div>
        </div>
        <div className="settings-option setting-row">
          <span className="settings-option-icon"><Minimize2 size={16}/></span>
          <div className="settings-option-copy"><strong>Compact interface</strong><small>Use tighter spacing to fit more dashboard content on screen.</small></div>
          <label className="settings-switch"><input type="checkbox" checked={compact} onChange={toggleCompact} aria-label="Compact interface"/><span className="settings-switch-track"/></label>
        </div>
      </div>
    </section>

    <section className="panel settings-card">
      <div className="settings-section-icon account-icon"><ShieldCheck size={19}/></div>
      <div className="settings-content">
        <div className="settings-card-heading"><div><h3>Account session</h3><p>Manage the account currently connected to this workspace.</p></div><span className="settings-section-label">ACCOUNT</span></div>
        <div className="settings-option setting-row">
          <span className="settings-option-icon"><UserRound size={16}/></span>
          <div className="settings-option-copy"><span className="settings-account-label">Signed in as</span><strong className="settings-username">{user || 'Unknown user'}</strong></div>
          <button className="secondary-button" type="button" onClick={() => onLogout?.()}>Sign out</button>
        </div>
      </div>
    </section>

    <section className="panel settings-card">
      <div className="settings-section-icon data-icon"><Database size={19}/></div>
      <div className="settings-content">
        <div className="settings-card-heading"><div><h3>Data & privacy</h3><p>Log records and alert updates are managed by your connected SIEM API.</p></div><span className="settings-section-label">PREFERENCES</span></div>
        <div className="settings-option setting-row">
          <button className="settings-option-icon settings-reset-icon" type="button" onClick={clear} aria-label="Reset display preferences" title="Reset display preferences"><RotateCcw size={16}/></button>
          <div className="settings-option-copy"><strong>Reset display preferences</strong><small>Restore the default theme and comfortable spacing.</small></div>
        </div>
      </div>
    </section>
  </div>
}
