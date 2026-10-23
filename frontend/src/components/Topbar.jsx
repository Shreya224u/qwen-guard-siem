import { useEffect, useState } from 'react'
import { Search, Sun, Moon, Command, LogOut, Menu } from 'lucide-react'

export default function Topbar({ theme, setTheme, query, setQuery, onLogout, onToggleSidebar, user }) {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])
  const date = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short', year: 'numeric' }).format(now)
  const time = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: true }).format(now)
  return <header className="topbar">
    <button className="icon-button mobile-menu" onClick={onToggleSidebar} aria-label="Toggle menu"><Menu size={18}/></button>
    <div className="crumb"><span>Workspace</span><b>/</b><strong>Security Operations</strong></div>
    <div className="top-actions">
      <label className="global-search"><Search size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search events, IPs..." /><kbd><Command size={10}/> K</kbd></label>
      <button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title="Toggle theme">{theme === 'dark' ? <Sun size={17}/> : <Moon size={17}/>}</button>
      <div className="top-divider" />
      <div className="user-avatar user-name" title={user} aria-label={`Signed in as ${user}`}>{user}</div>
      <button className="icon-button" title="Sign out" onClick={() => onLogout?.()}><LogOut size={17}/></button>
      <time className="topbar-clock" dateTime={now.toISOString()} aria-label={`Current date ${date}, current time ${time}`}><span>{date}</span><strong>{time}</strong></time>
    </div>
  </header>
}
