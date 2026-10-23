import { useEffect, useMemo, useRef, useState } from 'react'
import { Search, Sun, Moon, Command, LogOut, Menu, ArrowUpRight } from 'lucide-react'

const pageCommands = [
  { id: 'overview', label: 'Overview', terms: ['overview', 'dashboard', 'home', 'summary'] },
  { id: 'ingestion', label: 'Log Ingestion', terms: ['ingestion', 'log ingestion', 'upload logs', 'upload', 'logs'] },
  { id: 'alerts', label: 'Alert Queue', terms: ['alerts', 'alert queue', 'alert', 'threats', 'detections'] },
  { id: 'spam', label: 'Spam Watch', terms: ['spam watch', 'spam', 'phishing'] },
  { id: 'mitre', label: 'Attack Framework', terms: ['attack framework', 'mitre', 'attack', 'techniques', 'tactics'] },
  { id: 'account', label: 'Account Center', terms: ['account center', 'account', 'profile'] },
  { id: 'settings', label: 'Settings', terms: ['settings', 'preferences', 'configuration'] },
  { id: 'feedback', label: 'Feedback', terms: ['feedback', 'support'] },
  { id: 'admin', label: 'Admin', terms: ['admin', 'administrator', 'user management', 'users'], adminOnly: true },
]

function normalizeIntent(value) {
  return String(value || '').toLowerCase().replace(/[’']/g, '').replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .replace(/\b(please|show|open|go|navigate|take|me|to|the|page|screen|section|mujhe|dikha|dikhao|kholo|khol|do|de|kar|karo|jao|par|chahiye)\b/g, ' ')
    .replace(/\s+/g, ' ').trim()
}

function findPageCommands(query, isAdmin) {
  const intent = normalizeIntent(query)
  return pageCommands.filter(item => !item.adminOnly || isAdmin)
    .map(item => ({ ...item, score: intent ? Math.max(...item.terms.map(term => {
      const normalized = normalizeIntent(term)
      return normalized === intent ? 3 : intent.includes(normalized) ? 2 : normalized.includes(intent) && intent.length > 2 ? 1 : 0
    })) : 0 }))
    .filter(item => !intent || item.score > 0)
    .sort((a, b) => b.score - a.score || a.label.localeCompare(b.label))
    .slice(0, intent ? 4 : 6)
}

function recordMatches(record, query) {
  const searchable = `${record.id} ${record.type} ${record.source} ${record.message} ${record.time} ${record.severity} ${record.status}`.toLowerCase()
  return searchable.includes(query.trim().toLowerCase())
}

export default function Topbar({ theme, setTheme, query, setQuery, onLogout, onToggleSidebar, user, isAdmin = false, records = [], onNavigate, onSelectSearchResult }) {
  const [now, setNow] = useState(() => new Date())
  const [searchOpen, setSearchOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const searchRef = useRef(null)
  const searchShellRef = useRef(null)
  const pageMatches = useMemo(() => findPageCommands(query, isAdmin), [query, isAdmin])
  const recordResults = useMemo(() => query.trim().length < 2 ? [] : records.filter(record => recordMatches(record, query)).slice(0, 5), [records, query])

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    const handleShortcut = event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setSearchOpen(true)
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', handleShortcut)
    return () => window.removeEventListener('keydown', handleShortcut)
  }, [])

  useEffect(() => {
    const handleOutsideClick = event => {
      if (!searchShellRef.current?.contains(event.target)) setSearchOpen(false)
    }
    document.addEventListener('pointerdown', handleOutsideClick)
    return () => document.removeEventListener('pointerdown', handleOutsideClick)
  }, [])

  useEffect(() => setActiveIndex(0), [query])

  const date = new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short', year: 'numeric' }).format(now)
  const time = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', hour12: true }).format(now)
  const choosePage = item => {
    onNavigate?.(item.id)
    setQuery('')
    setSearchOpen(false)
    searchRef.current?.blur()
  }
  const chooseRecord = record => {
    onSelectSearchResult?.(record)
    setSearchOpen(false)
    searchRef.current?.blur()
  }
  const handleSearchKeyDown = event => {
    const optionCount = pageMatches.length + recordResults.length
    if (event.key === 'Escape') { setSearchOpen(false); searchRef.current?.blur(); return }
    if (event.key === 'ArrowDown' && optionCount) { event.preventDefault(); setActiveIndex(index => (index + 1) % optionCount); return }
    if (event.key === 'ArrowUp' && optionCount) { event.preventDefault(); setActiveIndex(index => (index - 1 + optionCount) % optionCount); return }
    if (event.key === 'Enter') {
      event.preventDefault()
      if (activeIndex < pageMatches.length && pageMatches[activeIndex]) choosePage(pageMatches[activeIndex])
      else if (recordResults[activeIndex - pageMatches.length]) chooseRecord(recordResults[activeIndex - pageMatches.length])
      else if (pageMatches[0]) choosePage(pageMatches[0])
      else if (recordResults[0]) chooseRecord(recordResults[0])
      else setSearchOpen(false)
    }
  }

  return <header className="topbar">
    <button className="icon-button mobile-menu" onClick={onToggleSidebar} aria-label="Toggle menu"><Menu size={18}/></button>
    <div className="crumb"><span>Workspace</span><b>/</b><strong>Security Operations</strong></div>
    <div className="top-actions">
      <div className="global-search-shell" ref={searchShellRef}>
        <label className="global-search"><Search size={16}/><input ref={searchRef} value={query} onChange={event => { setQuery(event.target.value); setSearchOpen(true) }} onFocus={() => setSearchOpen(true)} onKeyDown={handleSearchKeyDown} placeholder="Search pages, events, IPs..." aria-label="Search pages and records" aria-expanded={searchOpen} aria-controls="global-search-results" autoComplete="off"/><kbd><Command size={10}/> K</kbd></label>
        {searchOpen && <div className="global-search-results" id="global-search-results" role="listbox">
          {pageMatches.length > 0 && <>
            <div className="global-search-heading">{query.trim() ? 'Go to page' : 'Pages'}</div>
            {pageMatches.map((item, index) => <button key={item.id} type="button" role="option" aria-selected={activeIndex === index} className={`global-search-option ${activeIndex === index ? 'selected' : ''}`} onMouseEnter={() => setActiveIndex(index)} onMouseDown={event => event.preventDefault()} onClick={() => choosePage(item)}><span>{item.label}</span><small>Open page</small><ArrowUpRight size={14}/></button>)}
          </>}
          {recordResults.length > 0 && <>
            <div className="global-search-heading">Matching loaded records</div>
            {recordResults.map((record, index) => {
              const optionIndex = pageMatches.length + index
              return <button key={`${record.recordType}-${record.id}`} type="button" role="option" aria-selected={activeIndex === optionIndex} className={`global-search-option record-option ${activeIndex === optionIndex ? 'selected' : ''}`} onMouseEnter={() => setActiveIndex(optionIndex)} onMouseDown={event => event.preventDefault()} onClick={() => chooseRecord(record)}><span>{record.type || record.id}</span><small>{record.recordType === 'alert' ? 'Alert' : 'Log'} · {record.source || 'Unknown source'}</small><ArrowUpRight size={14}/></button>
            })}
          </>}
          {query.trim().length >= 2 && pageMatches.length === 0 && recordResults.length === 0 && <div className="global-search-empty">No matching page or loaded record.</div>}
          <div className="global-search-hint">↑ ↓ to navigate · Enter to open · Esc to close</div>
        </div>}
      </div>
      <button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} title="Toggle theme">{theme === 'dark' ? <Sun size={17}/> : <Moon size={17}/>}</button>
      <div className="top-divider" />
      <div className="user-avatar user-name" title={user} aria-label={`Signed in as ${user}`}>{user}</div>
      <button className="icon-button" title="Sign out" onClick={() => onLogout?.()}><LogOut size={17}/></button>
      <time className="topbar-clock" dateTime={now.toISOString()} aria-label={`Current date ${date}, current time ${time}`}><span>{date}</span><strong>{time}</strong></time>
    </div>
  </header>
}
