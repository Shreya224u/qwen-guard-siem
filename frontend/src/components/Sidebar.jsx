import { LayoutDashboard, BellRing, ShieldAlert, FileUp, Network, Settings, MessageSquareText, Users, UserRound } from 'lucide-react'

const items = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'ingestion', label: 'Log Ingestion', icon: FileUp },
  { id: 'alerts', label: 'Alert Queue', icon: BellRing },
  { id: 'spam', label: 'Spam Watch', icon: ShieldAlert },
  { id: 'mitre', label: 'Attack Framework', icon: Network },
  { id: 'account', label: 'Account Center', icon: UserRound },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'feedback', label: 'Feedback', icon: MessageSquareText }
]

export default function Sidebar({ page, setPage, collapsed, alertCount = 0, isAdmin = false }) {
  const visibleItems = isAdmin ? [...items, { id: 'admin', label: 'Admin', icon: Users }] : items
  return <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
    <div className="brand">
      <div className="brand-mark"><img src="/siem-ai-logo.png" alt="SIEM AI logo" /></div>
      {!collapsed && <div><strong>SIEM <span>AI</span></strong><small>SECURITY OPERATIONS</small></div>}
    </div>
    <div className="side-label">{!collapsed && 'WORKSPACE'}</div>
    <nav>
      {visibleItems.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? 'active' : ''} ${id === 'alerts' && alertCount > 0 ? 'has-unresolved-alerts' : ''}`} onClick={() => setPage(id)} title={collapsed ? `${label}${id === 'alerts' && alertCount > 0 ? ` · ${alertCount} unresolved` : ''}` : undefined}>
        <Icon size={18} /><span>{!collapsed && label}</span>{id === 'alerts' && alertCount > 0 && <i className="nav-count">{alertCount}</i>}
      </button>)}
    </nav>
  </aside>
}
