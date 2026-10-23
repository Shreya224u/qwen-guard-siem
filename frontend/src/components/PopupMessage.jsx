import { useState } from 'react'
import { CheckCircle2 } from 'lucide-react'
import Modal from './Modal'

const icons = {
  success: CheckCircle2,
}

function WarningIcon() {
  return <svg viewBox="0 0 128 120" width="112" height="112" aria-hidden="true">
    <path d="M53.6 12.5c4.7-8.2 16.5-8.2 21.2 0l48.3 83.7c4.7 8.2-1.2 18.4-10.6 18.4H15.9c-9.4 0-15.3-10.2-10.6-18.4z" fill="currentColor"/>
    <rect x="57" y="34" width="14" height="43" rx="7" fill="#fff"/>
    <circle cx="64" cy="94" r="7.5" fill="#fff"/>
  </svg>
}

export default function PopupMessage({
  title,
  message,
  variant = 'alert',
  actionLabel,
  cancelLabel,
  onAction,
  onClose,
}) {
  const [expanded, setExpanded] = useState(false)
  const Icon = icons[variant] || icons.success
  const showImmediately = variant === 'welcome'

  return <Modal title={title} onClose={onClose} className={`center-popup-modal center-popup-${variant}`}>
    <div className={`center-popup${expanded ? ' is-expanded' : ''}`}>
      {showImmediately
        ? <div className="center-popup-icon center-popup-icon-static" aria-hidden="true"><img src="/siem-ai-logo.png" alt="" /></div>
        : <button
          type="button"
          className="center-popup-icon"
          onClick={() => setExpanded(open => !open)}
          aria-label={expanded ? 'Hide message details' : `Show details: ${title}`}
          aria-expanded={expanded}
        >
          {variant === 'alert' ? <WarningIcon/> : <Icon size={112} strokeWidth={1.55} aria-hidden="true" />}
        </button>}
      {(showImmediately || expanded) && <div className="center-popup-details">
        <span className="center-popup-eyebrow">SIEM AI · {variant === 'welcome' ? 'WELCOME' : variant === 'success' ? 'SUCCESS' : 'NOTICE'}</span>
        <h2>{title}</h2>
        <p>{message}</p>
        {(actionLabel || cancelLabel) && <div className="center-popup-actions">
          {cancelLabel && <button type="button" className="center-popup-cancel" onClick={onClose}>{cancelLabel}</button>}
          {actionLabel && <button type="button" className="center-popup-action" onClick={onAction}>{actionLabel}</button>}
        </div>}
      </div>}
    </div>
  </Modal>
}
