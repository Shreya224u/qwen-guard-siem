import { useEffect, useRef } from 'react'
import { X } from 'lucide-react'
import { createPortal } from 'react-dom'

export default function Modal({ title, onClose, children, className = '' }) {
  const dialogRef = useRef(null)
  useEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return undefined
    dialog.showModal()
    return () => { if (dialog.open) dialog.close() }
  }, [])

  return createPortal(<dialog ref={dialogRef} className={`modal ${className}`.trim()} aria-label={title} onCancel={event => { event.preventDefault(); onClose() }} onClick={event => { if (event.target === event.currentTarget) onClose() }}>
    <header className="modal-header"><h3>{title}</h3><button type="button" className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={18}/></button></header>
    <div className="modal-content">{children}</div>
  </dialog>, document.body)
}
