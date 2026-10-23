import { useCallback, useEffect, useRef, useState } from 'react'
import { UploadCloud, FileText, AlertCircle, X, Database, Clock3, RefreshCw, Trash2, FileSearch } from 'lucide-react'
import { logsApi } from '../api'
import { formatTimestamp } from '../utils/dateTime'
import PopupMessage from '../components/PopupMessage'

export default function Ingestion({ onImported, onDeleted, onAnalyzeUploadedFile, token }) {
  const inputRef = useRef(null)
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState(null)
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState('')
  const [deletingFilename, setDeletingFilename] = useState('')
  const [pendingDelete, setPendingDelete] = useState(null)
  const refreshHistory = useCallback(async () => {
    setHistoryLoading(true); setHistoryError('')
    try { setHistory(await logsApi.uploads(token)) }
    catch (error) { setHistoryError(error.message || 'Could not load uploaded files.') }
    finally { setHistoryLoading(false) }
  }, [token])
  useEffect(() => { refreshHistory() }, [refreshHistory])
  const chooseFile = selected => { setNotice(null); setFile(selected || null) }
  const deleteUpload = async item => {
    setPendingDelete(null)
    setDeletingFilename(item.filename); setNotice(null)
    try {
      await logsApi.deleteUpload(item.filename, token)
      await Promise.all([refreshHistory(), onDeleted?.(item.filename)])
    } catch (error) { setNotice({ type: 'error', text: error.message || 'Could not delete this uploaded file.' }) }
    finally { setDeletingFilename('') }
  }
  const upload = async () => {
    if (!file) return
    setBusy(true); setNotice(null)
    try {
      const form = new FormData(); form.append('file', file)
      const result = await logsApi.upload(form, token)
      setNotice(null)
      setFile(null)
      if (inputRef.current) inputRef.current.value = ''
      // The upload is complete once the API responds. Refresh the dashboard
      // and upload history without keeping the Upload button in its busy state.
      void Promise.allSettled([onImported?.(result), refreshHistory()])
    } catch (error) { setNotice({ type: 'error', text: error.message || 'The SIEM API could not process this file.' }) }
    finally { setBusy(false) }
  }
  const drop = e => { e.preventDefault(); chooseFile(e.dataTransfer.files?.[0]) }
  return <div className="page-stack">
    {pendingDelete && <PopupMessage variant="alert" title={`Delete ${pendingDelete.filename}?`} message={`This will permanently remove ${pendingDelete.logs_count.toLocaleString()} stored logs and ${pendingDelete.alerts_count.toLocaleString()} generated alerts from this upload.`} cancelLabel="Cancel" actionLabel="Delete upload" onAction={() => deleteUpload(pendingDelete)} onClose={() => setPendingDelete(null)}/>}
    <div className="page-heading"><div><div className="eyebrow">DATA PIPELINE / INGESTION</div><h1>Log ingestion</h1><p>Upload a supported log file to the SIEM processing pipeline.</p></div></div>
    <div className="info-banner"><Database size={15}/> Files are sent to the authenticated SIEM API for parsing, storage, rule evaluation, and alert generation.</div>
    <section className="panel ingestion-panel"><div className="panel-header"><div><h3>Upload log file</h3><p>Choose a supported log file to begin processing.</p></div><span className="ingestion-format"><FileText size={15}/>CSV · LOG · TXT</span></div>
      <div className={`drop-zone${file ? ' has-file' : ''}`} onDragOver={e => e.preventDefault()} onDrop={drop} onClick={() => inputRef.current?.click()}>
        <input ref={inputRef} type="file" accept=".csv,.log,.txt,text/csv,text/plain" hidden onChange={e => chooseFile(e.target.files?.[0])}/>
        <div className="upload-icon"><UploadCloud size={23}/></div><div className="drop-copy"><h3>{file ? file.name : 'Drag and drop your log file'}</h3><p>{file ? `${(file.size / 1024).toFixed(1)} KB · ready to analyze` : 'Select a file from your device or drop it here'}</p></div><button className="secondary-button" type="button" onClick={e => { e.stopPropagation(); inputRef.current?.click() }}>{file ? 'Choose file' : 'Browse files'}</button>
      </div>
      <div className="ingestion-actions"><button className="primary-button" onClick={upload} disabled={!file || busy}>{busy ? 'Uploading…' : 'Upload'} <UploadCloud size={15}/></button></div>
    </section>
    <section className="panel upload-history-panel">
      <div className="panel-header"><div><h3>Uploaded files</h3><p>Files are grouped by name; deleting removes all matching logs and generated alerts.</p></div><button className="secondary-button" type="button" onClick={refreshHistory} disabled={historyLoading}><RefreshCw size={14}/> Refresh</button></div>
      {notice?.type === 'error' && <div className="notice error"><AlertCircle size={16}/><p>{notice.text}</p><button onClick={() => setNotice(null)} aria-label="Dismiss"><X size={14}/></button></div>}
      {historyLoading ? <div className="empty-state"><span>Loading upload history…</span></div>
        : historyError ? <div className="notice error"><p>{historyError}</p></div>
          : history.length === 0 ? <div className="empty-state"><FileText size={23}/><strong>No uploaded files yet</strong><span>Uploaded log files will appear here.</span></div>
            : <div className="upload-history-list">{history.map(item => <article className="upload-history-row" key={item.filename}>
              <span className="upload-history-icon"><FileText size={17}/></span>
              <div className="upload-history-name"><button className="upload-history-file-button" type="button" onClick={() => onAnalyzeUploadedFile?.(item.filename)} title={`View analysis for ${item.filename}`}><span>{item.filename}</span><FileSearch size={13}/></button><small><Clock3 size={12}/> {formatTimestamp(item.last_uploaded_at)}</small></div>
              <div className="upload-history-counts"><span>{item.logs_count.toLocaleString()} logs</span><span>{item.alerts_count.toLocaleString()} alerts</span></div>
              <button className="upload-history-delete" type="button" onClick={() => setPendingDelete(item)} disabled={busy || historyLoading || Boolean(deletingFilename)} title={`Delete ${item.filename}`} aria-label={`Delete ${item.filename}`}><Trash2 size={15}/><span>{deletingFilename === item.filename ? 'Deleting…' : 'Delete'}</span></button>
            </article>)}</div>}
    </section>
  </div>
}
