import { useEffect, useRef, useState } from 'react'
import { RotateCcw, Send, Sparkles, X } from 'lucide-react'
import { timestampValue } from '../utils/dateTime'

const quickQuestions = ['Guide me around SIEM AI', 'How do I upload logs?', 'How do I review an alert?']

const projectAnswers = [
  { match: /how (?:do i|can i|to) analyse|how (?:do i|can i|to) analyze|uploaded file.*(?:analyse|analyze)/, answer: 'To analyse an uploaded file, open Log Ingestion and click the filename in Uploaded files. SIEM AI opens Spam Watch with that upload selected, where you can review or scan its stored logs.', answerHi: 'Uploaded file analyse karne ke liye Log Ingestion mein Uploaded files ke andar us file ke naam par click karein. SIEM AI Spam Watch mein wahi upload select karega, jahan aap stored logs review ya scan kar sakti hain.' },
  { match: /how .*compact|compact interface.*(?:use|work|mean)|reduce spacing/, answer: 'Compact interface is in Settings → Appearance. Turn it on to reduce spacing in dashboard panels, cards, and rows so more content fits on screen. The preference is saved in this browser.', answerHi: 'Settings → Appearance mein Compact interface on karein. Isse dashboard panels, cards aur rows ki spacing kam hoti hai, taaki screen par zyada content dikhe. Ye preference isi browser mein save hoti hai.' },
  { match: /light mode|dark mode|theme change|change.*theme|color theme/, answer: 'Open Settings → Appearance and choose Light or Dark. The theme applies immediately and is saved in this browser.', answerHi: 'Settings → Appearance mein Light ya Dark choose karein. Theme turant apply hoti hai aur isi browser mein save hoti hai.' },
  { match: /review.*alert|alert.*details|event details|alert queue.*use|alert status|status.*alert/, answer: 'In Alert Queue, select Actions on an alert row to open its details. To change its status, press Action and choose Open, Investigating, Confirmed threat, False positive, or Resolved.', answerHi: 'Alert Queue mein row ke Actions button se details kholiye. Status badalne ke liye Action dabakar Open, Investigating, Confirmed threat, False positive ya Resolved chuniye.' },
  { match: /what.*mitre|mitre.*what|what.*att&ck|mitre.*framework|brute.?force.*technique|technique.*id|t1110|brute.?force.*mitre|mitre.*brute.?force/, answer: 'MITRE ATT&CK maps detected activity to attacker tactics and techniques. For example, brute_force maps to T1110 Brute Force under the Credential Access tactic. Alert details show a mapping when one is available.', answerHi: 'MITRE ATT&CK detected activity ko attacker tactics aur techniques se map karta hai. Example: brute_force, T1110 Brute Force technique se map hota hai jo Credential Access tactic mein hai. Mapping available ho to alert details mein dikhegi.' },
  { match: /app kya hai|siem ai kya|app kaise kaam|app ko kaise use|mujhe guide|guide karo|app samjhao/, answer: 'SIEM AI security logs analyse karke alerts review karne ka workspace hai. Shuru karne ke liye Log Ingestion mein CSV/LOG/TXT upload karein; Alert Queue mein detections investigate karein; Spam Watch mein selected file scan karein; MITRE ATT&CK mein technique mappings dekhein. Aap jis screen par hain uska naam ya screenshot/error bhejein, main uske exact steps bataunga.' },
  { match: /how (?:does|do) (?:this|the) app work|what is this app/, answer: 'SIEM AI is a security monitoring workspace. Upload a log file in Log Ingestion, review generated detections in Alert Queue, scan selected uploads in Spam Watch, and explore technique mappings in MITRE ATT&CK. Ask me about any section or paste an error and I can explain what to do next.' },
  { match: /(?:process|workflow|steps?).{0,35}(?:log )?ingestion|(?:log )?ingestion.{0,35}(?:process|workflow|steps?)|how does log ingestion work|ingestion ka process|log ingest kaise kaam/, answer: 'Log ingestion ka flow: 1) Log Ingestion mein CSV, LOG ya TXT file select karein. 2) Upload dabayein. 3) SIEM file ko parse/validate karke log records store karta hai. 4) Detection rules aur ML analysis records check karte hain aur matches par alerts bante hain. 5) Uploaded files mein counts dekhein; Alert Queue mein alerts review karein. File ko detail mein analyse karne ke liye Uploaded files mein uske naam par click karein.', answerEn: 'Log ingestion flow: 1) Open Log Ingestion and choose a CSV, LOG, or TXT file. 2) Click Upload. 3) SIEM parses and validates the file, then stores its log records. 4) Detection rules and ML analysis evaluate the records and create alerts for matches. 5) Check file counts in Uploaded files and review alerts in Alert Queue. Click the filename in Uploaded files to analyse that upload.' },
  { match: /alert kaise dekhe|alert ki detail|status kaise badle|alert status change/, answer: 'Alert Queue kholiye → alert row ke Actions button par click kijiye. Event details mein Action dabakar status option chuniye. MITRE mapping available ho to details mein dikh jayegi.' },
  { match: /file upload kaise|logs? upload kaise|file analyse|file analyze|uploaded file.*analyse|uploaded file.*analyze/, answer: 'Log Ingestion → Browse files se CSV, LOG ya TXT choose kijiye → Upload dabaiye. Uploaded files list mein file name par click karne se us upload ko Spam Watch mein analyse kar sakti hain.' },
  { match: /spam.*scan kaise|spam watch kaise|phishing.*scan kaise/, answer: 'Spam Watch kholiye, uploaded file selector se file chuniye, phir Scan selected file dabaiye. Results selected file ke stored logs ke liye hote hain.' },
  { match: /compact.*kya|compact interface.*use|theme.*kaise badle|light mode.*kaise|dark mode.*kaise/, answer: 'Settings → Appearance mein Light/Dark choose karke theme badlein. Compact interface on karne se cards aur rows ki spacing kam hoti hai. Reset preferences icon default display settings restore karta hai.' },
  { match: /mitre.*kya|brute.?force.*mitre|t1110/, answer: 'MITRE ATT&CK attacker tactics aur techniques ka framework hai. SIEM mein brute_force event T1110 – Brute Force technique se map hota hai, jo Credential Access tactic ke under hai.' },
  { match: /what (?:is|does) (?:this|the) (?:app|siem|platform)|what is siem ai|about this (?:app|project)/, answer: 'SIEM AI is a security monitoring workspace. Upload log files to store and evaluate records, review generated alerts, scan a selected upload for spam or phishing, and explore mapped MITRE ATT&CK techniques.' },
  { match: /how (?:do i|to) upload|upload instructions|supported (?:file|format)/, answer: 'Open Log Ingestion, choose a CSV, LOG, or TXT file, then select Upload and process. The SIEM stores the parsed records and evaluates them for alerts. Uploaded files and their alert counts appear in the Uploaded files section.' },
  { match: /how (?:are|do) alerts? (?:generated|create)|alert generation|where (?:do|are) alerts? come from/, answer: 'Alerts are generated when an uploaded log file is evaluated by the SIEM rule and ML engines. No new upload means no new alerts are generated. Each alert is linked to its source log.' },
  { match: /spam watch|scan.*spam|spam.*scan|phishing scan/, answer: 'In Spam Watch, choose an uploaded file and select Scan selected file. The scanner checks that file’s stored log text for spam and phishing indicators. Results are limited to the selected upload.' },
  { match: /delete.*(?:upload|file|logs?)|remove.*(?:upload|file)/, answer: 'Open Log Ingestion → Uploaded files and use Delete beside the file. This removes that upload’s stored logs and generated alerts.' },
  { match: /feedback.*(?:attach|file|screenshot)|attachment.*feedback/, answer: 'Feedback is under the Feedback section. A screenshot or video attachment is optional; you can submit feedback without uploading a file.' },
  { match: /google.*(?:sign|login)|github.*(?:sign|login)|oauth/, answer: 'Google and GitHub sign-in need OAuth Client ID and Client Secret values configured in backend/.env. The backend setup guide is backend/OAUTH_SETUP.md. Keep the client secret out of frontend code.' },
  { match: /phone.*(?:otp|sign|login)|(?:otp|sms).*(?:phone|mobile)|mobile login/, answer: 'Phone sign-in uses a one-time verification code. For real SMS delivery, configure Twilio credentials in backend/.env. Check the phone number format and Twilio Verify configuration if no code arrives.' },
  { match: /review.*alert|alert.*details|event details|alert queue.*use|alert status|status.*alert/, answer: 'In Alert Queue, use the row Actions button to open details. Severity, status, source, timestamp, and any MITRE mapping appear there. To change status, press Action and choose Open, Investigating, Confirmed threat, False positive, or Resolved.' },
  { match: /mitre|att&ck|brute.?force.*technique|technique.*id/, answer: 'The MITRE ATT&CK page maps detected activity to attacker tactics and techniques. Example: brute_force maps to T1110 Brute Force under Credential Access. Alert details show the mapping when one is available.' },
  { match: /compact interface|compact mode|compact ka kya|spacing kam/, answer: 'In Settings → Appearance, turn on Compact interface to reduce spacing in cards, panels, and rows, so more content fits on screen. The preference is saved in this browser.' },
  { match: /light mode|dark mode|theme change|theme kaise|color theme/, answer: 'In Settings → Appearance, choose Light or Dark. The theme applies immediately and is saved in this browser.' },
  { match: /session expired|sign.?in.*expire|logout|sign out/, answer: 'A sign-in session expires when its saved login token is no longer valid. Sign in again to create a fresh session.' },
]

const pageGuides = {
  overview: 'Aap Overview par hain. Yahan logs/alerts ka summary, severity, charts aur recent records dikhte hain. Kisi alert ki details ke liye Alert Queue kholiye.',
  ingestion: 'Aap Log Ingestion par hain. CSV, LOG ya TXT file choose karke upload karein. Uploaded files mein filename par click karke us file ko analyse karein; Delete us file ke logs aur generated alerts remove karta hai.',
  alerts: 'Aap Alert Queue par hain. Search ya filters se alerts dhoondhein. Row ke Actions button se event details, MITRE mapping aur status actions dekhein.',
  spam: 'Aap Spam Watch par hain. Uploaded file select karke scan karein; us file mein mile spam/phishing alerts yahin review karein.',
  mitre: 'Aap MITRE ATT&CK par hain. Techniques tactic ke hisaab se grouped hain. Technique ID/name search karein; T1110 Brute Force, Credential Access ke andar hai.',
  settings: 'Aap Settings par hain. Appearance mein theme aur compact spacing badlein. Account session mein signed-in user dekhein. Reset icon display preferences ko default par laata hai.',
  feedback: 'Aap Feedback par hain. Category choose karke issue describe karein. Privacy consent zaroori hai; file attach karna optional hai.',
}

const pageGuidesEn = {
  overview: 'You are on Overview. It summarizes logs, alerts, severity, charts, and recent records. Open Alert Queue to inspect an alert.',
  ingestion: 'You are on Log Ingestion. Choose a CSV, LOG, or TXT file and upload it. Click its filename in Uploaded files to analyse that upload; Delete removes its logs and generated alerts.',
  alerts: 'You are on Alert Queue. Search or filter alerts, then use a row Actions button to view event details, MITRE mapping, and status actions.',
  spam: 'You are on Spam Watch. Select an uploaded file and scan it to review spam or phishing alerts found in that file.',
  mitre: 'You are on MITRE ATT&CK. Techniques are grouped by tactic. Search by technique ID or name; T1110 Brute Force is under Credential Access.',
  settings: 'You are on Settings. Appearance controls the theme and compact spacing. Account session shows the signed-in user. The reset icon restores display defaults.',
  feedback: 'You are on Feedback. Choose a category and describe the issue. Privacy consent is required; file attachments are optional.',
}

function buildReply(question, events, logsTotal, alertsTotal, currentPage) {
  const prompt = question.toLowerCase()
  const isHindi = /[\u0900-\u097f]/.test(question) || /\b(kya|kaise|mujhe|kijiye|karo|hai|hain|batao|samjhao|dikhao|mera|meri|ye|isse|kaha|kyu|nahi|nhi|chahiye|karna|mein|krna)\b/i.test(question)
  const alerts = events.filter(event => event.recordType === 'alert')
  const logs = events.filter(event => event.recordType === 'log')
  const critical = alerts.filter(event => event.severity === 'Critical')
  const high = alerts.filter(event => event.severity === 'High')

  // Recognize the ingestion success text when a user pastes it into chat.
  // Handle it before alert-category intents so a pasted result is never
  // misread as a question about spam/phishing records.
  if (/logs? ingested|logs? stored|automatic investigation scheduled|rule\s*\+\s*ml engines?/i.test(prompt) && /alerts? created/i.test(prompt)) {
    const counts = prompt.match(/(\d+)\s+logs? stored[,;.]?\s*(\d+)\s+skipped[,;.]?\s*(\d+)\s+alerts? created/i)
    if (counts) return `Upload completed successfully: ${counts[1]} logs stored, ${counts[2]} skipped, and ${counts[3]} alerts created. The alerts were generated from this upload and can be reviewed in Alert Queue.`
    return 'This message confirms the upload completed: logs were stored and evaluated, and alerts were created for review in Alert Queue.'
  }

  if (/(what is this|what does this|this section|ye kya|ye kis liye|iska kya use|is section|ye kis kaam|kya use hai)/.test(prompt)) {
    return isHindi
      ? (pageGuides[currentPage] || 'SIEM AI mein Overview par summaries, Log Ingestion par file processing, Alert Queue par investigations, Spam Watch par spam scans, MITRE ATT&CK par technique mappings, Settings par preferences, aur Feedback par issue reporting milti hai.')
      : (pageGuidesEn[currentPage] || 'SIEM AI includes Overview for summaries, Log Ingestion for file processing, Alert Queue for investigations, Spam Watch for file scans, MITRE ATT&CK for technique mappings, Settings for preferences, and Feedback for issue reports.')
  }
  if (/\b(help|what can you do|commands|guide me|guide|samjhao|samjha do|kaise use|kaha se shuru|start kaise)\b/.test(prompt)) {
    return isHindi
      ? `Main SIEM AI use karne mein step-by-step guide karunga. ${pageGuides[currentPage] || 'Sidebar se Overview, Log Ingestion, Alert Queue, Spam Watch, MITRE ATT&CK, Settings ya Feedback khol sakti hain.'}\n\nAap pooch sakti hain: “ye section kya karta hai?”, “alert ka status kaise badlu?” ya “is error ka kya matlab hai?” Main loaded alerts/logs ka summary bhi de sakta hoon.`
      : `I can guide you through SIEM AI step by step. ${pageGuidesEn[currentPage] || 'Use the sidebar to open Overview, Log Ingestion, Alert Queue, Spam Watch, MITRE ATT&CK, Settings, or Feedback.'}\n\nAsk what a section does, how to change an alert status, or what an error means. I can also summarize the loaded alerts and logs.`
  }
  if (/critical|high severity|highest risk/.test(prompt)) {
    const matches = /critical/.test(prompt) ? critical : high
    if (!matches.length) return `There are no ${/critical/.test(prompt) ? 'critical' : 'high severity'} alerts in the currently loaded records.`
    return `${matches.length} ${/critical/.test(prompt) ? 'critical' : 'high severity'} alert${matches.length === 1 ? '' : 's'} in the loaded records:\n${matches.slice(0, 4).map(event => `• ${event.type} — ${event.source} (${event.id})`).join('\n')}${matches.length > 4 ? '\n…and more in Alert Queue.' : ''}`
  }
  const projectAnswer = projectAnswers.find(item => item.match.test(prompt))
  if (projectAnswer) return isHindi ? (projectAnswer.answerHi || projectAnswer.answer) : (projectAnswer.answerEn || projectAnswer.answer)
  if (/spam|phish|junk mail/.test(prompt)) {
    const matches = alerts.filter(event => /spam|phish|mail|email|bulk/i.test(`${event.type} ${event.message}`))
    if (matches.length) return `${matches.length} spam or phishing alert${matches.length === 1 ? '' : 's'} in the currently loaded records:\n${matches.slice(0, 5).map(event => `• ${event.type} — ${event.source} (${event.id})`).join('\n')}${matches.length > 5 ? '\n…and more in Spam Watch.' : ''}`
    return `There are no spam or phishing alerts in the currently loaded records. Spam Watch scans one selected uploaded file; ${logsTotal ? 'choose a file there and run “Scan selected file” to check its stored logs.' : 'upload a log file first, then select it in Spam Watch and run a scan.'}`
  }
  if (/mitre|att&ck|attack framework/.test(prompt)) {
    const mapped = [...new Map(alerts.map(event => {
      const raw = event.raw || {}
      const id = raw.mitre_technique_id
      return id ? [id, `${id} ${raw.mitre_technique_name || ''} — ${raw.mitre_tactic || ''}`] : null
    }).filter(Boolean))]
    return mapped.length ? `MITRE ATT&CK mappings in the loaded alerts:\n${mapped.slice(0, 5).map(([, description]) => `• ${description}`).join('\n')}` : 'The MITRE ATT&CK section lists the five unique techniques configured for this SIEM. An alert appears mapped when its detection rule has an associated technique.'
  }
  if (/\b(open|unresolved|pending|resolved|investigat(?:ing|ion))\b/.test(prompt) && /alert|status|case/.test(prompt)) {
    const status = /resolved/.test(prompt) ? 'Resolved' : /investigat/.test(prompt) ? 'Investigating' : 'Open'
    const matches = alerts.filter(event => event.status === status)
    return `${matches.length} ${status.toLowerCase()} alert${matches.length === 1 ? '' : 's'} in the currently loaded records.${matches.length ? `\n${matches.slice(0, 5).map(event => `• ${event.type} — ${event.source} (${event.id})`).join('\n')}` : ''}`
  }
  if (/alert|threat|summary|summari[sz]e/.test(prompt)) {
    if (!alertsTotal) return 'No alerts are loaded for this session yet. Upload a log file in Log Ingestion to run detection and create alerts.'
    return `The SIEM has ${alertsTotal.toLocaleString()} alert${alertsTotal === 1 ? '' : 's'} in the loaded workspace. I can see ${alerts.length} here, including ${critical.length} critical and ${high.length} high severity. ${logsTotal.toLocaleString()} logs are stored for this account.`
  }
  if (/log|upload|file|ingest/.test(prompt)) {
    if (!logsTotal) return 'There are no uploaded logs in this workspace yet. Open Log Ingestion and upload a CSV, LOG, or TXT file to begin.'
    const sources = [...new Set(logs.map(event => event.raw?.source_file).filter(Boolean))]
    return `${logsTotal.toLocaleString()} logs are stored for this account. ${sources.length ? `Recently loaded file${sources.length === 1 ? '' : 's'}: ${sources.slice(0, 4).join(', ')}.` : `${logs.length} log records are currently loaded.`} Upload another file from Log Ingestion to analyze it.`
  }
  if (/recent|latest|activity/.test(prompt)) {
    const recent = [...events].sort((a, b) => timestampValue(b.time) - timestampValue(a.time)).slice(0, 4)
    if (!recent.length) return 'No activity is loaded yet. Upload a log file to get started.'
    return `Recent loaded activity:\n${recent.map(event => `• ${event.recordType === 'alert' ? 'Alert' : 'Log'}: ${event.type} — ${event.source} (${event.severity})`).join('\n')}`
  }

  const matches = events.filter(event => `${event.id} ${event.type} ${event.source} ${event.message}`.toLowerCase().includes(prompt))
  if (matches.length) {
    return `I found ${matches.length} matching loaded record${matches.length === 1 ? '' : 's'}:\n${matches.slice(0, 4).map(event => `• ${event.recordType === 'alert' ? 'Alert' : 'Log'}: ${event.type} — ${event.source} (${event.id})`).join('\n')}`
  }
  return 'I couldn’t find that in the loaded records. Try asking for an alert summary, critical alerts, recent activity, or search by IP or event type.'
}

export default function ChatAssistant({ events, logsTotal, alertsTotal, apiConnected, currentPage }) {
  const [open, setOpen] = useState(false)
  const [avoidDelete, setAvoidDelete] = useState(false)
  const [draft, setDraft] = useState('')
  const [messages, setMessages] = useState([
    { id: 1, role: 'assistant', text: 'Hi! I’m SIEM AI Assistant. Ask me about the logs and alerts in your workspace.' },
  ])
  const listRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    if (open) {
      listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' })
      inputRef.current?.focus()
    }
  }, [open, messages])

  useEffect(() => {
    const handlePointerMove = event => {
      const nearDeleteButton = [...document.querySelectorAll('.upload-history-delete:not(:disabled)')].some(button => {
        const rect = button.getBoundingClientRect()
        const distanceX = Math.max(rect.left - event.clientX, 0, event.clientX - rect.right)
        const distanceY = Math.max(rect.top - event.clientY, 0, event.clientY - rect.bottom)
        return distanceX <= 48 && distanceY <= 48
      })
      setAvoidDelete(current => current === nearDeleteButton ? current : nearDeleteButton)
    }
    const resetAvoidance = () => setAvoidDelete(false)
    window.addEventListener('pointermove', handlePointerMove, { passive: true })
    window.addEventListener('blur', resetAvoidance)
    return () => {
      window.removeEventListener('pointermove', handlePointerMove)
      window.removeEventListener('blur', resetAvoidance)
    }
  }, [])

  const ask = question => {
    const text = question.trim()
    if (!text) return
    setMessages(current => [
      ...current,
      { id: Date.now(), role: 'user', text },
      { id: Date.now() + 1, role: 'assistant', text: buildReply(text, events, logsTotal, alertsTotal, currentPage) },
    ])
    setDraft('')
  }

  const resetChat = () => setMessages([
    { id: Date.now(), role: 'assistant', text: 'Chat cleared. Ask me about the logs and alerts in your workspace.' },
  ])

  return <div className={`chat-assistant${avoidDelete ? ' is-avoiding-delete' : ''}`}>
    {open && <button type="button" className="chat-backdrop" onClick={() => setOpen(false)} aria-label="Close SIEM AI Assistant sidebar"/>}
    {open && <section className="chat-panel" aria-label="SIEM AI Assistant sidebar">
      <header className="chat-header">
        <span className="chat-brand-icon"><img src="/chatbot-robot.svg" alt=""/></span>
        <div className="chat-heading"><strong>SIEM AI Assistant</strong><small><i className={`chat-status-dot${apiConnected ? ' is-online' : ''}`}/>{apiConnected ? 'Workspace connected' : 'Workspace data unavailable'}</small></div>
        <button type="button" className="chat-header-button" onClick={resetChat} aria-label="Clear chat"><RotateCcw size={15}/></button>
        <button type="button" className="chat-header-button" onClick={() => setOpen(false)} aria-label="Close chat"><X size={17}/></button>
      </header>
      <div className="chat-context"><Sparkles size={13}/> App guidance + loaded SIEM data</div>
      <div className="chat-messages" ref={listRef} aria-live="polite">
        {messages.map(message => <div className={`chat-message ${message.role}`} key={message.id}>
          {message.role === 'assistant' && <span className="chat-message-avatar"><img src="/chatbot-robot.svg" alt=""/></span>}
          <p>{message.text}</p>
        </div>)}
      </div>
      {messages.length === 1 && <div className="chat-suggestions">{quickQuestions.map(question => <button type="button" key={question} onClick={() => ask(question)}>{question}</button>)}</div>}
      <form className="chat-compose" onSubmit={event => { event.preventDefault(); ask(draft) }}>
        <input ref={inputRef} value={draft} onChange={event => setDraft(event.target.value)} placeholder="Ask how to use SIEM AI…" aria-label="Ask SIEM AI Assistant"/>
        <button type="submit" disabled={!draft.trim()} aria-label="Send message"><Send size={16}/></button>
      </form>
      <div className="chat-disclaimer">Workspace assistant · responses are based on loaded records</div>
    </section>}
    <button type="button" className={`chat-launcher${open ? ' is-open' : ''}`} onClick={() => setOpen(value => !value)} aria-expanded={open} aria-label={open ? 'Close SIEM AI Assistant' : 'Open SIEM AI Assistant'}>
      {open ? <X size={21}/> : <img src="/chatbot-robot.svg" alt="" className="chat-launcher-robot"/>}
    </button>
  </div>
}
