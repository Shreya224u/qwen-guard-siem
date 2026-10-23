import { useRef, useState } from 'react'
import { MessageSquareText, Send, Star, UploadCloud } from 'lucide-react'
import PopupMessage from '../components/PopupMessage'
import { feedbackApi } from '../api'

const categories = ['Bug report', 'Feature request', 'Design/Usability', 'General praise']
const maxAttachmentBytes = 10 * 1024 * 1024

export default function Feedback({ token, user }) {
  const [name, setName] = useState(user || '')
  const [email, setEmail] = useState('')
  const [rating, setRating] = useState(0)
  const [category, setCategory] = useState('Bug report')
  const [visitReason, setVisitReason] = useState('')
  const [foundWhatNeeded, setFoundWhatNeeded] = useState('')
  const [comments, setComments] = useState('')
  const [attachment, setAttachment] = useState(null)
  const [consent, setConsent] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const formRef = useRef(null)

  const submit = async event => {
    event.preventDefault()
    setError('')
    setSubmitted(false)
    if (!rating || !foundWhatNeeded || !visitReason.trim() || !comments.trim() || !consent) {
      setError('Complete the star rating, required questions, comments, and consent before submitting.')
      return
    }
    if (attachment && attachment.size > maxAttachmentBytes) {
      setError('Choose an image or video smaller than 10 MB.')
      return
    }

    const form = new FormData()
    form.append('name', name.trim())
    form.append('email', email.trim())
    form.append('star_rating', String(rating))
    form.append('category', category)
    form.append('visit_reason', visitReason.trim())
    form.append('found_what_needed', foundWhatNeeded)
    form.append('comments', comments.trim())
    form.append('consent', String(consent))
    if (attachment) form.append('attachment', attachment)

    setBusy(true)
    try {
      await feedbackApi.submit(form, token)
      setSubmitted(true)
      setRating(0)
      setCategory('Bug report')
      setVisitReason('')
      setFoundWhatNeeded('')
      setComments('')
      setAttachment(null)
      setConsent(false)
      formRef.current?.reset()
    } catch (err) {
      setError(err.message || 'Feedback could not be submitted. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  return <div className="page-stack">
    {submitted && <PopupMessage variant="success" title="Feedback submitted" message="Thank you for sharing your feedback. Your response was submitted successfully." actionLabel="Done" onAction={() => setSubmitted(false)} onClose={() => setSubmitted(false)}/>}
    <div className="page-heading"><div><div className="eyebrow">WORKSPACE / FEEDBACK</div><h1>Share your feedback</h1><p>Tell us about your experience. Required questions are marked with an asterisk.</p></div></div>
    <section className="panel feedback-panel">
      <div className="feedback-intro"><span className="feedback-icon"><MessageSquareText size={21}/></span><div><h2>Your feedback matters</h2><p>Your response is sent securely to the SIEM service and linked to your signed-in account.</p></div></div>
      {error && <div className="notice error" role="alert">{error}</div>}
      <form ref={formRef} className="feedback-form" onSubmit={submit}>
        <h3 className="feedback-section-title">Your details <span>Optional</span></h3>
        <div className="feedback-identity-grid">
          <label className="feedback-label" htmlFor="feedback-name">Name / username<input id="feedback-name" className="form-input" value={name} onChange={event => setName(event.target.value)} maxLength={120}/></label>
          <label className="feedback-label" htmlFor="feedback-email">Email address<input id="feedback-email" className="form-input" type="email" value={email} onChange={event => setEmail(event.target.value)} maxLength={320}/></label>
        </div>

        <h3 className="feedback-section-title">Rating <span>Required</span></h3>
        <fieldset className="feedback-fieldset"><legend className="feedback-label">Overall satisfaction *</legend>
          <div className="feedback-rating" role="group" aria-label="Rate your experience from 1 to 5">
            {[1, 2, 3, 4, 5].map(value => <button key={value} type="button" className={value <= rating ? 'selected' : ''} onClick={() => setRating(value)} aria-label={`${value} ${value === 1 ? 'star' : 'stars'}`} aria-pressed={rating === value}><Star size={23} fill={value <= rating ? 'currentColor' : 'none'}/></button>)}
            <span>{rating ? 'Rating selected' : 'Choose a star rating'}</span>
          </div>
        </fieldset>
        <h3 className="feedback-section-title">Tell us more</h3>
        <label className="feedback-label" htmlFor="feedback-category">Feedback category *</label>
        <select id="feedback-category" className="select-control feedback-select" value={category} onChange={event => setCategory(event.target.value)} required>{categories.map(item => <option key={item}>{item}</option>)}</select>
        <label className="feedback-label" htmlFor="feedback-visit-reason">What was the main reason for your visit? *</label>
        <textarea id="feedback-visit-reason" className="feedback-textarea" value={visitReason} onChange={event => setVisitReason(event.target.value)} maxLength={1200} rows={2} required/>
        <label className="feedback-label" htmlFor="feedback-found">Did you find what you were looking for? *</label>
        <select id="feedback-found" className="select-control feedback-select" value={foundWhatNeeded} onChange={event => setFoundWhatNeeded(event.target.value)} required><option value="">Choose an answer</option><option value="yes">Yes</option><option value="partially">Partially</option><option value="no">No</option></select>
        <label className="feedback-label" htmlFor="feedback-comments">What did you like or dislike about your experience? *</label>
        <textarea id="feedback-comments" className="feedback-textarea" value={comments} onChange={event => setComments(event.target.value)} placeholder="Share details, including steps to reproduce a bug if relevant…" rows={5} maxLength={4000} required/>
        <div className="feedback-form-footer"><span>{comments.length}/4000</span></div>

        <h3 className="feedback-section-title">Attachment <span>Optional</span></h3>
        <p className="feedback-attachment-hint">You can submit feedback without adding a file. Attach a screenshot or video only if it helps explain your feedback.</p>
        <label className={`feedback-upload-zone${attachment ? ' has-file' : ''}`} htmlFor="feedback-attachment">
          <input id="feedback-attachment" className="feedback-file-input" type="file" accept="image/*,video/*" onChange={event => setAttachment(event.target.files?.[0] || null)}/>
          <span className="feedback-upload-icon"><UploadCloud size={21}/></span>
          <span className="feedback-upload-copy"><strong>{attachment ? 'Attachment ready' : 'Add a screenshot or video'}</strong><small>Image or video · Up to 10 MB</small></span>
          <span className="feedback-browse-button">{attachment ? 'Replace file' : 'Choose file'}</span>
        </label>
        {attachment && <div className="feedback-file-selected">{attachment.name} · {(attachment.size / 1024 / 1024).toFixed(2)} MB <button type="button" onClick={() => { setAttachment(null); document.getElementById('feedback-attachment').value = '' }}>Remove</button></div>}

        <details className="feedback-privacy"><summary>Privacy details</summary><p>Your feedback and any attachment you choose to add are sent to the SIEM service so authorized service operators can review the report. Name and email are optional.</p></details>
        <label className="feedback-consent"><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} required/><span className="feedback-consent-copy"><strong>Privacy and data use <i>Required</i></strong><small>I agree to the collection and use of this feedback and, if provided, its attachment as described in the privacy details. *</small></span></label>
        <div className="feedback-form-footer"><span>Feedback is associated with your signed-in account.</span><button className="primary-button" type="submit" disabled={busy || !consent}>{busy ? 'Submitting…' : 'Submit feedback'} <Send size={15}/></button></div>
      </form>
    </section>
  </div>
}
