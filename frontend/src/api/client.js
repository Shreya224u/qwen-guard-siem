const API_ROOT = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '')

export class ApiError extends Error {
  constructor(message, { status = null, code = 'API_ERROR', details = null, requestId = null, cause } = {}) {
    super(message, { cause })
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
  }
}

const errorMessageFrom = (payload, status) => {
  const detail = payload?.detail ?? payload?.message
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail.map(item => {
      const field = Array.isArray(item.loc) ? item.loc.slice(1).join('.') : ''
      return `${field ? `${field}: ` : ''}${item.msg || String(item)}`
    }).join('; ')
  }
  return `Request failed (${status})`
}

export const apiUrl = path => `${API_ROOT}${path}`

export async function apiRequest(path, { token = localStorage.getItem('siem-token'), ...options } = {}) {
  const headers = new Headers(options.headers || {})
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (options.body && !(options.body instanceof FormData) && !(options.body instanceof URLSearchParams) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  let response
  try {
    response = await fetch(apiUrl(path), { ...options, headers })
  } catch (cause) {
    if (cause?.name === 'AbortError') throw cause
    throw new ApiError('Cannot reach the SIEM API. Check that the backend is running and try again.', {
      code: 'NETWORK_ERROR',
      cause,
    })
  }

  if (!response.ok) {
    let payload = null
    try { payload = await response.json() } catch { /* use the HTTP status fallback */ }
    throw new ApiError(errorMessageFrom(payload, response.status), {
      status: response.status,
      code: payload?.code || `HTTP_${response.status}`,
      details: payload?.errors || null,
      requestId: payload?.request_id || response.headers.get('X-Request-ID'),
    })
  }
  if (response.status === 204) return null
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) {
    throw new ApiError('The API returned an unexpected response format.', {
      status: response.status,
      code: 'INVALID_RESPONSE',
    })
  }
  return response.json()
}
