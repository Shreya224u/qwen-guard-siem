import { apiRequest } from './client'

export const accountApi = {
  overview: token => apiRequest('/auth/account/overview', { token }),
  sessions: token => apiRequest('/auth/account/sessions', { token }),
  linkProvider: (provider, token) => apiRequest(`/auth/oauth/${provider}/link`, { token }),
  changePassword: (payload, token) => apiRequest('/auth/account/password', { token, method: 'POST', body: JSON.stringify(payload) }),
  sendEmailTwoFactor: token => apiRequest('/auth/account/email-2fa/send', { token, method: 'POST' }),
  confirmEmailTwoFactor: (payload, token) => apiRequest('/auth/account/email-2fa/confirm', { token, method: 'POST', body: JSON.stringify(payload) }),
  revokeSession: (id, token) => apiRequest(`/auth/account/sessions/${encodeURIComponent(id)}`, { token, method: 'DELETE' }),
  revokeOtherSessions: token => apiRequest('/auth/account/sessions/revoke-others', { token, method: 'POST' }),
  revokeAllSessions: token => apiRequest('/auth/account/sessions/revoke-all', { token, method: 'POST' }),
}
