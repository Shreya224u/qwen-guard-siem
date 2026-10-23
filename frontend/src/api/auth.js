import { apiRequest } from './client'

export const authApi = {
  me: token => apiRequest('/auth/me', { token }),
  login: credentials => apiRequest('/auth/login', { token: null, method: 'POST', body: credentials }),
  register: payload => apiRequest('/auth/register', { token: null, method: 'POST', body: JSON.stringify(payload) }),
  sendVerification: (channel, payload) => apiRequest(`/auth/verification/${channel}/send`, { token: null, method: 'POST', body: JSON.stringify(payload) }),
  verifyCode: (channel, payload) => apiRequest(`/auth/verification/${channel}/verify`, { token: null, method: 'POST', body: JSON.stringify(payload) }),
  verifyEmailChallenge: payload => apiRequest('/auth/login/email-2fa/verify', { token: null, method: 'POST', body: JSON.stringify(payload) }),
  phoneLogin: payload => apiRequest('/auth/phone/login', { token: null, method: 'POST', body: JSON.stringify(payload) }),
  requestPasswordReset: payload => apiRequest('/auth/password-reset/request', { token: null, method: 'POST', body: JSON.stringify(payload) }),
  confirmPasswordReset: payload => apiRequest('/auth/password-reset/confirm', { token: null, method: 'POST', body: JSON.stringify(payload) }),
  oauthProviders: () => apiRequest('/auth/oauth/providers', { token: null }),
}
