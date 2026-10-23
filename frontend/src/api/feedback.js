import { apiRequest } from './client'

export const feedbackApi = {
  submit: (formData, token) => apiRequest('/feedback', { token, method: 'POST', body: formData }),
}
