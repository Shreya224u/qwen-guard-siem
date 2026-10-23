import { apiRequest } from './client'

export const mitreApi = {
  techniques: token => apiRequest('/mitre/techniques', { token }),
}
