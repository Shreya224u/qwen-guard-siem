import { apiRequest } from './client'

export const alertsApi = {
  list: ({ skip = 0, limit = 100, sourceFile, token } = {}) => {
    const query = new URLSearchParams({ skip: String(skip), limit: String(limit) })
    if (sourceFile) query.set('source_file', sourceFile)
    return apiRequest(`/alerts?${query}`, { token })
  },
  setStatus: (id, action, token) => apiRequest(`/alerts/${id}/action`, {
    token,
    method: 'PUT',
    body: JSON.stringify({ action }),
  }),
}
