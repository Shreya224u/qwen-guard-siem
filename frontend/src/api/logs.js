import { apiRequest } from './client'

export const logsApi = {
  list: ({ skip = 0, limit = 100, token } = {}) => apiRequest(`/logs?${new URLSearchParams({ skip: String(skip), limit: String(limit) })}`, { token }),
  activity: (range = '24h', sourceFile = '', token) => {
    const query = new URLSearchParams({ range })
    if (sourceFile) query.set('source_file', sourceFile)
    return apiRequest(`/logs/activity?${query}`, { token })
  },
  uploads: token => apiRequest('/logs/uploads', { token }),
  upload: (formData, token) => apiRequest('/logs/upload', { token, method: 'POST', body: formData }),
  deleteUpload: (filename, token) => apiRequest(`/logs/uploads?filename=${encodeURIComponent(filename)}`, { token, method: 'DELETE' }),
}
