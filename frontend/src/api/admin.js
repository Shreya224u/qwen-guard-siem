import { apiRequest } from './client'

export const adminApi = {
  users: token => apiRequest('/admin/users', { token }),
  activity: (limit = 100, token) => apiRequest(`/admin/activity?limit=${limit}`, { token }),
  updateRole: (id, role, token) => apiRequest(`/admin/users/${id}/role`, { token, method: 'PATCH', body: JSON.stringify({ role }) }),
}
