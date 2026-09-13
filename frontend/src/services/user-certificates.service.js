import { apiClient, buildQueryString } from './apiClient'

const BASE = '/user-certificates'

export const userCertificatesService = {
  getAll: (params = {}) => apiClient.get(`${BASE}${buildQueryString(params)}`),
  getStats: () => apiClient.get(`${BASE}/stats`),
  getById: (id) => apiClient.get(`${BASE}/${id}`),
  export: (id, format = 'pem', { password, includeKey = true, includeChain = true, includeRoot = false, legacy = false } = {}) => {
    return apiClient.post(`${BASE}/${id}/export`, {
      format,
      include_key: includeKey,
      include_chain: includeChain,
      include_root: includeRoot,
      password,
      legacy,
    }, { responseType: 'blob' })
  },
  revoke: (id, reason = 'unspecified') => apiClient.post(`${BASE}/${id}/revoke`, { reason }),
  delete: (id) => apiClient.delete(`${BASE}/${id}`),
}
