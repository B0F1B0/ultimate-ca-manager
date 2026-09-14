/**
 * The length rule for an export password, asked of the server.
 *
 * Every dialog used to carry its own numbers. `ExportModal` refused under 8
 * and knew of no ceiling; `ExportActions` refused under 4; the converter page
 * asked only that the field not be empty. The routes behind them disagreed
 * in the other direction, so the same dialog was stricter than the server on
 * a certificate export and more permissive than it on a CA export, where a
 * 300-character password came back refused.
 *
 * `GET /api/v2/export/password-policy` publishes what the routes apply
 * (backend/utils/export_password.py). The constants below are the fallback
 * for a page rendered before the answer arrives -- they are what the server
 * currently says, not a second opinion.
 */
import { apiClient } from '../services/apiClient'

export const EXPORT_PASSWORD_MIN_LENGTH = 8
export const EXPORT_PASSWORD_MAX_LENGTH = 256

const FALLBACK = {
  min_length: EXPORT_PASSWORD_MIN_LENGTH,
  max_length: EXPORT_PASSWORD_MAX_LENGTH,
}

let _cached = null
let _inFlight = null

/** The rule the server applies, fetched once per session. */
export async function loadExportPasswordPolicy() {
  if (_cached) return _cached
  if (!_inFlight) {
    _inFlight = (async () => {
      try {
        const resp = await apiClient.get('/export/password-policy')
        const data = resp?.data || resp || {}
        const min = Number(data.min_length)
        const max = Number(data.max_length)
        if (Number.isFinite(min) && Number.isFinite(max) && min > 0 && max >= min) {
          _cached = { min_length: min, max_length: max }
          return _cached
        }
        return FALLBACK
      } catch {
        // The server decides; when it cannot be asked, refuse the same
        // things it would rather than letting everything through.
        return FALLBACK
      } finally {
        _inFlight = null
      }
    })()
  }
  return _inFlight
}

/** Synchronous view for a first render, before the policy has arrived. */
export function exportPasswordPolicy() {
  return _cached || FALLBACK
}

/** Whether this password may be submitted. */
export function isExportPasswordValid(password, policy = exportPasswordPolicy()) {
  const length = (password || '').length
  return length >= policy.min_length && length <= policy.max_length
}

/** Test seam: forget the cached answer. */
export function resetExportPasswordPolicy() {
  _cached = null
  _inFlight = null
}
