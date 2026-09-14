/**
 * How strong a password is — asked of the server that decides.
 *
 * Two scorers existed. The server's (`security/password_policy
 * .get_password_strength`, 0-100 with weak/fair/good/strong buckets) knows
 * about a blacklist, repeated characters, sequential runs and how many
 * distinct characters were used. The browser's counted five properties and
 * had none of that, so it read higher than the server on most inputs that
 * matter:
 *
 *   Ab1!Ab1!      browser "strong"  server "fair"   (50)
 *   Tr0ub4dor&3   browser "strong"  server "good"   (70)
 *   aaaaaaaaaaaa  browser "fair"    server "weak"   (20)
 *
 * A meter exists to tell somebody how good their password is, so a meter
 * that overstates is the whole failure. `POST /api/v2/users/password-strength`
 * has been there all along and nothing called it.
 *
 * The local heuristic below survives as the answer for a browser that cannot
 * reach the server, and only there. It is deliberately the pessimistic half:
 * where it and the server disagree it reads high, so it is capped at "good"
 * rather than allowed to promise "strong" on nobody's authority.
 */
import { apiClient } from '../services/apiClient'

export const STRENGTH_LEVELS = ['weak', 'fair', 'good', 'strong']

/** Bars out of five for a 0-100 score, for the meter's five segments. */
export function barsForScore(score) {
  const value = Number(score) || 0
  if (value <= 0) return 0
  return Math.max(1, Math.min(5, Math.ceil(value / 20)))
}

/**
 * The offline answer. Same five properties the browser used to score with,
 * but never reported above "good": it cannot see the blacklist or the
 * repetition the server checks, so it has no grounds to say "strong".
 */
export function localPasswordStrength(password) {
  if (!password) return { score: 0, level: 'weak', offline: true }
  let points = 0
  if (password.length >= 8) points += 1
  if (password.length >= 12) points += 1
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) points += 1
  if (/\d/.test(password)) points += 1
  if (/[^a-zA-Z0-9]/.test(password)) points += 1
  const level = points >= 4 ? 'good' : points >= 3 ? 'fair' : 'weak'
  return { score: points * 20, level, offline: true }
}

/**
 * Ask the server. Resolves to `{score, level, feedback, offline}`; falls back
 * to the local answer when the request fails.
 */
export async function fetchPasswordStrength(password) {
  if (!password) return { score: 0, level: 'weak', feedback: [], offline: false }
  try {
    const resp = await apiClient.post('/users/password-strength', { password })
    const data = resp?.data || resp || {}
    const score = Number(data.score)
    if (Number.isFinite(score) && STRENGTH_LEVELS.includes(data.level)) {
      return {
        score,
        level: data.level,
        feedback: data.feedback || [],
        offline: false,
      }
    }
    return localPasswordStrength(password)
  } catch {
    return localPasswordStrength(password)
  }
}
