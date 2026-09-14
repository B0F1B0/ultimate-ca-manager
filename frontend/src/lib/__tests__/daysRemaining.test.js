/**
 * DUP-FE-012. The CA detail panel read `ca.days_remaining`, a field the CA
 * serializer never emits (backend/models/ca.py to_dict has valid_from/valid_to
 * but no days_remaining — only Certificate.to_dict has one). `undefined !== null`
 * is true, so the block rendered; every numeric comparison against undefined is
 * false, so it rendered with no colour band and a count of undefined.
 *
 * The helper below recomputes it from `valid_to`, rounding the way the server
 * does (`timedelta.days` is a floor) so the CA panel cannot disagree by a day
 * with the certificate panel next to it.
 */
import { describe, it, expect, vi, afterEach } from 'vitest'
import { daysRemaining } from '../utils'

const NOW = new Date('2026-06-01T12:00:00Z')

afterEach(() => vi.useRealTimers())

function at(iso) {
  vi.useFakeTimers()
  vi.setSystemTime(NOW)
  return daysRemaining(iso)
}

describe('daysRemaining', () => {
  it('floors, matching the server’s timedelta.days', () => {
    // 7 days and 12 hours away is still "7 days", never 8
    expect(at('2026-06-09T00:00:00Z')).toBe(7)
  })

  it('does not round a partial day up into the next band', () => {
    // 7.4 days: floor keeps it in the 7-day critical band, ceil would not
    expect(at('2026-06-08T21:36:00Z')).toBe(7)
  })

  it('counts a whole number of days exactly', () => {
    expect(at('2026-06-08T12:00:00Z')).toBe(7)
    expect(at('2026-06-01T12:00:00Z')).toBe(0)
  })

  it('goes negative for an already-expired date, so "expired N days ago" works', () => {
    expect(at('2026-05-30T12:00:00Z')).toBe(-2)
  })

  it('returns null rather than NaN for a missing date', () => {
    expect(daysRemaining(null)).toBeNull()
    expect(daysRemaining(undefined)).toBeNull()
    expect(daysRemaining('')).toBeNull()
  })

  it('returns null rather than NaN for an unparseable date', () => {
    expect(daysRemaining('not-a-date')).toBeNull()
  })

  it('never returns undefined, which is what broke the CA badge', () => {
    for (const input of [null, undefined, '', 'not-a-date', '2026-06-08T12:00:00Z']) {
      expect(daysRemaining(input)).not.toBeUndefined()
    }
  })
})
