/**
 * formatRelativeTime used to live in lib/ui.js next to a second copy of
 * formatDate, and for anything older than 7 days (or dated in the future) it
 * fell through to THAT copy. The two copies disagreed twice (DUP-FE-001):
 *
 *   - the `us` branch of the lib/ui copy hardcoded `day: 'numeric'`, so it
 *     produced 02/6/2026 where every table cell produced 02/06/2026;
 *   - its catch returned String(date), so a malformed backend timestamp was
 *     printed raw into the DOM instead of the '-' shown everywhere else.
 *
 * Both are observable on the dashboard and the audit log, which render a
 * formatRelativeTime value and a formatDate value side by side.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { formatDate, formatRelativeTime } from '../utils'
import { setDateFormat, setShowTime } from '../../stores/dateFormatStore'

const OLD = '2020-02-06T12:00:00Z' // far enough back to take the formatDate path

afterEach(() => {
  setDateFormat('short')
  setShowTime(true)
})

describe('formatRelativeTime — agrees with formatDate on the fallback path', () => {
  it.each(['short', 'iso', 'eu', 'us', 'long'])(
    'renders an old date exactly like formatDate under the %s preference',
    (fmt) => {
      setDateFormat(fmt)
      setShowTime(false)
      expect(formatRelativeTime(OLD)).toBe(formatDate(OLD))
    }
  )

  it('does not print a bare day number under the us preference', () => {
    setDateFormat('us')
    setShowTime(false)
    // 02/06/2020, never 02/6/2020
    expect(formatRelativeTime(OLD)).toMatch(/^\d{2}\/\d{2}\/\d{4}$/)
  })

  it('returns the placeholder for a malformed timestamp, not the raw string', () => {
    expect(formatRelativeTime('not-a-date')).toBe('-')
    expect(formatRelativeTime('not-a-date')).not.toContain('not-a-date')
  })

  it('still returns the placeholder for an empty value', () => {
    expect(formatRelativeTime(null)).toBe('-')
    expect(formatRelativeTime(undefined)).toBe('-')
    expect(formatRelativeTime('')).toBe('-')
  })

  it('still renders recent timestamps relatively', () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    expect(formatRelativeTime(twoHoursAgo)).toMatch(/^2h( \d+m)? ago$/)
    expect(formatRelativeTime(new Date().toISOString())).toBe('just now')
  })

  it('routes through the translator when one is supplied', () => {
    const t = (key) => `T:${key}`
    expect(formatRelativeTime(new Date().toISOString(), t)).toBe('T:common.justNow')
  })
})
