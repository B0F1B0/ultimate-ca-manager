/**
 * A swallowed load leaves a trace.
 *
 * Twenty catch blocks returned nothing and said nothing, so a settings panel
 * that failed to load looked exactly like one with nothing to show.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { reportSilentFailure } from '../silentFailure'

afterEach(() => vi.restoreAllMocks())

describe('reportSilentFailure', () => {
  it('names the load and what it answered', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    reportSilentFailure('loadBackups', new Error('Network unreachable'))
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0][0]).toContain('loadBackups')
    expect(warn.mock.calls[0][1]).toBe('Network unreachable')
  })

  it('survives an error with no message', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    reportSilentFailure('loadCAs', undefined)
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('reads a status when that is all there is', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    reportSilentFailure('loadDbStats', { status: 503 })
    expect(warn.mock.calls[0][1]).toBe(503)
  })
})
