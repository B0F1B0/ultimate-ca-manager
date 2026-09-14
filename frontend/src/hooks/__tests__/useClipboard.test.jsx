/**
 * useClipboard is the one copy path (DUP-FE-009), so its two silent gaps are
 * everyone's gaps.
 *
 * The non-secure-context fallback reports success by RETURNING false, never by
 * throwing: a browser that refuses the synthetic copy (no user gesture, a
 * locked-down policy) left the hook answering `true`, and every caller that
 * trusts that answer then tells the operator a challenge or a private key is
 * on the clipboard when it is not.
 *
 * And the "Copied!" reset timer was never cleared on unmount, so closing a
 * detail panel right after a copy left a setState scheduled on a gone tree.
 */
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { useClipboard } from '../useClipboard'

/** jsdom runs on http:// — pin the flag explicitly rather than assume it. */
function setSecureContext(value) {
  Object.defineProperty(window, 'isSecureContext', {
    value, configurable: true, writable: true,
  })
}

const originalExecCommand = document.execCommand

beforeEach(() => {
  setSecureContext(false)
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
  document.execCommand = originalExecCommand
})

describe('useClipboard fallback honesty', () => {
  it('answers false when execCommand refuses the copy', async () => {
    const execCommand = vi.fn(() => false)
    document.execCommand = execCommand

    const { result } = renderHook(() => useClipboard())
    let answered
    await act(async () => { answered = await result.current.copy('challenge', 'k') })

    expect(execCommand).toHaveBeenCalledWith('copy')
    expect(answered).toBe(false)
    // …and no "Copied!" badge for a copy that never happened.
    expect(result.current.isCopied('k')).toBe(false)
  })

  it('still answers true, and flags the key, when execCommand accepts', async () => {
    document.execCommand = vi.fn(() => true)

    const { result } = renderHook(() => useClipboard())
    let answered
    await act(async () => { answered = await result.current.copy('challenge', 'k') })

    expect(answered).toBe(true)
    expect(result.current.isCopied('k')).toBe(true)
  })

  it('leaves the textarea it borrowed out of the document either way', async () => {
    document.execCommand = vi.fn(() => false)

    const { result } = renderHook(() => useClipboard())
    await act(async () => { await result.current.copy('challenge') })

    expect(document.querySelectorAll('textarea')).toHaveLength(0)
  })
})

describe('useClipboard timer ownership', () => {
  it('cancels the pending reset when the component unmounts', async () => {
    vi.useFakeTimers()
    document.execCommand = vi.fn(() => true)

    // A distinctive delay so the hook's own timer is identifiable among the
    // ones React's scheduler also books.
    const RESET_MS = 1234
    const setSpy = vi.spyOn(globalThis, 'setTimeout')

    const { result, unmount } = renderHook(() => useClipboard(RESET_MS))
    await act(async () => { await result.current.copy('pem') })

    const index = setSpy.mock.calls.findIndex(([, delay]) => delay === RESET_MS)
    expect(index).toBeGreaterThanOrEqual(0)
    const timerId = setSpy.mock.results[index].value

    const clearSpy = vi.spyOn(globalThis, 'clearTimeout')
    unmount()
    expect(clearSpy.mock.calls.map(([id]) => id)).toContain(timerId)
  })
})
