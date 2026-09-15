/**
 * Server notices reach the operator.
 *
 * A validity shortened by a policy comes back in `meta.notices` on a 201.
 * Dropping it on the floor is how the shortening became invisible in the
 * first place, so the reading is pinned here.
 */
import { describe, it, expect, vi } from 'vitest'
import { noticesOf, showNotices } from '../notices'

describe('noticesOf', () => {
  it('reads the notices a response carries', () => {
    expect(noticesOf({ meta: { notices: ['a', 'b'] } })).toEqual(['a', 'b'])
  })

  it('is empty when there are none, whatever the shape', () => {
    expect(noticesOf({ meta: {} })).toEqual([])
    expect(noticesOf({})).toEqual([])
    expect(noticesOf(null)).toEqual([])
    expect(noticesOf(undefined)).toEqual([])
    expect(noticesOf({ meta: { notices: 'not a list' } })).toEqual([])
  })

  it('drops blanks rather than showing an empty warning', () => {
    expect(noticesOf({ meta: { notices: ['kept', '', null, undefined] } }))
      .toEqual(['kept'])
  })
})

describe('showNotices', () => {
  it('warns once per notice and reports how many', () => {
    const showWarning = vi.fn()
    const shown = showNotices(
      { meta: { notices: ['Issued for 30 day(s) instead of the 365 requested.'] } },
      showWarning,
    )
    expect(shown).toBe(1)
    expect(showWarning).toHaveBeenCalledTimes(1)
    expect(showWarning).toHaveBeenCalledWith(
      'Issued for 30 day(s) instead of the 365 requested.',
    )
  })

  it('stays quiet when the request was honoured as asked', () => {
    const showWarning = vi.fn()
    expect(showNotices({ data: { id: 1 } }, showWarning)).toBe(0)
    expect(showWarning).not.toHaveBeenCalled()
  })
})
