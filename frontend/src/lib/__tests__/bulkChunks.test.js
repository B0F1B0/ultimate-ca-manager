/**
 * A selection larger than the server's cap is sent in batches.
 *
 * The bulk routes refuse more than 100 ids. The screens let an operator
 * select far more than that, and the whole operation answered 400 with
 * nothing done.
 */
import { describe, expect, it, vi } from 'vitest'
import { chunkIds, MAX_BULK_IDS, runInBatches } from '../bulkChunks'

const ids = (count) => Array.from({ length: count }, (_, i) => i + 1)

describe('chunkIds', () => {
  it('leaves a selection at the cap in one piece', () => {
    expect(chunkIds(ids(MAX_BULK_IDS)).length).toBe(1)
  })

  it('splits what the server would refuse', () => {
    const batches = chunkIds(ids(250))
    expect(batches.map(b => b.length)).toEqual([100, 100, 50])
    expect(batches.flat()).toEqual(ids(250))
  })

  it('answers an empty list rather than throwing', () => {
    expect(chunkIds([])).toEqual([])
    expect(chunkIds(undefined)).toEqual([])
  })
})

describe('runInBatches', () => {
  it('sends one request when the selection fits', async () => {
    const send = vi.fn().mockResolvedValue({ data: { success: [1], failed: [] } })
    await runInBatches(ids(100), send)
    expect(send).toHaveBeenCalledTimes(1)
    expect(send.mock.calls[0][0].length).toBe(100)
  })

  it('merges what each batch answered', async () => {
    const send = vi.fn(batch => Promise.resolve({
      data: { success: batch.slice(0, 2), failed: batch.slice(2, 3) },
    }))
    const answer = await runInBatches(ids(250), send)
    expect(send).toHaveBeenCalledTimes(3)
    expect(answer.data.success.length).toBe(6)
    expect(answer.data.failed.length).toBe(3)
  })

  it('passes the single-batch answer through untouched', async () => {
    const original = { data: { success: [], failed: [] }, message: 'done' }
    const send = vi.fn().mockResolvedValue(original)
    expect(await runInBatches([1, 2], send)).toBe(original)
  })
})
