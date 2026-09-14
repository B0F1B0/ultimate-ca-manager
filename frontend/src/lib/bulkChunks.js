/**
 * The server caps a bulk request at 100 ids (services/deletion_blockers).
 *
 * The screens let an operator select a whole page and more, so a selection
 * past the cap answered 400 with nothing done. Splitting it here keeps the
 * one-request-per-batch contract the routes were written for.
 */
export const MAX_BULK_IDS = 100

export function chunkIds(ids, size = MAX_BULK_IDS) {
  const list = Array.isArray(ids) ? ids : []
  const chunks = []
  for (let start = 0; start < list.length; start += size) {
    chunks.push(list.slice(start, start + size))
  }
  return chunks
}

/**
 * Run `send` over each batch and merge the `{success, failed}` bodies the
 * bulk routes answer with, so the caller sees one result for the selection.
 */
export async function runInBatches(ids, send) {
  const batches = chunkIds(ids)
  if (batches.length <= 1) return send(batches[0] || [])

  const merged = { success: [], failed: [] }
  for (const batch of batches) {
    const answer = await send(batch)
    const body = answer?.data ?? answer ?? {}
    merged.success.push(...(body.success || []))
    merged.failed.push(...(body.failed || []))
  }
  return { data: merged }
}
