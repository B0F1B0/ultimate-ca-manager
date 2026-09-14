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
 * Run `send` over each batch and merge the bodies into one result.
 *
 * Every array the routes answer with is concatenated, not just `success` and
 * `failed`: bulk sign also answers `pending_approval`, and merging a fixed
 * pair dropped it, so a selection over the cap looked like zero approvals
 * raised while the server had created them.
 */
export async function runInBatches(ids, send) {
  const batches = chunkIds(ids)
  if (batches.length <= 1) return send(batches[0] || [])

  const merged = {}
  for (const batch of batches) {
    const answer = await send(batch)
    const body = answer?.data ?? answer ?? {}
    for (const [key, value] of Object.entries(body)) {
      if (Array.isArray(value)) {
        merged[key] = [...(merged[key] || []), ...value]
      } else if (!(key in merged)) {
        // A scalar the route reports once (a count, a message): the first
        // batch answers for the selection rather than the last.
        merged[key] = value
      }
    }
  }
  // Keep the shape the callers read even when no batch reported them.
  merged.success = merged.success || []
  merged.failed = merged.failed || []
  return { data: merged }
}
