/**
 * Server notices: what was done on other terms than the ones asked for.
 *
 * A notice is not an error. The request succeeded, and something about it was
 * decided for the caller: a validity shortened by a policy or by the issuing
 * CA's own expiry. The server puts these in `meta.notices`; without showing
 * them, the only trace is a date nobody reads until it matters.
 */

/** The notices carried by a response, or an empty array. */
export function noticesOf(response) {
  const list = response?.meta?.notices
  return Array.isArray(list) ? list.filter(Boolean) : []
}

/**
 * Show each notice as a warning.
 *
 * Returns how many were shown, so a caller can keep its success toast quiet
 * when the server had something to say instead.
 */
export function showNotices(response, showWarning) {
  const list = noticesOf(response)
  list.forEach((notice) => showWarning(notice))
  return list.length
}
