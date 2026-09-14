/**
 * useClipboard - Centralized copy-to-clipboard hook
 *
 * The single copy path for the whole app: no surface calls the clipboard API
 * by hand any more. It matters because UCM is routinely served over plain
 * HTTP, where the async clipboard API does not exist at all — copying then
 * falls back to a hidden textarea, and `copy` answers false when even that is
 * refused, so callers can choose between their success and failure wording
 * instead of announcing a copy that never happened.
 *
 * `copy(text, key)` resolves to a boolean; `isCopied(key)` drives the
 * transient "Copied!" badge, whose reset timer the hook owns and cancels on
 * unmount.
 */
import { useState, useCallback, useRef, useEffect } from 'react'

export function useClipboard(timeout = 2000) {
  const [copiedKey, setCopiedKey] = useState(null)
  const timerRef = useRef(null)

  // The reset timer belongs to the component: closing a detail panel right
  // after a copy would otherwise fire setCopiedKey on a tree that is gone.
  useEffect(() => () => {
    if (timerRef.current) clearTimeout(timerRef.current)
  }, [])

  const copy = useCallback(async (text, key = '_default') => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(String(text))
      } else {
        // Fallback for non-secure contexts
        const textarea = document.createElement('textarea')
        textarea.value = String(text)
        textarea.style.position = 'fixed'
        textarea.style.opacity = '0'
        document.body.appendChild(textarea)
        textarea.select()
        // execCommand signals refusal by returning false, not by throwing:
        // ignoring it reported a copy that never reached the clipboard.
        const copiedByFallback = document.execCommand('copy')
        document.body.removeChild(textarea)
        if (!copiedByFallback) return false
      }
      setCopiedKey(key)
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setCopiedKey(null), timeout)
      return true
    } catch {
      return false
    }
  }, [timeout])

  const isCopied = useCallback((key = '_default') => {
    return copiedKey === key
  }, [copiedKey])

  return { copy, isCopied, copied: copiedKey !== null }
}
