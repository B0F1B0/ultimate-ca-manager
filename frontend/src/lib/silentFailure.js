/**
 * A load that failed and has nothing to show for it.
 *
 * Twenty catch blocks swallow a request whole: the panel stays empty and the
 * console says nothing, so the only way to find out is to open the network
 * tab. A toast is the wrong answer here, because opening the settings page
 * fires fourteen of these loads at once and a wall of toasts would be worse
 * than the silence. This keeps the screen as it is and leaves a trace.
 */
export function reportSilentFailure(where, error) {
  const detail = error && (error.message || error.status || error)
  // eslint-disable-next-line no-console
  console.warn(`[ucm] ${where} failed and was ignored:`, detail)
}
