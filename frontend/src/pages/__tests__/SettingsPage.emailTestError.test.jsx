/**
 * DUP-FE-003 — the "test email" failure banner must never render a boolean.
 *
 * `utils/response.py` puts `'error': True` (a boolean) in every error body, so
 * `error?.data?.message || error?.data?.error || ...` yields `true` whenever
 * `message` is missing. React renders a boolean as nothing, i.e. a blank red
 * banner with no reason in it. `apiClient.buildErrorMessage` already guards
 * this with `typeof data.error === 'string'`; this pins the same guard here.
 *
 * EmailSection is stubbed so the test drives `handleTestEmail` directly instead
 * of hunting for a button inside a 1700-line settings page.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

vi.mock('../settings/EmailSection', () => ({
  default: ({ updateSetting, emailTestResult, handleTestEmail }) => (
    <div>
      <button onClick={() => updateSetting('_testRecipient', 'ops@example.com')}>set-recipient</button>
      <button onClick={handleTestEmail}>run-test-email</button>
      {/* Rendered raw, exactly like EmailSection does — a boolean shows as ''. */}
      <div data-testid="email-test-message">{emailTestResult?.message}</div>
    </div>
  ),
}))

import './pageRenderingSetup.jsx'

import SettingsPage from '../SettingsPage'
import { settingsService } from '../../services/settings.service'

function renderSettings() {
  return render(
    <MemoryRouter initialEntries={['/settings?tab=email']}>
      <SettingsPage />
    </MemoryRouter>,
  )
}

async function runTestEmail() {
  await act(async () => { screen.getByText('set-recipient').click() })
  await act(async () => { screen.getByText('run-test-email').click() })
}

function apiError(data) {
  // Shape produced by apiClient: message = buildErrorMessage(status, data).
  const err = new Error('Request failed with status 500')
  err.status = 500
  err.data = data
  return err
}

describe('DUP-FE-003 — SettingsPage email test failure banner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('never surfaces the boolean `error` flag when the body has no message', async () => {
    // A UCM problem document whose `message` was lost (proxy, 502 page,
    // truncated body...): only `error: true` and `detail` survive.
    settingsService.testEmail = vi.fn().mockRejectedValue(
      apiError({ error: true, status: 500, type: 'about:blank' }),
    )

    renderSettings()
    await runTestEmail()

    await waitFor(() => {
      expect(screen.getByTestId('email-test-message').textContent).not.toBe('')
    })
    const shown = screen.getByTestId('email-test-message').textContent
    expect(shown).toBe('Request failed with status 500')
    expect(shown).not.toBe('true')
  })

  it('still prefers data.message when the backend sends one', async () => {
    settingsService.testEmail = vi.fn().mockRejectedValue(
      apiError({ error: true, message: 'SMTP connection refused', detail: 'SMTP connection refused' }),
    )

    renderSettings()
    await runTestEmail()

    await waitFor(() => {
      expect(screen.getByTestId('email-test-message').textContent).toBe('SMTP connection refused')
    })
  })

  it('still uses data.error when it really is a string (legacy bodies)', async () => {
    settingsService.testEmail = vi.fn().mockRejectedValue(
      apiError({ error: 'Mailbox unavailable' }),
    )

    renderSettings()
    await runTestEmail()

    await waitFor(() => {
      expect(screen.getByTestId('email-test-message').textContent).toBe('Mailbox unavailable')
    })
  })
})
