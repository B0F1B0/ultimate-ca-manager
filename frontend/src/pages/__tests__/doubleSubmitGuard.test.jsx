/**
 * Double-submit guard tests (#269)
 *
 * Creating a CA / issuing a certificate involves slow crypto on the backend;
 * an unguarded submit button lets a double-click create duplicates. The
 * submit handlers must ignore re-entrant submissions while one is in flight.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, fireEvent, waitFor } from '@testing-library/react'

vi.mock('../../services', () => ({
  templatesService: { getAll: vi.fn().mockResolvedValue({ data: [] }) },
  ekuService: { getKnown: vi.fn().mockResolvedValue({ data: [] }) },
}))

vi.mock('../../contexts', () => ({
  useNotification: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showWarning: vi.fn(),
  }),
}))

const t = (key, params) => key

async function renderIssueFormWithSlowSubmit() {
  const { IssueCertificateForm } = await import('../certificates/IssueCertificateForm')

  let releaseSubmit
  const gate = new Promise((resolve) => { releaseSubmit = resolve })
  const onSubmit = vi.fn(() => gate)

  const utils = render(
    <IssueCertificateForm
      cas={[{ id: 1, descr: 'Test CA', subject: 'CN=Test CA' }]}
      onSubmit={onSubmit}
      onCancel={() => {}}
      t={t}
    />
  )
  return { ...utils, onSubmit, releaseSubmit }
}

describe('IssueCertificateForm — double-submit guard (#269)', () => {
  // Rendering this form is slow enough that the default 5 s runs out when the
  // machine is busy, which made the whole suite look flaky.
  it('ignores a second submit while the first is in flight', async () => {
    const { container, onSubmit, releaseSubmit } = await renderIssueFormWithSlowSubmit()

    const form = container.querySelector('form')
    fireEvent.submit(form)
    fireEvent.submit(form)
    fireEvent.submit(form)

    expect(onSubmit).toHaveBeenCalledTimes(1)

    // Once the in-flight call settles, submitting works again
    releaseSubmit()
    const button = container.querySelector('button[type="submit"]')
    await waitFor(() => expect(button).not.toBeDisabled())
    fireEvent.submit(form)
    expect(onSubmit).toHaveBeenCalledTimes(2)
  }, 20000)

  it('submit button is disabled while issuing', async () => {
    const { container, releaseSubmit } = await renderIssueFormWithSlowSubmit()
    const form = container.querySelector('form')
    const button = container.querySelector('button[type="submit"]')
    expect(button).not.toBeDisabled()
    fireEvent.submit(form)
    await waitFor(() => expect(button).toBeDisabled())
    releaseSubmit()
    await waitFor(() => expect(button).not.toBeDisabled())
  })
})
