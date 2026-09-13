/**
 * PKCS#12 compatibility mode (issue #331).
 *
 * The export modal offers a 3DES/SHA-1 profile for importers that reject the
 * AES-256/SHA-256 default as a wrong password (Android 15 and earlier, macOS 14
 * and earlier, old Windows and Java). The checkbox exists only for PKCS#12,
 * is off by default, and reaches onExport as `legacy`.
 */
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ExportModal } from '../ExportModal'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key, fallback) => fallback || key }),
  initReactI18next: { type: '3rdParty', init: () => {} },
  Trans: ({ children }) => children,
}))

const renderModal = (onExport = vi.fn()) => {
  render(
    <ExportModal
      open
      onClose={() => {}}
      entityType="certificate"
      entityName="web.example.com"
      hasPrivateKey
      canExportKey
      onExport={onExport}
    />
  )
  return onExport
}

describe('ExportModal PKCS#12 compatibility mode', () => {
  it('returns the explicit Root CA choice', async () => {
    const onExport = renderModal(vi.fn().mockResolvedValue(undefined))
    fireEvent.click(screen.getByText('Include Root CA'))
    fireEvent.submit(screen.getByText('Include Root CA').closest('form'))
    await waitFor(() => expect(onExport).toHaveBeenCalledTimes(1))
    expect(onExport.mock.calls[0][1].includeRoot).toBe(true)
  })

  it('hides the checkbox for PEM and shows it for PKCS#12', () => {
    renderModal()
    expect(screen.queryByTestId('export-legacy-pkcs12')).toBeNull()
    fireEvent.click(screen.getByText('P12 / PKCS#12'))
    expect(screen.getByTestId('export-legacy-pkcs12')).not.toBeChecked()
  })

  it('sends legacy: true only when ticked', async () => {
    const onExport = renderModal(vi.fn().mockResolvedValue(undefined))
    fireEvent.click(screen.getByText('P12 / PKCS#12'))
    fireEvent.change(screen.getByPlaceholderText('Min. 8 characters'), { target: { value: 'compat-password-123' } })
    fireEvent.click(screen.getByTestId('export-legacy-pkcs12'))
    fireEvent.submit(screen.getByTestId('export-legacy-pkcs12').closest('form'))
    await waitFor(() => expect(onExport).toHaveBeenCalledTimes(1))
    const [format, options] = onExport.mock.calls[0]
    expect(format).toBe('pkcs12')
    expect(options.legacy).toBe(true)
    expect(options.password).toBe('compat-password-123')
  })

  it('defaults to the modern profile', async () => {
    const onExport = renderModal(vi.fn().mockResolvedValue(undefined))
    fireEvent.click(screen.getByText('P12 / PKCS#12'))
    fireEvent.change(screen.getByPlaceholderText('Min. 8 characters'), { target: { value: 'compat-password-123' } })
    fireEvent.submit(screen.getByTestId('export-legacy-pkcs12').closest('form'))
    await waitFor(() => expect(onExport).toHaveBeenCalledTimes(1))
    expect(onExport.mock.calls[0][1].legacy).toBe(false)
  })
})
