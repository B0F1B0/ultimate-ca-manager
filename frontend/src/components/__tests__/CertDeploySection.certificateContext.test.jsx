import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  getBindings: vi.fn(),
  getTargets: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../contexts', () => ({
  useNotification: () => ({
    showSuccess: vi.fn(),
    showError: vi.fn(),
    showConfirm: vi.fn(),
  }),
}))

vi.mock('../../hooks', () => ({
  usePermission: () => ({ hasPermission: () => true }),
}))

vi.mock('../../services', () => ({ deployService: mocks }))

vi.mock('../Modal', () => ({
  Modal: ({ open, title, children }) => open
    ? <div role="dialog"><div data-testid="modal-title">{title}</div>{children}</div>
    : null,
}))

import { CertDeploySection } from '../deploy/CertDeploySection'

async function openAttachDialog(certificate) {
  render(<CertDeploySection certificate={certificate} />)
  fireEvent.click(await screen.findByText('deploy.attachTarget'))
  return screen.findByRole('dialog')
}

describe('CertDeploySection certificate context', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getBindings.mockResolvedValue({ data: [] })
    mocks.getTargets.mockResolvedValue({ data: [] })
  })

  it('identifies the certificate by common name in the attach dialog title', async () => {
    await openAttachDialog({
      id: 42,
      common_name: 'npm.lan',
      descr: 'NPM certificate',
      has_private_key: true,
    })

    expect(screen.getByTestId('modal-title')).toHaveTextContent(
      'deploy.attachTarget: npm.lan')
  })

  it('falls back to the certificate description when no common name is available', async () => {
    await openAttachDialog({
      id: 43,
      descr: 'Imported appliance certificate',
      has_private_key: false,
    })

    expect(screen.getByTestId('modal-title')).toHaveTextContent(
      'deploy.attachTarget: Imported appliance certificate')
  })
})
