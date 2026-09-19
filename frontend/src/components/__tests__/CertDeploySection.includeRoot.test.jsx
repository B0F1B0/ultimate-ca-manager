import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  getBindings: vi.fn(),
  getTargets: vi.fn(),
  createBinding: vi.fn(),
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
  Modal: ({ open, children }) => open ? <div role="dialog">{children}</div> : null,
}))

import { CertDeploySection } from '../deploy/CertDeploySection'

const certificate = { id: 42, has_private_key: true }

async function openForm() {
  render(<CertDeploySection certificate={certificate} />)
  fireEvent.click(await screen.findByText('deploy.attachTarget'))
  await screen.findByRole('dialog')
  fireEvent.change(screen.getByRole('combobox'), { target: { value: '7' } })
  fireEvent.change(screen.getByPlaceholderText('/etc/ssl/certs/app-fullchain.pem'), {
    target: { value: '/etc/ssl/certs/app-fullchain.pem' },
  })
}

describe('CertDeploySection root CA option', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getBindings.mockResolvedValue({ data: [] })
    mocks.getTargets.mockResolvedValue({
      data: [{ id: 7, name: 'web01', host: '192.0.2.10', username: 'deploy', enabled: true }],
    })
    mocks.createBinding.mockResolvedValue({ data: { id: 1 } })
  })

  it('shows the option only for a fullchain and submits the safe default', async () => {
    render(<CertDeploySection certificate={certificate} />)
    fireEvent.click(await screen.findByText('deploy.attachTarget'))
    await screen.findByRole('dialog')
    expect(screen.queryByText('export.includeRoot')).not.toBeInTheDocument()

    fireEvent.change(screen.getByRole('combobox'), { target: { value: '7' } })
    fireEvent.change(screen.getByPlaceholderText('/etc/ssl/certs/app-fullchain.pem'), {
      target: { value: '/etc/ssl/certs/app-fullchain.pem' },
    })
    expect(screen.getByText('export.includeRoot')).toBeInTheDocument()

    fireEvent.submit(document.querySelector('form'))
    await waitFor(() => expect(mocks.createBinding).toHaveBeenCalledWith(
      expect.objectContaining({ include_root: false })))
  })

  it('submits include_root=true when explicitly selected', async () => {
    await openForm()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.submit(document.querySelector('form'))

    await waitFor(() => expect(mocks.createBinding).toHaveBeenCalledWith({
      certificate_id: 42,
      target_id: 7,
      cert_path: undefined,
      key_path: undefined,
      fullchain_path: '/etc/ssl/certs/app-fullchain.pem',
      include_root: true,
    }))
  })
})
