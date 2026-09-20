import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  getCRLBindings: vi.fn(),
  getTargets: vi.fn(),
  createCRLBinding: vi.fn(),
  t: vi.fn(key => key),
  showSuccess: vi.fn(),
  showError: vi.fn(),
  showConfirm: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: mocks.t }),
}))

vi.mock('../../contexts', () => ({
  useNotification: () => ({
    showSuccess: mocks.showSuccess,
    showError: mocks.showError,
    showConfirm: mocks.showConfirm,
  }),
}))

vi.mock('../../hooks', () => ({
  usePermission: () => ({ hasPermission: () => true }),
}))

vi.mock('../../services', () => ({ deployService: mocks }))

vi.mock('../index', () => ({
  Badge: ({ children }) => <span>{children}</span>,
  Button: ({ children, loading: _loading, ...props }) => <button {...props}>{children}</button>,
  CompactSection: ({ children }) => <section>{children}</section>,
}))

vi.mock('../Modal', () => ({
  Modal: ({ open, children }) => open ? <div role="dialog">{children}</div> : null,
}))

import { CRLDeploySection } from '../CRLDeploySection'

describe('CRLDeploySection format options', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.getCRLBindings.mockResolvedValue({ data: [] })
    mocks.getTargets.mockResolvedValue({
      data: [{ id: 7, name: 'web01', host: '192.0.2.10', enabled: true }],
    })
    mocks.createCRLBinding.mockResolvedValue({ data: { id: 1 } })
  })

  it('hides parent CRLs for DER and submits include_parent_crls=false', async () => {
    render(<CRLDeploySection ca={{ id: 42, descr: 'Client CA' }} hasCRL />)
    fireEvent.click(await screen.findByText('crlDeploy.attach'))
    await screen.findByRole('dialog')

    const path = screen.getByPlaceholderText('/root/certs/CRL.crl')
    expect(path).toHaveValue('')
    expect(path).toBeRequired()

    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[0], { target: { value: '7' } })
    expect(screen.getByText('crlDeploy.includeParents')).toBeInTheDocument()

    fireEvent.change(selects[1], { target: { value: 'der' } })
    expect(screen.queryByText('crlDeploy.includeParents')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()

    fireEvent.submit(document.querySelector('form'))
    await waitFor(() => expect(mocks.createCRLBinding).toHaveBeenCalledWith(
      expect.objectContaining({ format: 'der', include_parent_crls: false })))
  })
})
