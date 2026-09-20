import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../../contexts', () => ({
  useNotification: () => ({
    showSuccess: vi.fn(),
    showError: vi.fn(),
    showConfirm: vi.fn(),
  }),
}))

vi.mock('../../../services', () => ({
  deployService: {
    getTargets: vi.fn().mockResolvedValue({ data: [] }),
  },
}))

vi.mock('../../../components', () => ({
  Button: ({ children, ...props }) => <button {...props}>{children}</button>,
  Badge: ({ children }) => <span>{children}</span>,
  HelpCard: ({ children }) => <div>{children}</div>,
  DetailSection: ({ children }) => <section>{children}</section>,
  DetailContent: ({ children }) => <div>{children}</div>,
  DetailHeader: ({ title }) => <header>{title}</header>,
  EmptyState: ({ action }) => <button onClick={action.onClick}>{action.label}</button>,
}))

vi.mock('../../../components/Modal', () => ({
  Modal: ({ open, children }) => open ? <div role="dialog">{children}</div> : null,
}))

import DeploySection from '../DeploySection'

describe('DeploySection same-host preset', () => {
  it('fills the local SFTP target fields', async () => {
    render(<DeploySection />)

    fireEvent.click(await screen.findByText('deploy.addTarget'))
    fireEvent.click(screen.getByText('deploy.sameHost'))

    expect(screen.getByDisplayValue('127.0.0.1')).toBeInTheDocument()
    expect(screen.getByDisplayValue('ucm-deploy')).toBeInTheDocument()
    expect(screen.queryByText('deploy.reloadCommand')).not.toBeInTheDocument()
    expect(screen.getByText('deploy.sameHostHint')).toBeInTheDocument()
  })
})
