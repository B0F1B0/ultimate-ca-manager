/**
 * Managing template pins mirrors the backend scopes.
 *
 * POST/DELETE /api/v2/cas/<id>/templates/<id>/pin require write:cas AND
 * write:templates. The operator role holds only the first, so the button
 * opened a modal whose every toggle answered 403.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ permissions: ['*'], user: { id: 1, username: 'probe' } }),
}))

vi.mock('../../contexts/NotificationContext', () => ({
  useNotification: () => ({
    showSuccess: vi.fn(), showError: vi.fn(), showWarning: vi.fn(),
  }),
}))

vi.mock('../../services', () => ({
  casService: { getCrlInfo: vi.fn().mockResolvedValue({ data: {} }) },
  templatesService: { getForCA: vi.fn().mockResolvedValue({ data: [] }) },
}))

import { CADetailsPanel } from '../cas/CADetailsPanel'

const CA = {
  id: 1, refid: 'ca-probe', descr: 'Probe CA', type: 'root', is_root: true,
  has_private_key: true, pending: false, revoked: false,
}

function renderPanel(granted) {
  const canWrite = (resource) => granted.includes(resource)
  render(
    <CADetailsPanel
      ca={CA}
      canWrite={canWrite}
      canDelete={() => false}
      onExport={vi.fn()}
      onDelete={vi.fn()}
      onChanged={vi.fn()}
      t={(key) => key}
    />
  )
}

describe('CADetailsPanel — template pins need both scopes', () => {
  it('hides the button from a holder of write:cas alone', () => {
    renderPanel(['cas'])
    expect(screen.queryByText('templates.managePins')).not.toBeInTheDocument()
  })

  it('hides it from a holder of write:templates alone', () => {
    renderPanel(['templates'])
    expect(screen.queryByText('templates.managePins')).not.toBeInTheDocument()
  })

  it('offers it to a holder of both', () => {
    renderPanel(['cas', 'templates'])
    expect(screen.getByText('templates.managePins')).toBeInTheDocument()
  })
})
