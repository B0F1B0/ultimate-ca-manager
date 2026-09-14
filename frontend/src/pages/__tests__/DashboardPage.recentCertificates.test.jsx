/**
 * DashboardPage — the "recent certificates" panel (DUP-FE-014c / DUP-FE-013b).
 *
 * The panel asked for `{ limit: 5, sort: 'created_at', order: 'desc' }`.
 * /api/v2/certificates reads page / per_page / sort_by / sort_order, so all
 * three were ignored and the panel showed page 1 of 20 sorted by subject
 * ascending, i.e. not the newest certificates at all.
 *
 * The same endpoint answers `data` as a bare array, so `data.certificates`
 * was a branch that could never be taken.
 *
 * And an expired certificate was badged `warning` here while every other
 * certificate surface badges it `danger`.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import './pageRenderingSetup.jsx'
import { dashboardService } from '../../services/dashboard.service'
import { certificatesService } from '../../services/certificates.service'

import DashboardPage from '../DashboardPage'

const PAST = new Date(Date.now() - 10 * 864e5).toISOString()
const FUTURE = new Date(Date.now() + 200 * 864e5).toISOString()

const renderDashboard = () => render(<MemoryRouter><DashboardPage /></MemoryRouter>)

describe('DashboardPage — recent certificates', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.localStorage.clear()
    dashboardService.getStats = vi.fn().mockResolvedValue({ data: {} })
    dashboardService.getRecentCAs = vi.fn().mockResolvedValue({ data: [] })
    dashboardService.getActivityLog = vi.fn().mockResolvedValue({ data: [] })
    dashboardService.getCertificateTrend = vi.fn().mockResolvedValue({ data: [] })
    dashboardService.getSystemStatus = vi.fn().mockResolvedValue({ data: {} })
    dashboardService.getNextExpirations = vi.fn().mockResolvedValue({ data: [] })
    certificatesService.getAll = vi.fn().mockResolvedValue({ data: [] })
  })

  it('asks for the five newest with the parameters the endpoint reads', async () => {
    renderDashboard()
    await waitFor(() => expect(certificatesService.getAll).toHaveBeenCalled())
    const params = certificatesService.getAll.mock.calls[0][0] || {}
    expect(params.per_page).toBe(5)
    expect(params.sort_by).toBe('created_at')
    expect(params.sort_order).toBe('desc')
    expect('limit' in params).toBe(false)
    expect('sort' in params).toBe(false)
    expect('order' in params).toBe(false)
  })

  it('reads the certificates from the bare `data` array the backend sends', async () => {
    certificatesService.getAll.mockResolvedValue({
      data: [{ id: 7, common_name: 'fresh.example.org', valid_to: FUTURE, created_at: FUTURE }],
    })
    renderDashboard()
    expect((await screen.findAllByText('fresh.example.org')).length).toBeGreaterThan(0)
  })

  it('does not read a `data.certificates` envelope the backend never sends', async () => {
    certificatesService.getAll.mockResolvedValue({
      data: { certificates: [{ id: 8, common_name: 'phantom.example.org', valid_to: FUTURE }] },
    })
    renderDashboard()
    expect((await screen.findAllByText('dashboard.noCertificatesYet')).length).toBeGreaterThan(0)
    expect(screen.queryByText('phantom.example.org')).toBeNull()
  })

  it('badges an expired certificate as danger, like every other certificate list', async () => {
    certificatesService.getAll.mockResolvedValue({
      data: [{ id: 9, common_name: 'old.example.org', valid_to: PAST, revoked: false }],
    })
    renderDashboard()
    const badges = await screen.findAllByText('common.expired')
    expect(badges.length).toBeGreaterThan(0)
    badges.forEach((b) => {
      expect(b.className).toMatch(/status-danger-bg/)
      expect(b.className).not.toMatch(/status-warning-bg/)
    })
  })

  it('still badges a valid certificate success and a revoked one danger', async () => {
    certificatesService.getAll.mockResolvedValue({
      data: [
        { id: 10, common_name: 'good.example.org', valid_to: FUTURE, revoked: false },
        { id: 11, common_name: 'gone.example.org', valid_to: FUTURE, revoked: true },
      ],
    })
    renderDashboard()
    const valid = await screen.findAllByText('common.valid')
    const revoked = await screen.findAllByText('common.revoked')
    expect(valid.some((b) => /status-success-bg/.test(b.className))).toBe(true)
    expect(revoked.some((b) => /status-danger-bg/.test(b.className))).toBe(true)
  })
})
