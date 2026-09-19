/**
 * SystemLogsPage — the level floor and the search reach the server rather than
 * being applied in the browser, so a filter never hides lines that were simply
 * never fetched. A deployment with no log file yet says so instead of looking
 * like an empty log.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  getApplicationLog: vi.fn(),
  showError: vi.fn(),
  showSuccess: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key }),
}))

vi.mock('../../services', () => ({
  systemService: { getApplicationLog: mocks.getApplicationLog },
}))

vi.mock('../../contexts', () => ({
  useNotification: () => ({ showError: mocks.showError, showSuccess: mocks.showSuccess }),
}))

vi.mock('../../lib/utils', () => ({
  extractData: (r) => r?.data ?? r,
}))

vi.mock('../../components', () => ({
  Card: ({ children }) => <div>{children}</div>,
  Button: ({ children, loading: _loading, ...props }) => <button {...props}>{children}</button>,
  Input: ({ label, ...props }) => <input aria-label={label} {...props} />,
  Select: ({ label, options = [], value, onChange }) => (
    <select aria-label={label} value={value ?? ''} onChange={(e) => onChange?.(e.target.value)}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  ),
  LoadingSpinner: () => <div>loading</div>,
  CompactHeader: ({ title }) => <h1>{title}</h1>,
}))

import SystemLogsPage from '../SystemLogsPage'

const LINES = [
  { ts: '2026-09-19 13:41:36', logger: 'services.scep', level: 'WARNING', message: 'failInfo=1' },
  { ts: '2026-09-19 13:41:37', logger: 'api.v2', level: 'INFO', message: 'log read' },
]

function respondWith(data) {
  mocks.getApplicationLog.mockResolvedValue({ data })
}

const DEFAULT_DATA = {
  source: 'app', exists: true, lines: LINES, truncated: false,
  path: '/x/ucm.log', available_sources: ['app', 'access'],
}

async function renderPage(data = DEFAULT_DATA) {
  respondWith(data)
  render(<SystemLogsPage />)
  await waitFor(() => expect(mocks.getApplicationLog).toHaveBeenCalled())
}

describe('SystemLogsPage', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders the returned log lines', async () => {
    await renderPage()
    expect(await screen.findByText('failInfo=1')).toBeInTheDocument()
    expect(screen.getByText('[services.scep]')).toBeInTheDocument()
  })

  it('asks the server for the application log, INFO and 200 lines by default', async () => {
    await renderPage()
    expect(mocks.getApplicationLog).toHaveBeenCalledWith({
      source: 'app', level: 'INFO', lines: 200,
    })
  })

  it('offers only the sources this deployment reported', async () => {
    await renderPage()
    const options = [...screen.getByLabelText('logs.source').options].map((o) => o.value)
    expect(options).toEqual(['app', 'access'])
  })

  it('refetches when the source changes', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.source'), { target: { value: 'access' } })
    await waitFor(() =>
      expect(mocks.getApplicationLog).toHaveBeenLastCalledWith({
        source: 'access', level: 'INFO', lines: 200,
      }))
  })

  it('renders a line that carries no level', async () => {
    await renderPage({
      ...DEFAULT_DATA, source: 'access',
      lines: [{ ts: null, logger: null, level: null, message: 'GET /api 200' }],
    })
    expect(await screen.findByText('GET /api 200')).toBeInTheDocument()
  })

  it('refetches when the level floor changes', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.level'), { target: { value: 'ERROR' } })
    await waitFor(() =>
      expect(mocks.getApplicationLog).toHaveBeenLastCalledWith({ source: 'app', level: 'ERROR', lines: 200 }))
  })

  it('refetches when the line count changes', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.lines'), { target: { value: '1000' } })
    await waitFor(() =>
      expect(mocks.getApplicationLog).toHaveBeenLastCalledWith({ source: 'app', level: 'INFO', lines: 1000 }))
  })

  it('sends the search term to the server rather than filtering locally', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('common.search'), { target: { value: 'scep' } })
    fireEvent.click(screen.getByRole('button', { name: /common\.search/ }))
    await waitFor(() =>
      expect(mocks.getApplicationLog).toHaveBeenLastCalledWith({
        source: 'app', level: 'INFO', lines: 200, q: 'scep',
      }))
  })

  it('omits an empty search term from the request', async () => {
    await renderPage()
    expect(mocks.getApplicationLog).toHaveBeenCalledWith({
      source: 'app', level: 'INFO', lines: 200,
    })
  })

  it('says the log is unavailable rather than showing an empty log', async () => {
    await renderPage({ ...DEFAULT_DATA, exists: false, lines: [], path: null })
    expect(await screen.findByText('logs.unavailable')).toBeInTheDocument()
  })

  it('distinguishes no matches from no log file', async () => {
    await renderPage({ ...DEFAULT_DATA, lines: [] })
    expect(await screen.findByText('logs.empty')).toBeInTheDocument()
  })

  it('warns when older lines were left off', async () => {
    await renderPage({ ...DEFAULT_DATA, truncated: true })
    expect(await screen.findByText('logs.truncated')).toBeInTheDocument()
  })

  it('shows which file is being read', async () => {
    await renderPage()
    expect(await screen.findByText('/x/ucm.log')).toBeInTheDocument()
  })

  it('reports a failed read instead of rendering a blank page', async () => {
    mocks.getApplicationLog.mockRejectedValue(new Error('boom'))
    render(<SystemLogsPage />)
    await waitFor(() => expect(mocks.showError).toHaveBeenCalledWith('logs.unavailable'))
  })
})
