/**
 * SystemLogsPage — every filter reaches the server rather than being applied in
 * the browser, so a filter never hides lines that were simply never fetched.
 * The component list is offered from everything read, not from what survived
 * the filters, so narrowing to one subsystem cannot empty the list it came
 * from. A deployment with no log file says so instead of looking like an empty
 * log.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
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
  cn: (...a) => a.filter(Boolean).join(' '),
}))

// The layout is exercised by its own tests; here it only has to surface the
// filters it is handed, so each one can be driven by its label.
vi.mock('../../components/ui/responsive', () => ({
  ResponsiveLayout: ({ title, actions, filters = [], children }) => (
    <div>
      <h1>{title}</h1>
      {filters.map((f) => (
        <select
          key={f.key}
          aria-label={f.label}
          value={f.value ?? ''}
          onChange={(e) => f.onChange?.(e.target.value)}
        >
          {(f.options || []).map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      ))}
      <div>{actions}</div>
      {children}
    </div>
  ),
}))

vi.mock('../../components', () => ({
  Button: ({ children, loading: _loading, ...props }) => <button {...props}>{children}</button>,
  Input: ({ label, ...props }) => <input aria-label={label || props.placeholder} {...props} />,
  Select: ({ label, options = [], value, onChange }) => (
    <select aria-label={label || 'lines'} value={value ?? ''} onChange={(e) => onChange?.(e.target.value)}>
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  ),
  LoadingSpinner: () => <div>loading</div>,
}))

vi.mock('../../components/ui/ToggleSwitch', () => ({
  ToggleSwitch: ({ label, checked, onChange }) => (
    <input type="checkbox" aria-label={label} checked={checked} onChange={(e) => onChange(e.target.checked)} />
  ),
}))

import SystemLogsPage from '../SystemLogsPage'

const LINES = [
  { ts: '2026-09-19 13:41:36', logger: 'services.scep', level: 'WARNING', message: 'failInfo=1' },
  { ts: '2026-09-19 13:41:37', logger: 'api.v2', level: 'INFO', message: 'log read' },
]

const DEFAULT_DATA = {
  source: 'app', exists: true, lines: LINES, truncated: false, path: '/x/ucm.log',
  available_sources: ['app', 'access'], components: ['api.v2', 'services.scep'],
}

async function renderPage(data = DEFAULT_DATA) {
  mocks.getApplicationLog.mockResolvedValue({ data })
  render(<SystemLogsPage />)
  await waitFor(() => expect(mocks.getApplicationLog).toHaveBeenCalled())
}

const BASE = { source: 'app', level: 'INFO', lines: 200 }

describe('SystemLogsPage', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => vi.useRealTimers())

  it('renders each record as its own row with its parts split out', async () => {
    await renderPage()
    const row = (await screen.findByText('failInfo=1')).closest('div')
    expect(row).toHaveTextContent('2026-09-19 13:41:36')
    expect(row).toHaveTextContent('WARNING')
    expect(row).toHaveTextContent('services.scep')
    // the parts are separate cells, not one concatenated line
    expect(row.querySelectorAll('span').length).toBe(4)
  })

  it('marks a record that carries no level rather than dropping it', async () => {
    await renderPage({
      ...DEFAULT_DATA,
      lines: [{ ts: null, logger: null, level: null, message: 'GET /api 200' }],
    })
    expect(await screen.findByText('GET /api 200')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('asks the server for the application log, INFO and 200 lines by default', async () => {
    await renderPage()
    expect(mocks.getApplicationLog).toHaveBeenCalledWith(BASE)
  })

  it('offers only the sources this deployment reported', async () => {
    await renderPage()
    const opts = [...screen.getByLabelText('logs.source').options].map((o) => o.value)
    expect(opts).toEqual(['app', 'access'])
  })

  it('offers the components the server found, with an all-components default', async () => {
    await renderPage()
    const opts = [...screen.getByLabelText('logs.component').options].map((o) => o.value)
    expect(opts).toEqual(['', 'api.v2', 'services.scep'])
  })

  it('sends the component to the server, and omits it when set back to all', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.component'), { target: { value: 'services.scep' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, component: 'services.scep' }))

    fireEvent.change(screen.getByLabelText('logs.component'), { target: { value: '' } })
    await waitFor(() => expect(mocks.getApplicationLog).toHaveBeenLastCalledWith(BASE))
  })

  it('refetches when the source, level or line count changes', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.level'), { target: { value: 'ERROR' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, level: 'ERROR' }))

    fireEvent.change(screen.getByLabelText('lines'), { target: { value: '1000' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, level: 'ERROR', lines: 1000 }))
  })

  it('sends the search term to the server rather than filtering locally', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.searchPlaceholder'), { target: { value: 'scep' } })
    fireEvent.click(screen.getByRole('button', { name: /common\.search/ }))
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, q: 'scep' }))
  })

  it('polls while following, and stops when switched off', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    await renderPage()
    const before = mocks.getApplicationLog.mock.calls.length

    fireEvent.click(screen.getByLabelText('logs.follow'))
    await vi.advanceTimersByTimeAsync(11000)
    const polled = mocks.getApplicationLog.mock.calls.length
    expect(polled).toBeGreaterThan(before)

    fireEvent.click(screen.getByLabelText('logs.follow'))
    await vi.advanceTimersByTimeAsync(11000)
    expect(mocks.getApplicationLog.mock.calls.length).toBe(polled)
  })

  it('keeps the lines already shown when a poll fails', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    await renderPage()
    mocks.getApplicationLog.mockRejectedValue(new Error('network'))
    fireEvent.click(screen.getByLabelText('logs.follow'))
    await vi.advanceTimersByTimeAsync(6000)
    expect(screen.getByText('failInfo=1')).toBeInTheDocument()
    expect(mocks.showError).not.toHaveBeenCalled()
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

  it('reports a failed manual read instead of rendering a blank page', async () => {
    mocks.getApplicationLog.mockRejectedValue(new Error('boom'))
    render(<SystemLogsPage />)
    await waitFor(() => expect(mocks.showError).toHaveBeenCalledWith('logs.unavailable'))
  })
})
