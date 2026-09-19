/**
 * SystemLogsPage — every filter reaches the server rather than being applied in
 * the browser, so a filter never hides lines that were simply never fetched.
 * The component list and the counts are built from everything read, not from
 * what survived the filters, so narrowing can neither empty the list it came
 * from nor appear to change how many errors the server had. A deployment with
 * no log file says so instead of looking like an empty log.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  getApplicationLog: vi.fn(),
  showError: vi.fn(),
  showSuccess: vi.fn(),
  writeText: vi.fn(() => Promise.resolve()),
}))

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key) => key }) }))
vi.mock('../../services', () => ({
  systemService: { getApplicationLog: mocks.getApplicationLog },
}))
vi.mock('../../contexts', () => ({
  useNotification: () => ({ showError: mocks.showError, showSuccess: mocks.showSuccess }),
}))
vi.mock('../../lib/utils', () => ({ extractData: (r) => r?.data ?? r }))

// Both layout pieces have their own tests. Here they only surface what the page
// hands them, so each control can be driven by the label the page gave it.
vi.mock('../../components/ui/responsive', () => ({
  ResponsiveLayout: ({ title, stats = [], slideOverOpen, slideOverContent, children }) => (
    <div>
      <h1>{title}</h1>
      <ul aria-label="stats">
        {stats.map((s) => <li key={s.label}>{`${s.label}=${s.value}`}</li>)}
      </ul>
      {children}
      {slideOverOpen && <aside aria-label="slideover">{slideOverContent}</aside>}
    </div>
  ),
  ResponsiveDataTable: ({
    data = [], columns = [], externalSearch, onSearchChange, searchPlaceholder,
    toolbarActions, emptyState,
    multiSelect, selectedIds, onSelectionChange, bulkActions,
  }) => (
    <div>
      <input
        aria-label={searchPlaceholder}
        value={externalSearch ?? ''}
        onChange={(e) => onSearchChange?.(e.target.value)}
      />
      <div>{toolbarActions}</div>
      {multiSelect && (
        <div>
          {data.map((row) => (
            <input
              key={row.id}
              type="checkbox"
              aria-label={`select-${row.id}`}
              checked={selectedIds?.has(row.id) || false}
              onChange={(e) => {
                const next = new Set(selectedIds)
                if (e.target.checked) next.add(row.id)
                else next.delete(row.id)
                onSelectionChange(next)
              }}
            />
          ))}
          {selectedIds?.size > 0 && bulkActions}
        </div>
      )}
      {data.length === 0 ? (
        <p>{emptyState?.title}</p>
      ) : (
        <table>
          <thead><tr>{columns.map((c) => <th key={c.key}>{c.header}</th>)}</tr></thead>
          <tbody>
            {data.map((row) => (
              <tr key={row.id}>
                {columns.map((c) => <td key={c.key}>{c.render(row[c.key], row)}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  ),
}))

vi.mock('../../components', () => ({
  Badge: ({ children }) => <span>{children}</span>,
  Button: ({ children, loading: _loading, ...props }) => <button {...props}>{children}</button>,
  Input: ({ label, ...props }) => <input aria-label={label || props.placeholder} {...props} />,
  Select: ({ label, options = [], value, onChange, disabled }) => (
    <select
      aria-label={label}
      value={value ?? ''}
      disabled={disabled}
      onChange={(e) => onChange?.(e.target.value)}
    >
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  ),
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
  matched: 1193, levels: { DEBUG: 0, INFO: 1, WARNING: 13, ERROR: 5, CRITICAL: 1, UNKNOWN: 0 },
  timezone: { name: 'CEST', offset: '+02:00' },
}

async function renderPage(data = DEFAULT_DATA) {
  // A fresh object per call, as a real fetch gives: one shared reference makes
  // React bail out of the re-render and hides the effects under test.
  mocks.getApplicationLog.mockImplementation(async () => ({ data: { ...data } }))
  render(<SystemLogsPage />)
  await waitFor(() => expect(mocks.getApplicationLog).toHaveBeenCalled())
}

const BASE = { source: 'app', level: 'INFO', lines: 200 }

describe('SystemLogsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.assign(navigator, { clipboard: { writeText: mocks.writeText } })
  })
  afterEach(() => vi.useRealTimers())

  it('heads the table with the column names', async () => {
    await renderPage()
    expect([...document.querySelectorAll('th')].map((h) => h.textContent))
      .toEqual(['logs.time', 'logs.levelShort', 'logs.component', 'logs.message'])
  })

  it('renders each record as a row with its parts in their own cells', async () => {
    await renderPage()
    const row = (await screen.findByText('failInfo=1')).closest('tr')
    expect([...row.querySelectorAll('td')].map((c) => c.textContent.trim()))
      .toEqual(['2026-09-19 13:41:36', 'WARNING', 'services.scep', 'failInfo=1'])
  })

  it('keeps a record that carries no level, and invents none for it', async () => {
    await renderPage({
      ...DEFAULT_DATA,
      lines: [{ ts: null, logger: null, level: null, message: 'GET /api 200' }],
    })
    const row = (await screen.findByText('GET /api 200')).closest('tr')
    expect(row).toBeTruthy()                                   // shown, not dropped
    expect(row.querySelectorAll('td')[1].textContent).toBe('')  // and no badge
  })

  it('summarises what the filters matched, not the page of it on screen', async () => {
    await renderPage()
    const stats = [...screen.getByLabelText('stats').children].map((li) => li.textContent)
    expect(stats).toContain('common.total=1193')
    expect(stats).toContain('logs.errors=6')        // ERROR + CRITICAL
    expect(stats).toContain('logs.warnings=13')
    expect(stats).toContain('logs.components=2')
  })

  it('asks the server for the application log, INFO and 200 lines by default', async () => {
    await renderPage()
    expect(mocks.getApplicationLog).toHaveBeenCalledWith(BASE)
  })

  it('offers each source this deployment has, and the components beneath it', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    expect([...(await screen.findByLabelText('logs.source')).options].map((o) => o.value))
      .toEqual(['app', 'access'])
    // a component entry that means all of them, so the log itself is reachable
    expect([...screen.getByLabelText('logs.component').options].map((o) => o.value))
      .toEqual(['', 'api.v2', 'services.scep'])
  })

  it('narrows to a component, and back to the whole log', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    fireEvent.change(await screen.findByLabelText('logs.component'), { target: { value: 'services.scep' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, component: 'services.scep' }))

    fireEvent.change(screen.getByLabelText('logs.component'), { target: { value: '' } })
    await waitFor(() => expect(mocks.getApplicationLog).toHaveBeenLastCalledWith(BASE))
  })

  it('drops the component when another log is picked, as it has none', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    fireEvent.change(await screen.findByLabelText('logs.component'), { target: { value: 'services.scep' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, component: 'services.scep' }))

    fireEvent.change(screen.getByLabelText('logs.source'), { target: { value: 'access' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, source: 'access' }))
  })

  it('offers every level as a floor, with no entry that means none', async () => {
    await renderPage()
    const select = screen.getByLabelText('logs.level')
    expect([...select.options].map((o) => o.value))
      .toEqual(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
  })

  it('refetches when the level or line count changes', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.level'), { target: { value: 'ERROR' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, level: 'ERROR' }))

    fireEvent.change(screen.getByLabelText('logs.lines'), { target: { value: '1000' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, level: 'ERROR', lines: 1000 }))
  })

  it('sends the search term to the server rather than filtering locally', async () => {
    await renderPage()
    fireEvent.change(screen.getByLabelText('logs.searchPlaceholder'), { target: { value: 'scep' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, q: 'scep' }))
  })

  it('sends a time window from the filter panel', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    fireEvent.change(await screen.findByLabelText('logs.from'), { target: { value: '2026-09-19T12:30' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, since: '2026-09-19T12:30' }))
  })

  it('sends an exclusion to the server rather than applying it here', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    fireEvent.change(await screen.findByLabelText('logs.exclude'), { target: { value: 'heartbeat' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, exclude: 'heartbeat' }))
  })

  it('offers no pattern switch: search and exclude are text', async () => {
    // One gevent worker answers every protocol this server speaks, and a
    // pattern from here is unbounded work over thousands of records.
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    expect(await screen.findByLabelText('logs.exclude')).toBeInTheDocument()
    expect(screen.queryByLabelText('logs.regex')).toBeNull()

    fireEvent.change(screen.getByLabelText('logs.searchPlaceholder'), { target: { value: '.*' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, q: '.*' }))
    expect(mocks.getApplicationLog.mock.calls.every(([args]) => !('regex' in args))).toBe(true)
  })

  it('asks once when the typing stops, not once per character', async () => {
    // Each read is a 2 MB tail, a redaction pass and a parse on the worker that
    // also answers ACME, SCEP and OCSP.
    vi.useFakeTimers({ shouldAdvanceTime: true })
    await renderPage()
    const before = mocks.getApplicationLog.mock.calls.length
    const box = screen.getByLabelText('logs.searchPlaceholder')

    for (const typed of ['s', 'sc', 'sce', 'scep']) {
      fireEvent.change(box, { target: { value: typed } })
      await vi.advanceTimersByTimeAsync(50)
    }
    expect(mocks.getApplicationLog.mock.calls.length).toBe(before)

    await vi.advanceTimersByTimeAsync(400)
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, q: 'scep' }))
    expect(mocks.getApplicationLog.mock.calls.length).toBe(before + 1)
  })

  it('waits for the pause on the exclusion box too', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    await renderPage()
    const before = mocks.getApplicationLog.mock.calls.length
    fireEvent.click(screen.getByText('logs.filters'))
    const box = await screen.findByLabelText('logs.exclude')

    for (const typed of ['h', 'he', 'hea', 'heartbeat']) {
      fireEvent.change(box, { target: { value: typed } })
      await vi.advanceTimersByTimeAsync(50)
    }
    expect(mocks.getApplicationLog.mock.calls.length).toBe(before)

    await vi.advanceTimersByTimeAsync(400)
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, exclude: 'heartbeat' }))
  })

  it('clears the time window when live logs is switched on', async () => {
    await renderPage()
    fireEvent.click(screen.getByText('logs.filters'))
    fireEvent.change(await screen.findByLabelText('logs.from'), { target: { value: '2026-09-19T12:30' } })
    await waitFor(() => expect(mocks.getApplicationLog)
      .toHaveBeenLastCalledWith({ ...BASE, since: '2026-09-19T12:30' }))

    fireEvent.click(screen.getByLabelText('logs.follow'))
    await waitFor(() => expect(mocks.getApplicationLog).toHaveBeenLastCalledWith(BASE))
  })

  it('polls while live, and stops when switched off', async () => {
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

  it('lists the newest line first, so page one is the recent one', async () => {
    await renderPage()
    const first = document.querySelector('tbody tr')
    expect(first.querySelectorAll('td')[0].textContent).toBe('2026-09-19 13:41:37')
  })

  it("copies every line as the file writes it, newest first as shown", async () => {
    // asctime, [name], level, message. The other order reads the same to a
    // person and parses back as neither, which matters when a pasted line
    // comes back to this page.
    await renderPage()
    fireEvent.click(screen.getByText('logs.copyAll'))
    await waitFor(() => expect(mocks.writeText).toHaveBeenCalled())
    expect(mocks.writeText.mock.calls[0][0]).toBe(
      '2026-09-19 13:41:37 [api.v2] INFO log read\n'
      + '2026-09-19 13:41:36 [services.scep] WARNING failInfo=1',
    )
  })

  it('copies only the ticked lines once any are ticked', async () => {
    await renderPage()
    expect(screen.queryByText('logs.copySelected')).toBeNull()

    fireEvent.click(screen.getByLabelText('select-0'))
    fireEvent.click(screen.getByText('logs.copySelected'))
    await waitFor(() => expect(mocks.writeText).toHaveBeenCalled())
    expect(mocks.writeText.mock.calls[0][0])
      .toBe('2026-09-19 13:41:36 [services.scep] WARNING failInfo=1')
  })

  it('says the log is unavailable rather than showing an empty log', async () => {
    await renderPage({ ...DEFAULT_DATA, exists: false, lines: [], path: null })
    expect(await screen.findByText('logs.unavailable')).toBeInTheDocument()
  })

  it('distinguishes no matches from no log file', async () => {
    await renderPage({ ...DEFAULT_DATA, lines: [] })
    expect(await screen.findByText('logs.empty')).toBeInTheDocument()
  })

  it('names the file and the zone the timestamps are written in', async () => {
    await renderPage()
    expect(await screen.findByText(/\/x\/ucm\.log/)).toBeInTheDocument()
    expect(screen.getByText(/logs\.serverTime \(CEST \+02:00\)/)).toBeInTheDocument()
  })

  it('says how much of what matched is on screen when the cap cut it', async () => {
    await renderPage({ ...DEFAULT_DATA, truncated: true })
    expect(await screen.findByText(/logs\.showing/)).toBeInTheDocument()
  })

  it('says separately when only the tail of the file was scanned', async () => {
    await renderPage({ ...DEFAULT_DATA, scan_truncated: true })
    expect(await screen.findByText(/logs\.scanCap/)).toBeInTheDocument()
  })

  it('reports a failed manual read instead of rendering a blank page', async () => {
    mocks.getApplicationLog.mockRejectedValue(new Error('boom'))
    render(<SystemLogsPage />)
    await waitFor(() => expect(mocks.showError).toHaveBeenCalledWith('logs.unavailable'))
  })
})
