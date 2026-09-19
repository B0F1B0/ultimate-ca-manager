/**
 * System Logs Page - Migrated to ResponsiveLayout
 * The server's own application log: filter by source, component, level and time
 */
import { useState, useEffect, useMemo, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Stack, ArrowsClockwise, Copy, Warning, XCircle, Database, Cube, FunnelSimple
} from '@phosphor-icons/react'
import { Badge, Button, Input, Select } from '../components'
import { ToggleSwitch } from '../components/ui/ToggleSwitch'
import { ResponsiveLayout, ResponsiveDataTable } from '../components/ui/responsive'
import { useNotification } from '../contexts'
import { systemService } from '../services'
import { extractData } from '../lib/utils'

const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const LINE_COUNTS = [100, 200, 500, 1000, 2000, 5000]
const FOLLOW_INTERVAL_MS = 5000

const SOURCE_LABELS = {
  app: 'logs.sourceApp',
  access: 'logs.sourceAccess',
  error: 'logs.sourceError',
  journal: 'logs.sourceJournal',
}

const LEVEL_VARIANT = {
  DEBUG: 'gray',
  INFO: 'info',
  WARNING: 'warning',
  ERROR: 'danger',
  CRITICAL: 'danger',
}

export default function SystemLogsPage() {
  const { t } = useTranslation()
  const { showError, showSuccess } = useNotification()
  const [source, setSource] = useState('app')
  const [component, setComponent] = useState('')
  const [level, setLevel] = useState('INFO')
  const [lines, setLines] = useState('200')
  const [search, setSearch] = useState('')
  const [since, setSince] = useState('')
  const [until, setUntil] = useState('')
  const [follow, setFollow] = useState(false)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [showFilters, setShowFilters] = useState(false)
  const [exclude, setExclude] = useState('')
  const [selectedIds, setSelectedIds] = useState(() => new Set())

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    try {
      const response = await systemService.getApplicationLog({
        source, level, lines: parseInt(lines),
        ...(component ? { component } : {}),
        ...(search ? { q: search } : {}),
        ...(since ? { since } : {}),
        ...(until ? { until } : {}),
        ...(exclude ? { exclude } : {}),
      })
      setResult(extractData(response))
    } catch {
      if (!quiet) showError(t('logs.unavailable'))
      setResult((prev) => (quiet ? prev : null))
    } finally {
      if (!quiet) setLoading(false)
    }
  }, [source, component, level, lines, search, since, until, exclude, showError, t])

  useEffect(() => { load() }, [source, component, level, lines, search, since, until, exclude])  // eslint-disable-line react-hooks/exhaustive-deps

  // Live mode polls rather than streaming: a log line pushed over the event bus
  // is itself logged by the push, which is a loop the interval cannot make.
  useEffect(() => {
    if (!follow) return undefined
    const id = setInterval(() => load(true), FOLLOW_INTERVAL_MS)
    return () => clearInterval(id)
  }, [follow, load])

  // The server returns the tail oldest-first, as the file is written. The table
  // paginates, so that would put the newest lines on the last page and open on
  // the oldest — reversed here, page one is the most recent.
  const rows = useMemo(
    () => (result?.lines || []).map((line, index) => ({ id: index, ...line })).reverse(),
    [result],
  )

  // Source and component were one nested control until the component list grew
  // to every subsystem UCM has: the three other logs then sat below thirty
  // entries, where nobody found them. Two plain selects, both in the panel.
  const sourceOptions = useMemo(
    () => (result?.available_sources || ['app']).map((s) => ({
      value: s, label: t(SOURCE_LABELS[s] || s),
    })),
    [result, t],
  )

  const componentOptions = useMemo(
    () => [
      { value: '', label: t('logs.allComponents') },
      ...(result?.components || []).map((c) => ({ value: c, label: c })),
    ],
    [result, t],
  )

  const filtered = source !== 'app' || component || since || until || exclude

  const headerStats = useMemo(() => {
    const levels = result?.levels || {}
    return [
      { icon: Database, label: t('common.total'), value: result?.matched || 0, variant: 'default' },
      {
        icon: XCircle,
        label: t('logs.errors'),
        value: (levels.ERROR || 0) + (levels.CRITICAL || 0),
        variant: 'danger',
      },
      { icon: Warning, label: t('logs.warnings'), value: levels.WARNING || 0, variant: 'warning' },
      {
        icon: Cube,
        label: t('logs.components'),
        value: (result?.components || []).length,
        variant: 'info',
      },
    ]
  }, [result, t])

  const columns = useMemo(() => [
    {
      key: 'ts',
      header: t('logs.time'),
      priority: 1,
      render: (value) => (
        <span className="font-mono text-xs text-text-secondary whitespace-nowrap">{value || ''}</span>
      ),
      mobileRender: (value, row) => (
        <div className="flex items-center justify-between gap-2 w-full">
          <span className="font-mono text-xs text-text-secondary">{value || ''}</span>
          {row.level && <Badge variant={LEVEL_VARIANT[row.level]} size="sm">{row.level}</Badge>}
        </div>
      ),
    },
    {
      key: 'level',
      header: t('logs.levelShort'),
      priority: 2,
      // A line whose format carries no level gets no badge. A placeholder in
      // its place reads as a level of its own, which is the one thing the
      // reader must not conclude from a line nobody could parse.
      render: (value) => (
        value ? <Badge variant={LEVEL_VARIANT[value]} size="sm">{value}</Badge> : null
      ),
    },
    {
      key: 'logger',
      header: t('logs.component'),
      priority: 3,
      render: (value) => (
        <span className="font-mono text-xs text-text-secondary">{value || ''}</span>
      ),
    },
    {
      key: 'message',
      header: t('logs.message'),
      priority: 1,
      render: (value) => (
        <span className="font-mono text-xs text-text-primary whitespace-pre-wrap break-words">{value}</span>
      ),
      mobileRender: (value, row) => (
        <div className="space-y-1">
          <span className="font-mono text-xs text-text-tertiary">{row.logger || ''}</span>
          <p className="font-mono text-xs text-text-primary break-words">{value}</p>
        </div>
      ),
    },
  ], [t])

  // Copied in the log's own shape, field for field: asctime, [name], level,
  // message, as the formatter in app.py writes it. Level and component the
  // other way round read the same to a person and parse back as neither, which
  // matters when the line is pasted into an issue and read by this same page.
  const copy = (subset) => {
    const text = subset
      .map((l) => [l.ts, l.logger && `[${l.logger}]`, l.level, l.message].filter(Boolean).join(' '))
      .join('\n')
    navigator.clipboard.writeText(text).then(
      () => showSuccess(t('common.copy')),
      () => showError(t('common.copy')),
    )
  }

  const toolbarActions = (
    <>
      <div className="w-32">
        <Select
          label={t('logs.level')}
          value={level}
          onChange={setLevel}
          options={LEVELS.map((l) => ({ value: l, label: l }))}
        />
      </div>
      <div className="w-32">
        <Select
          label={t('logs.lines')}
          value={lines}
          onChange={setLines}
          options={LINE_COUNTS.map((n) => ({
            value: String(n), label: t('logs.linesOpt', { count: n }),
          }))}
        />
      </div>
      <ToggleSwitch
        checked={follow}
        onChange={(on) => {
          // A window into the past and a tail of the present are opposite
          // requests; following one clears the other rather than leaving an
          // empty pane that reads as nothing being logged.
          setFollow(on)
          if (on) { setSince(''); setUntil(''); setShowFilters(false) }
        }}
        label={t('logs.follow')}
        size="sm"
      />
      <Button
        type="button"
        variant={filtered ? 'primary' : 'secondary'}
        size="sm"
        onClick={() => setShowFilters(true)}
      >
        <FunnelSimple size={14} /> {t('logs.filters')}
      </Button>
      <Button type="button" variant="secondary" size="sm" onClick={() => load()} loading={loading}>
        <ArrowsClockwise size={14} />
      </Button>
      <Button type="button" variant="ghost" size="sm" onClick={() => copy(rows)}>
        <Copy size={14} /> <span className="hidden sm:inline">{t('logs.copyAll')}</span>
      </Button>
    </>
  )

  const filterContent = (
    <div className="p-4 space-y-4">
      <Select
        label={t('logs.source')}
        value={source}
        onChange={(v) => { setSource(v); if (v !== 'app') setComponent('') }}
        options={sourceOptions}
      />
      <Select
        label={t('logs.component')}
        value={component}
        onChange={setComponent}
        disabled={source !== 'app'}
        options={componentOptions}
      />
      <Input
        type="datetime-local"
        label={t('logs.from')}
        value={since}
        disabled={follow}
        onChange={(e) => setSince(e.target.value)}
      />
      <Input
        type="datetime-local"
        label={t('logs.to')}
        value={until}
        disabled={follow}
        onChange={(e) => setUntil(e.target.value)}
      />
      <p className="text-xs text-text-tertiary">{t('logs.serverTime')}</p>
      {/* Search and Exclude are substrings, not patterns: one gevent worker
          answers every protocol this server speaks, and a pattern from the
          browser is unbounded work over thousands of records. */}
      <Input
        label={t('logs.exclude')}
        placeholder={t('logs.exclude')}
        value={exclude}
        onChange={(e) => setExclude(e.target.value)}
      />
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={() => {
          setSource('app'); setComponent('')
          setSince(''); setUntil(''); setExclude('')
        }}
      >
        {t('common.clear')}
      </Button>
    </div>
  )

  return (
    <ResponsiveLayout
      title={t('common.systemLogs')}
      icon={Stack}
      subtitle={t('logs.subtitle')}
      stats={headerStats}
      helpPageKey="systemLogs"
      slideOverOpen={showFilters}
      onSlideOverClose={() => setShowFilters(false)}
      slideOverTitle={t('logs.filters')}
      slideOverContent={filterContent}
      slideOverWidth="narrow"
    >
      <div className="flex flex-col h-full min-h-0">
        <ResponsiveDataTable
          data={rows}
          columns={columns}
          keyField="id"
          loading={loading}
          searchable
          externalSearch={search}
          onSearchChange={setSearch}
          searchPlaceholder={t('logs.searchPlaceholder')}
          densityStorageKey="ucm-system-logs-density"
          toolbarActions={toolbarActions}
          multiSelect
          selectedIds={selectedIds}
          onSelectionChange={setSelectedIds}
          bulkActions={
            <Button
              type="button" variant="secondary" size="sm"
              onClick={() => copy(rows.filter((r) => selectedIds.has(r.id)))}
            >
              <Copy size={14} /> {t('logs.copySelected')}
            </Button>
          }
          emptyState={{
            icon: Stack,
            title: result && !result.exists ? t('logs.unavailable') : t('logs.empty'),
            description: result && !result.exists ? '' : t('common.tryAdjustFilters'),
          }}
        />
        {result && (
          <p className="px-4 py-2 text-xs text-text-tertiary border-t border-border break-all">
            {result.path && (
              <>{t('logs.readingFrom')} <code className="font-mono">{result.path}</code>{' · '}</>
            )}
            {t('logs.serverTime')}
            {result.timezone?.name || result.timezone?.offset
              ? ` (${[result.timezone.name, result.timezone.offset].filter(Boolean).join(' ')})`
              : ''}
            {result.truncated
              ? ` · ${t('logs.showing', { shown: rows.length, matched: result.matched })}`
              : ''}
            {result.scan_truncated ? ` · ${t('logs.scanCap')}` : ''}
          </p>
        )}
      </div>
    </ResponsiveLayout>
  )
}
