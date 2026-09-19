/**
 * System Logs Page - Migrated to ResponsiveLayout
 * The server's own application log: filter by source, component, level and time
 */
import { useState, useEffect, useMemo, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Stack, ArrowsClockwise, Copy, Warning, XCircle, Database, Cube, CalendarBlank
} from '@phosphor-icons/react'
import { Badge, Button, Input, Select } from '../components'
import { ToggleSwitch } from '../components/ui/ToggleSwitch'
import { ResponsiveLayout, ResponsiveDataTable } from '../components/ui/responsive'
import { useNotification } from '../contexts'
import { systemService } from '../services'
import { extractData } from '../lib/utils'

const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const LINE_COUNTS = [100, 200, 500, 1000, 2000]
const FOLLOW_INTERVAL_MS = 5000
const INDENT = '  '

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
  const [showTimeFilters, setShowTimeFilters] = useState(false)
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
      })
      setResult(extractData(response))
    } catch {
      if (!quiet) showError(t('logs.unavailable'))
      setResult((prev) => (quiet ? prev : null))
    } finally {
      if (!quiet) setLoading(false)
    }
  }, [source, component, level, lines, search, since, until, showError, t])

  useEffect(() => { load() }, [source, component, level, lines, search, since, until])  // eslint-disable-line react-hooks/exhaustive-deps

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

  // Source and component answer one question — which lines am I looking at —
  // so they are one control. FilterSelect always prepends a cleared entry and
  // labels it from allLabel, so that entry *is* the unfiltered application log:
  // its components nest under it, and the other sources follow. Listing 'app'
  // again would duplicate the entry that already means it.
  const sourceOptions = useMemo(() => {
    const out = []
    for (const c of (result?.components || [])) {
      out.push({ value: `app:${c}`, label: `${INDENT}${c}` })
    }
    for (const s of (result?.available_sources || [])) {
      if (s !== 'app') out.push({ value: s, label: t(SOURCE_LABELS[s] || s) })
    }
    return out
  }, [result, t])

  const sourceValue = component ? `app:${component}` : (source === 'app' ? '' : source)
  const onSourceChange = (v) => {
    const [nextSource, nextComponent = ''] = String(v || 'app').split(':')
    setSource(nextSource)
    setComponent(nextComponent)
  }

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
          <Badge variant={LEVEL_VARIANT[row.level] || 'gray'} size="sm">{row.level || '—'}</Badge>
        </div>
      ),
    },
    {
      key: 'level',
      header: t('logs.levelShort'),
      priority: 2,
      render: (value) => (
        <Badge variant={LEVEL_VARIANT[value] || 'gray'} size="sm">{value || '—'}</Badge>
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

  // Copied in the log's own shape, so what lands on the clipboard can be pasted
  // into an issue and read as a log rather than as a table.
  const copy = (subset) => {
    const text = subset
      .map((l) => [l.ts, l.level, l.logger && `[${l.logger}]`, l.message].filter(Boolean).join(' '))
      .join('\n')
    navigator.clipboard.writeText(text).then(
      () => showSuccess(t('common.copy')),
      () => showError(t('common.copy')),
    )
  }

  const toolbarActions = (
    <>
      <div className="w-24">
        <Select
          value={lines}
          onChange={setLines}
          options={LINE_COUNTS.map((n) => ({ value: String(n), label: String(n) }))}
        />
      </div>
      <ToggleSwitch
        checked={follow}
        onChange={(on) => {
          // A window into the past and a tail of the present are opposite
          // requests; following one clears the other rather than leaving an
          // empty pane that reads as nothing being logged.
          setFollow(on)
          if (on) { setSince(''); setUntil(''); setShowTimeFilters(false) }
        }}
        label={t('logs.follow')}
        size="sm"
      />
      <Button
        type="button"
        variant={since || until ? 'primary' : 'secondary'}
        size="sm"
        disabled={follow}
        onClick={() => setShowTimeFilters(true)}
      >
        <CalendarBlank size={14} /> {t('common.date')}
      </Button>
      <Button type="button" variant="secondary" size="sm" onClick={() => load()} loading={loading}>
        <ArrowsClockwise size={14} />
      </Button>
      <Button type="button" variant="ghost" size="sm" onClick={() => copy(rows)}>
        <Copy size={14} /> <span className="hidden sm:inline">{t('logs.copyAll')}</span>
      </Button>
    </>
  )

  const timeFilterContent = (
    <div className="p-4 space-y-4">
      <Input
        type="datetime-local"
        label={t('logs.from')}
        value={since}
        onChange={(e) => setSince(e.target.value)}
      />
      <Input
        type="datetime-local"
        label={t('logs.to')}
        value={until}
        onChange={(e) => setUntil(e.target.value)}
      />
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={() => { setSince(''); setUntil('') }}
      >
        {t('common.clear')}
      </Button>
      <p className="text-xs text-text-tertiary">{t('logs.serverTime')}</p>
    </div>
  )

  return (
    <ResponsiveLayout
      title={t('common.systemLogs')}
      icon={Stack}
      subtitle={t('logs.subtitle')}
      stats={headerStats}
      helpPageKey="systemLogs"
      slideOverOpen={showTimeFilters}
      onSlideOverClose={() => setShowTimeFilters(false)}
      slideOverTitle={t('common.date')}
      slideOverContent={timeFilterContent}
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
          toolbarFilters={[
            {
              key: 'source',
              label: t('logs.source'),
              value: sourceValue,
              onChange: onSourceChange,
              allLabel: t('logs.sourceApp'),
              placeholder: t('logs.sourceApp'),
              options: sourceOptions,
            },
            {
              key: 'level',
              label: t('logs.level'),
              // Cleared means no floor, which is the lowest level there is.
              value: level === 'DEBUG' ? '' : level,
              onChange: (v) => setLevel(v || 'DEBUG'),
              allLabel: t('logs.allLevels'),
              placeholder: t('logs.allLevels'),
              options: LEVELS.filter((l) => l !== 'DEBUG').map((l) => ({ value: l, label: l })),
            },
          ]}
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
            {result.truncated ? ` · ${t('logs.truncated')}` : ''}
          </p>
        )}
      </div>
    </ResponsiveLayout>
  )
}
