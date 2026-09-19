/**
 * System Logs Page - Migrated to ResponsiveLayout
 * Tail of the server's own application log, by source, component, level and text
 */
import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { Stack, MagnifyingGlass, ArrowsClockwise, Copy } from '@phosphor-icons/react'
import { Button, Input, Select, LoadingSpinner } from '../components'
import { ToggleSwitch } from '../components/ui/ToggleSwitch'
import { ResponsiveLayout } from '../components/ui/responsive'
import { useNotification } from '../contexts'
import { systemService } from '../services'
import { extractData, cn } from '../lib/utils'

const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const LINE_COUNTS = [100, 200, 500, 1000, 2000]
const FOLLOW_INTERVAL_MS = 5000

const SOURCE_LABELS = {
  app: 'logs.sourceApp',
  access: 'logs.sourceAccess',
  error: 'logs.sourceError',
  journal: 'logs.sourceJournal',
}

const LEVEL_CLASS = {
  DEBUG: 'text-text-tertiary',
  INFO: 'text-accent-primary',
  WARNING: 'status-warning-text',
  ERROR: 'status-danger-text',
  CRITICAL: 'status-danger-text',
}

export default function SystemLogsPage() {
  const { t } = useTranslation()
  const { showError, showSuccess } = useNotification()
  const [source, setSource] = useState('app')
  const [component, setComponent] = useState('')
  const [level, setLevel] = useState('INFO')
  const [lines, setLines] = useState('200')
  const [query, setQuery] = useState('')
  const [follow, setFollow] = useState(false)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const paneRef = useRef(null)

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true)
    try {
      const response = await systemService.getApplicationLog({
        source, level, lines: parseInt(lines),
        ...(component ? { component } : {}),
        ...(query ? { q: query } : {}),
      })
      setResult(extractData(response))
    } catch {
      if (!quiet) showError(t('logs.unavailable'))
      setResult((prev) => (quiet ? prev : null))
    } finally {
      if (!quiet) setLoading(false)
    }
  }, [source, component, level, lines, query, showError, t])

  useEffect(() => { load() }, [source, component, level, lines])   // eslint-disable-line react-hooks/exhaustive-deps

  // Follow mode polls rather than streaming: a log line pushed over the event
  // bus is itself logged by the push, which is a loop the interval cannot make.
  useEffect(() => {
    if (!follow) return undefined
    const id = setInterval(() => load(true), FOLLOW_INTERVAL_MS)
    return () => clearInterval(id)
  }, [follow, load])

  // Newest is last, so following is only useful pinned to the bottom.
  useEffect(() => {
    if (follow && paneRef.current) paneRef.current.scrollTop = paneRef.current.scrollHeight
  }, [result, follow])

  const copyAll = () => {
    const text = (result?.lines || [])
      .map((l) => [l.ts, l.level, l.logger && `[${l.logger}]`, l.message].filter(Boolean).join(' '))
      .join('\n')
    navigator.clipboard.writeText(text).then(
      () => showSuccess(t('common.copy')),
      () => showError(t('common.copy')),
    )
  }

  const filters = useMemo(() => [
    {
      key: 'source',
      label: t('logs.source'),
      type: 'select',
      value: source,
      onChange: setSource,
      placeholder: t('logs.source'),
      options: (result?.available_sources || ['app']).map((s) => ({
        value: s, label: t(SOURCE_LABELS[s] || s),
      })),
    },
    {
      key: 'component',
      label: t('logs.component'),
      type: 'select',
      value: component,
      onChange: setComponent,
      placeholder: t('logs.allComponents'),
      options: [
        { value: '', label: t('logs.allComponents') },
        ...(result?.components || []).map((c) => ({ value: c, label: c })),
      ],
    },
    {
      key: 'level',
      label: t('logs.level'),
      type: 'select',
      value: level,
      onChange: setLevel,
      placeholder: t('logs.level'),
      options: LEVELS.map((l) => ({ value: l, label: l })),
    },
  ], [source, component, level, result, t])

  const actions = (
    <>
      <Button type="button" variant="secondary" size="sm" onClick={() => load()} loading={loading}>
        <ArrowsClockwise size={14} />
        <span className="hidden sm:inline">{t('common.refresh')}</span>
      </Button>
      <Button type="button" variant="ghost" size="sm" onClick={copyAll}>
        <Copy size={14} />
        <span className="hidden sm:inline">{t('common.copy')}</span>
      </Button>
    </>
  )

  return (
    <ResponsiveLayout
      title={t('common.systemLogs')}
      subtitle={t('logs.subtitle')}
      icon={Stack}
      actions={actions}
      filters={filters}
    >
      <div className="flex flex-col h-full min-h-0">
        <form
          className="flex flex-wrap items-center gap-2 p-3 md:p-4 border-b border-border"
          onSubmit={(e) => { e.preventDefault(); load() }}
        >
          <div className="flex-1 min-w-32">
            <Input
              placeholder={t('logs.searchPlaceholder')}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <Button type="submit" variant="secondary" size="sm">
            <MagnifyingGlass size={14} />
            <span className="hidden sm:inline">{t('common.search')}</span>
          </Button>
          <div className="w-24">
            <Select
              value={lines}
              onChange={setLines}
              options={LINE_COUNTS.map((n) => ({ value: String(n), label: String(n) }))}
            />
          </div>
          <ToggleSwitch
            checked={follow}
            onChange={setFollow}
            label={t('logs.follow')}
            size="sm"
          />
        </form>

        {loading ? (
          <div className="flex-1 flex items-center justify-center p-8"><LoadingSpinner /></div>
        ) : !result?.exists ? (
          <p className="p-6 text-sm text-text-secondary">{t('logs.unavailable')}</p>
        ) : result.lines.length === 0 ? (
          <p className="p-6 text-sm text-text-secondary">{t('logs.empty')}</p>
        ) : (
          <>
            {result.truncated && (
              <p className="px-3 md:px-4 py-1.5 text-xs text-text-tertiary border-b border-border">
                {t('logs.truncated')}
              </p>
            )}
            <div ref={paneRef} className="flex-1 min-h-0 overflow-auto">
              {result.lines.map((line, index) => (
                <div
                  key={index}
                  className={cn(
                    'grid gap-x-3 px-3 md:px-4 py-1.5 border-b border-border last:border-0',
                    'grid-cols-1 md:grid-cols-[auto_auto_minmax(0,14rem)_minmax(0,1fr)]',
                    'text-xs font-mono hover:bg-bg-hover',
                  )}
                >
                  <span className="text-text-tertiary whitespace-nowrap">{line.ts || ''}</span>
                  <span className={cn('font-semibold whitespace-nowrap',
                    LEVEL_CLASS[line.level] || 'text-text-tertiary')}>
                    {line.level || '—'}
                  </span>
                  <span className="text-text-secondary truncate" title={line.logger || ''}>
                    {line.logger || ''}
                  </span>
                  <span className="text-text-primary whitespace-pre-wrap break-words">
                    {line.message}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}

        {result?.path && (
          <p className="px-3 md:px-4 py-2 text-xs text-text-tertiary border-t border-border break-all">
            {t('logs.readingFrom')} <code className="font-mono">{result.path}</code>
          </p>
        )}
      </div>
    </ResponsiveLayout>
  )
}
