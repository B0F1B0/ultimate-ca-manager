/**
 * System Logs Page
 * Tail of the server's own application log, filtered by level and text
 */
import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Stack, MagnifyingGlass, ArrowsClockwise, Copy } from '@phosphor-icons/react'
import {
  Card, Button, Input, Select, LoadingSpinner, CompactHeader
} from '../components'
import { useNotification } from '../contexts'
import { systemService } from '../services'
import { extractData } from '../lib/utils'

const LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const LINE_COUNTS = [100, 200, 500, 1000, 2000]
const SOURCE_LABELS = {
  app: 'logs.sourceApp',
  access: 'logs.sourceAccess',
  error: 'logs.sourceError',
  journal: 'logs.sourceJournal',
}

const levelClass = {
  DEBUG: 'text-text-tertiary',
  INFO: 'text-text-secondary',
  WARNING: 'status-warning-text',
  ERROR: 'status-danger-text',
  CRITICAL: 'status-danger-text',
}

export default function SystemLogsPage() {
  const { t } = useTranslation()
  const { showError, showSuccess } = useNotification()
  const [source, setSource] = useState('app')
  const [level, setLevel] = useState('INFO')
  const [lines, setLines] = useState('200')
  const [query, setQuery] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const response = await systemService.getApplicationLog({
        source, level, lines: parseInt(lines), ...(query ? { q: query } : {}),
      })
      setResult(extractData(response))
    } catch {
      showError(t('logs.unavailable'))
      setResult(null)
    } finally {
      setLoading(false)
    }
  }, [source, level, lines, query, showError, t])

  useEffect(() => { load() }, [source, level, lines])   // eslint-disable-line react-hooks/exhaustive-deps

  const copyAll = () => {
    const text = (result?.lines || [])
      .map((line) => [line.ts, line.logger, line.level, line.message].filter(Boolean).join(' '))
      .join('\n')
    navigator.clipboard.writeText(text).then(
      () => showSuccess(t('common.copy')),
      () => showError(t('common.copy')),
    )
  }

  return (
    <div className="space-y-4">
      <CompactHeader
        icon={Stack}
        title={t('common.systemLogs')}
        subtitle={t('logs.subtitle')}
      />

      <Card className="p-4">
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => { e.preventDefault(); load() }}
        >
          <div className="w-40">
            <Select
              label={t('logs.source')}
              value={source}
              onChange={setSource}
              options={(result?.available_sources || ['app']).map((s) => ({
                value: s, label: t(SOURCE_LABELS[s] || s),
              }))}
            />
          </div>
          <div className="w-40">
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
              options={LINE_COUNTS.map((n) => ({ value: String(n), label: String(n) }))}
            />
          </div>
          <div className="flex-1 min-w-48">
            <Input
              label={t('common.search')}
              placeholder={t('logs.searchPlaceholder')}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <Button type="submit" variant="secondary" size="sm">
            <MagnifyingGlass size={14} /> {t('common.search')}
          </Button>
          <Button type="button" variant="secondary" size="sm" onClick={load} loading={loading}>
            <ArrowsClockwise size={14} /> {t('common.refresh')}
          </Button>
          <Button type="button" variant="ghost" size="sm" onClick={copyAll}>
            <Copy size={14} /> {t('common.copy')}
          </Button>
        </form>
      </Card>

      <Card className="p-0 overflow-hidden">
        {loading ? (
          <div className="p-8 flex justify-center"><LoadingSpinner /></div>
        ) : !result?.exists ? (
          <p className="p-6 text-sm text-text-secondary">{t('logs.unavailable')}</p>
        ) : result.lines.length === 0 ? (
          <p className="p-6 text-sm text-text-secondary">{t('logs.empty')}</p>
        ) : (
          <>
            {result.truncated && (
              <p className="px-4 py-2 text-xs text-text-tertiary border-b border-border">
                {t('logs.truncated')}
              </p>
            )}
            <div className="max-h-[60vh] overflow-auto font-mono text-xs">
              {result.lines.map((line, index) => (
                <div
                  key={index}
                  className="px-4 py-1 border-b border-border last:border-0 whitespace-pre-wrap break-all"
                >
                  <span className="text-text-tertiary">{line.ts}</span>{' '}
                  {line.level && (
                    <span className={levelClass[line.level] || 'text-text-secondary'}>
                      {line.level}
                    </span>
                  )}{' '}
                  {line.logger && <span className="text-text-tertiary">[{line.logger}]</span>}{' '}
                  <span className="text-text-primary">{line.message}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </Card>

      {result?.path && (
        <p className="text-xs text-text-tertiary">
          {t('logs.readingFrom')} <code className="font-mono">{result.path}</code>
        </p>
      )}
    </div>
  )
}
