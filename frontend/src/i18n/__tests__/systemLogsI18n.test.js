import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const dir = dirname(fileURLToPath(import.meta.url))
const localesDir = join(dir, '..', 'locales')
const LOCALE_CODES = ['de', 'en', 'es', 'fr', 'it', 'ja', 'pt', 'uk', 'zh']
const LOG_KEYS = ['subtitle', 'level', 'lines', 'searchPlaceholder', 'empty',
  'unavailable', 'truncated', 'readingFrom', 'source', 'sourceApp', 'sourceAccess',
  'sourceError', 'sourceJournal', 'component', 'follow', 'time', 'message', 'levelShort', 'from', 'to', 'serverTime', 'errors', 'warnings', 'components', 'allLevels', 'copyAll', 'copySelected']

function loadLocale(code) {
  return JSON.parse(readFileSync(join(localesDir, `${code}.json`), 'utf8'))
}

describe('system logs i18n keys (9 locales)', () => {
  for (const code of LOCALE_CODES) {
    it(`${code}: the nav label is defined`, () => {
      const value = loadLocale(code).common?.systemLogs
      expect(value, `missing common.systemLogs in ${code}`).toBeTruthy()
      expect(String(value).trim().length).toBeGreaterThan(2)
    })

    it(`${code}: every page key is defined`, () => {
      const bundle = loadLocale(code).logs
      expect(bundle, `missing logs namespace in ${code}`).toBeTruthy()
      for (const key of LOG_KEYS) {
        expect(bundle[key], `missing logs.${key} in ${code}`).toBeTruthy()
      }
    })
  }

  it('no locale was left on the English string', () => {
    const english = loadLocale('en')
    for (const code of LOCALE_CODES.filter((c) => c !== 'en')) {
      expect(loadLocale(code).common.systemLogs,
        `${code} still carries the English nav label`).not.toBe(english.common.systemLogs)
    }
  })
})
