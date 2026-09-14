/**
 * `constants/config.js` carried eleven blocks nobody imported, three of whose
 * values disagreed with the backend (DUP-FE-018). Dead constants are not a bug
 * until someone adopts them, at which point all three become one — so this
 * test keeps the module down to what a call site actually reads.
 *
 * Adding an export here without a consumer fails. That is the point: pair it
 * with its call site, and check the value against the backend default it
 * mirrors.
 */
import { describe, it, expect } from 'vitest'
import fs from 'fs'
import path from 'path'
import * as config from '../config'

const SRC = path.resolve(__dirname, '../..')

function sourceFiles(dir, acc = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'constants') continue
      sourceFiles(full, acc)
    } else if (/\.jsx?$/.test(entry.name)) {
      acc.push(full)
    }
  }
  return acc
}

describe('constants/config', () => {
  it('exports nothing that no source file reads', () => {
    const sources = sourceFiles(SRC).map((f) => fs.readFileSync(f, 'utf8')).join('\n')
    const orphans = Object.keys(config).filter(
      (name) => !new RegExp(`\\b${name}\\b`).test(sources)
    )
    expect(
      orphans,
      `Unused exports — delete them, or wire them to the call site that needs them:\n  ${orphans.join('\n  ')}`
    ).toEqual([])
  })

  it('has no barrel re-exporting it, since nothing imported the barrel', () => {
    expect(fs.existsSync(path.join(SRC, 'constants', 'index.js'))).toBe(false)
  })

  it('keeps the default CSR validity aligned with the issuance forms', () => {
    // IssueCertificateForm and OperationsPage both hardcode '365'.
    expect(config.VALIDITY.DEFAULT_DAYS).toBe(365)
  })
})
