/**
 * The browser half of the `days_remaining` contract.
 *
 * `contracts/days_remaining_contract.json` says what a published number
 * means. `backend/tests/test_days_remaining_contract.py` holds the server to
 * publishing it; this holds the screens to reading it the same way.
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
  daysSinceExpiry,
  expiryBucket,
  expiryVariant,
  hasExpiry,
} from '../expiry'

const here = dirname(fileURLToPath(import.meta.url))
const contractPath = join(here, '..', '..', '..', '..', 'contracts', 'days_remaining_contract.json')
const contract = JSON.parse(readFileSync(contractPath, 'utf8'))

describe('expiryBucket agrees with the contract', () => {
  for (const { days_remaining: days, bucket } of contract.buckets) {
    it(`reads ${days} as ${bucket}`, () => {
      expect(expiryBucket(days)).toBe(bucket)
    })
  }

  it('reads a missing field the same way as an explicit null', () => {
    expect(expiryBucket(undefined)).toBe('none')
    expect(hasExpiry(undefined)).toBe(false)
    expect(hasExpiry(null)).toBe(false)
  })
})

describe('a row with no expiry date is not an expired one', () => {
  it('is not expired', () => {
    expect(expiryBucket(null)).not.toBe('expired')
  })

  it('does not claim a number of days since expiry', () => {
    expect(daysSinceExpiry(null)).toBe(0)
  })

  it('does not get the danger badge', () => {
    expect(expiryVariant(null)).toBe('secondary')
  })
})

describe('the instant of expiry', () => {
  it('counts zero as expired, not as expiring', () => {
    expect(expiryBucket(0)).toBe('expired')
    expect(expiryVariant(0)).toBe('danger')
  })

  it('counts one day left as expiring, not as expired', () => {
    expect(expiryBucket(1)).toBe('expiring')
    expect(expiryVariant(1)).toBe('warning')
  })
})

describe('a long-expired certificate says how long', () => {
  for (const { days_remaining: days, bucket } of contract.buckets) {
    if (bucket !== 'expired') continue
    it(`reports ${Math.abs(days)} days since expiry for ${days}`, () => {
      expect(daysSinceExpiry(days)).toBe(Math.abs(days))
    })
  }
})
