/**
 * Three services built their query string by hand instead of going through
 * `buildQueryString` (DUP-FE-004), and each hand-rolled filter diverged from it
 * on a different input:
 *
 *   - deploy.service filtered on `v != null`, which keeps the empty string, so
 *     an unset filter went to the wire as `target_id=` and the server filtered
 *     on an empty value instead of not filtering at all;
 *   - the same filter comma-joined arrays (`status=pending,failed`), which
 *     Flask's `request.args.getlist` reads as one value that matches nothing,
 *     where buildQueryString repeats the key;
 *   - settings.service put its arguments straight into URLSearchParams, so an
 *     explicit `null` was stringified and `per_page=null` was sent.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

const get = vi.fn().mockResolvedValue({ data: [] })
vi.mock('../apiClient', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, apiClient: { ...actual.apiClient, get: (...a) => get(...a) } }
})

const { deployService } = await import('../deploy.service')
const settingsServiceModule = await import('../settings.service')
const settingsService = settingsServiceModule.settingsService || settingsServiceModule.default

const urlOf = () => get.mock.calls.at(-1)[0]

beforeEach(() => get.mockClear())

describe('deploy.service — bindings', () => {
  it('omits an empty filter instead of sending it as an empty value', async () => {
    await deployService.getBindings({ certificate_id: 5, target_id: '' })
    expect(urlOf()).toBe('/deploy/bindings?certificate_id=5')
    expect(urlOf()).not.toContain('target_id=')
  })

  it('repeats the key for an array rather than comma-joining it', async () => {
    await deployService.getBindings({ status: ['pending', 'failed'] })
    expect(urlOf()).toBe('/deploy/bindings?status=pending&status=failed')
  })

  it('drops null and undefined', async () => {
    await deployService.getBindings({ a: null, b: undefined, c: 1 })
    expect(urlOf()).toBe('/deploy/bindings?c=1')
  })

  it('keeps a falsy-but-meaningful value', async () => {
    await deployService.getBindings({ enabled: false, count: 0 })
    expect(urlOf()).toBe('/deploy/bindings?enabled=false&count=0')
  })

  it('sends no query at all when nothing survives filtering', async () => {
    await deployService.getBindings({ a: '', b: null })
    expect(urlOf()).toBe('/deploy/bindings')
  })
})

describe('deploy.service — deliveries', () => {
  it('omits an empty filter', async () => {
    await deployService.getDeliveries({ binding_id: 3, status: '' })
    expect(urlOf()).toBe('/deploy/deliveries?binding_id=3')
  })

  it('repeats the key for an array', async () => {
    await deployService.getDeliveries({ status: ['sent', 'failed'] })
    expect(urlOf()).toBe('/deploy/deliveries?status=sent&status=failed')
  })
})

describe('settings.service — webhook deliveries', () => {
  it('does not stringify an explicit null into per_page', async () => {
    await settingsService.getWebhookDeliveries(1, { perPage: null })
    expect(urlOf()).not.toContain('per_page=null')
  })

  it('still sends the defaults', async () => {
    await settingsService.getWebhookDeliveries(1)
    expect(urlOf()).toBe('/webhooks/1/deliveries?page=1&per_page=25')
  })

  it('passes the status filter through', async () => {
    await settingsService.getWebhookDeliveries(1, { page: 2, perPage: 50, status: 'failed' })
    expect(urlOf()).toBe('/webhooks/1/deliveries?page=2&per_page=50&status=failed')
  })

  it('never emits a bare question mark', async () => {
    await settingsService.getWebhookDeliveries(1, { page: null, perPage: null })
    expect(urlOf()).not.toMatch(/\?$/)
  })
})
