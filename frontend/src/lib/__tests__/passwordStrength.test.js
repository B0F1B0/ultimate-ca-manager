/**
 * The meter reports the server's verdict, not its own.
 *
 * The browser used to score a password by counting five properties. The
 * server (`security/password_policy.get_password_strength`) also weighs a
 * blacklist, repeated characters, sequential runs and how many distinct
 * characters were used, and the two disagreed on most passwords a person
 * actually types -- always with the browser reading higher:
 *
 *   Ab1!Ab1!      browser "strong"  server "fair"
 *   Tr0ub4dor&3   browser "strong"  server "good"
 *   aaaaaaaaaaaa  browser "fair"    server "weak"
 *
 * backend/tests/test_password_strength_contract.py is the other half.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../services/apiClient', () => ({
  apiClient: { post: vi.fn() },
}))

const { apiClient } = await import('../../services/apiClient')
const {
  barsForScore,
  fetchPasswordStrength,
  localPasswordStrength,
  STRENGTH_LEVELS,
} = await import('../passwordStrength')

afterEach(() => {
  vi.clearAllMocks()
})

describe('the verdict comes from the server', () => {
  it('reports what the endpoint returned', async () => {
    apiClient.post.mockResolvedValue({ data: { score: 50, level: 'fair', feedback: [] } })
    const result = await fetchPasswordStrength('Ab1!Ab1!')
    expect(apiClient.post).toHaveBeenCalledWith('/users/password-strength', {
      password: 'Ab1!Ab1!',
    })
    expect(result).toMatchObject({ score: 50, level: 'fair', offline: false })
  })

  it('does not upgrade a verdict the server refused to give', async () => {
    apiClient.post.mockResolvedValue({ data: { score: 20, level: 'weak', feedback: [] } })
    const result = await fetchPasswordStrength('aaaaaaaaaaaa')
    expect(result.level).toBe('weak')
  })

  it('asks nothing for an empty password', async () => {
    const result = await fetchPasswordStrength('')
    expect(apiClient.post).not.toHaveBeenCalled()
    expect(result.level).toBe('weak')
  })

  it('falls back to the local reading when the server cannot be reached', async () => {
    apiClient.post.mockRejectedValue(new Error('offline'))
    const result = await fetchPasswordStrength('Str0ng@Pass!XY')
    expect(result.offline).toBe(true)
  })

  it('falls back when the answer is not one it understands', async () => {
    apiClient.post.mockResolvedValue({ data: { score: 'lots', level: 'excellent' } })
    const result = await fetchPasswordStrength('Str0ng@Pass!XY')
    expect(result.offline).toBe(true)
    expect(STRENGTH_LEVELS).toContain(result.level)
  })
})

describe('the offline reading never promises more than it knows', () => {
  // It cannot see the blacklist, the repeated characters or the sequential
  // runs the server checks, so "strong" is not its to give.
  for (const password of [
    'Str0ng@Pass!XY',
    'Password123!',
    'Ab1!Ab1!',
    'Tr0ub4dor&3',
    'aaaaaaaaaaaaaaaaaaaa',
  ]) {
    it(`does not call ${password} strong`, () => {
      expect(localPasswordStrength(password).level).not.toBe('strong')
    })
  }

  it('still calls a short password weak', () => {
    expect(localPasswordStrength('x').level).toBe('weak')
  })

  it('only ever answers with a level the server also uses', () => {
    for (const password of ['', 'x', 'abcdefgh', 'Ab1!Ab1!', 'Str0ng@Pass!XY']) {
      expect(STRENGTH_LEVELS).toContain(localPasswordStrength(password).level)
    }
  })
})

describe('the bars follow the score', () => {
  it.each([
    [0, 0],
    [1, 1],
    [20, 1],
    [21, 2],
    [50, 3],
    [80, 4],
    [100, 5],
    [1000, 5],
  ])('paints %i as %i bars', (score, bars) => {
    expect(barsForScore(score)).toBe(bars)
  })

  it('never paints a bar for nothing typed', () => {
    expect(barsForScore(0)).toBe(0)
  })
})
