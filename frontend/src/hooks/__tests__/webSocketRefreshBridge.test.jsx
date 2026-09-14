/**
 * A change made elsewhere refreshes the table, not just the toast.
 *
 * The pages listen on the in-app `ucm:data-changed` bus, which only the
 * acting tab fired. A second operator saw the revocation toast beside a list
 * that still showed the certificate as valid until a manual reload.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, act } from '@testing-library/react'

const socketHandlers = new Map()
const fakeSocket = {
  on: (evt, cb) => { socketHandlers.set(evt, cb) },
  emit: vi.fn(),
  disconnect: vi.fn(),
  connected: false,
}
vi.mock('socket.io-client', () => ({ io: vi.fn(() => fakeSocket) }))

vi.mock('../../contexts/NotificationContext', () => ({
  useNotification: () => ({
    showSuccess: vi.fn(), showError: vi.fn(),
    showWarning: vi.fn(), showInfo: vi.fn(),
  }),
  NotificationProvider: ({ children }) => children,
}))
vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ isAuthenticated: true }),
  AuthProvider: ({ children }) => children,
}))

import { WebSocketProvider, EventType } from '../useWebSocket'

function emit(payload) {
  render(<WebSocketProvider><div /></WebSocketProvider>)
  const onEvent = socketHandlers.get('event')
  const seen = []
  const listener = (e) => seen.push(e.detail?.type)
  window.addEventListener('ucm:data-changed', listener)
  act(() => { onEvent(payload) })
  window.removeEventListener('ucm:data-changed', listener)
  return seen
}

describe('the socket announces the change on the refresh bus', () => {
  beforeEach(() => socketHandlers.clear())

  it.each([
    [EventType.CERTIFICATE_REVOKED, 'certificate'],
    [EventType.CERTIFICATE_ISSUED, 'certificate'],
    [EventType.CERTIFICATE_DELETED, 'certificate'],
    [EventType.CA_CREATED, 'ca'],
    [EventType.CA_DELETED, 'ca'],
    [EventType.CRL_REGENERATED, 'ca'],
    [EventType.USER_CREATED, 'user'],
    [EventType.GROUP_DELETED, 'group'],
  ])('%s refreshes the %s pages', (type, resource) => {
    expect(emit({ type, data: {} })).toEqual([resource])
  })

  it('says nothing for an event that changes no table', () => {
    expect(emit({ type: EventType.USER_LOGIN, data: {} })).toEqual(['user'])
    expect(emit({ type: 'nope.nope', data: {} })).toEqual([])
    expect(emit({ type: EventType.SYSTEM_ALERT, data: {} })).toEqual([])
  })
})

describe('a reconnection refreshes what it may have missed', () => {
  beforeEach(() => socketHandlers.clear())

  it('says nothing on the first connection', () => {
    render(<WebSocketProvider><div /></WebSocketProvider>)
    const seen = []
    const listener = (e) => seen.push(e.detail?.type)
    window.addEventListener('ucm:data-changed', listener)
    act(() => { socketHandlers.get('connect')() })
    window.removeEventListener('ucm:data-changed', listener)
    expect(seen).toEqual([])
  })

  it('refreshes every table after the socket comes back', () => {
    render(<WebSocketProvider><div /></WebSocketProvider>)
    act(() => { socketHandlers.get('connect')() })
    act(() => { socketHandlers.get('disconnect')('transport close') })

    const seen = []
    const listener = (e) => seen.push(e.detail?.type)
    window.addEventListener('ucm:data-changed', listener)
    act(() => { socketHandlers.get('connect')() })
    window.removeEventListener('ucm:data-changed', listener)

    // Events sent while it was down are gone; the tables reload instead.
    expect(new Set(seen)).toEqual(new Set(['certificate', 'ca', 'user', 'group']))
  })
})
