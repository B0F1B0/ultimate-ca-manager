/**
 * The format→extension table, now held once (DUP-FE-007).
 *
 * Four handlers carried their own copy and they had already drifted: one knew
 * pfx, one stopped at pkcs7, two fell back to "pem" for anything unlisted —
 * so the same JKS or key-only export could land under a different name
 * depending on which surface started it.
 */
import { describe, expect, it, vi } from 'vitest'

const downloadBlob = vi.hoisted(() => vi.fn())
vi.mock('../utils', () => ({ downloadBlob }))

import { downloadExport, exportFileName, EXPORT_EXTENSIONS } from '../exportDownload'

describe('exportFileName', () => {
  it('covers every format ExportModal can ask for', () => {
    // Mirrors the FORMATS table in components/ExportModal.jsx.
    const offered = ['pem', 'der', 'pkcs7', 'pkcs12', 'jks', 'key']
    offered.forEach(format => expect(EXPORT_EXTENSIONS[format]).toBeTruthy())
    expect(exportFileName('web.example.com', 'pkcs7')).toBe('web.example.com.p7b')
    expect(exportFileName('web.example.com', 'pkcs12')).toBe('web.example.com.p12')
    expect(exportFileName('web.example.com', 'jks')).toBe('web.example.com.jks')
    expect(exportFileName('web.example.com', 'key')).toBe('web.example.com.key')
  })

  it('keeps an unlisted format as its own extension rather than renaming it', () => {
    expect(exportFileName('web.example.com', 'p7c')).toBe('web.example.com.p7c')
  })
})

describe('downloadExport', () => {
  it('saves a Blob answer under the resolved name', async () => {
    downloadBlob.mockClear()
    const blob = new Blob(['pem'])
    await downloadExport(Promise.resolve(blob), { format: 'pem', name: 'web' })
    expect(downloadBlob).toHaveBeenCalledWith(blob, 'web.pem')
  })

  it('wraps an envelope answer instead of writing [object Object]', async () => {
    downloadBlob.mockClear()
    await downloadExport(Promise.resolve({ data: 'raw-pem' }), { format: 'der', name: 'web' })
    const [saved, filename] = downloadBlob.mock.calls[0]
    expect(filename).toBe('web.der')
    expect(saved).toBeInstanceOf(Blob)
    // "[object Object]" would be 15 bytes; the payload itself is 7.
    expect(saved.size).toBe('raw-pem'.length)
  })

  it('lets the failure reach the caller so the page can say so', async () => {
    downloadBlob.mockClear()
    const boom = new Error('403')
    await expect(
      downloadExport(Promise.reject(boom), { format: 'pem', name: 'web' })
    ).rejects.toThrow('403')
    expect(downloadBlob).not.toHaveBeenCalled()
  })
})
