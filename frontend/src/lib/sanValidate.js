/**
 * Client-side SAN validation (mirrors backend utils/san_parse.py).
 * Returns i18n key + params, or null if valid.
 */

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

function normalizeSanType(type) {
  const map = {
    dns: 'DNS',
    ip: 'IP',
    email: 'Email',
    uri: 'URI',
    upn: 'UPN',
  }
  const raw = (type || '').trim()
  return map[raw.toLowerCase()] || raw.toUpperCase()
}

function looksLikeIpv4(v) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)
}

function looksLikeIpv6(v) {
  // IPv6 must contain at least one ':' and no scheme separator.
  // Exclude URIs (e.g. https://host) which also contain ':'.
  if (v.includes('://')) return false
  return /^[0-9a-fA-F:]+$/.test(v) && v.includes(':')
}

function looksLikeIp(v) {
  return looksLikeIpv4(v) || looksLikeIpv6(v)
}

function isValidEmail(v) {
  return EMAIL_RE.test(v)
}

function isValidUri(v) {
  // Backend (utils/san_parse.py) accepts any RFC 3986 scheme via urlparse,
  // including authority-less URIs (urn:, mailto:, did:) — mirror that here.
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:.+/.test(v)
}

function isValidUpn(v) {
  const parts = v.split('@')
  return parts.length === 2 && parts[0] && parts[1]
}

/** CN is an RFC822 address — not a DNS hostname. */
export function isCnEmail(cn) {
  return isValidEmail((cn || '').trim())
}

// A hostname label, as the backend defines one (utils/san_parse.py):
// letters, digits, hyphen never at an edge, plus underscore.
const HOSTNAME_LABEL = /^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$/

/** Hostname shape — ASCII only, since x509.DNSName refuses a U-label. */
export function looksLikeHostname(value) {
  let v = (value || '').trim()
  if (!v || v.length > 253) return false
  if (v.startsWith('*.')) v = v.slice(2)
  if (v.endsWith('.')) v = v.slice(0, -1)
  if (!v.includes('.')) return false
  return v.split('.').every((label) => HOSTNAME_LABEL.test(label))
}

/** FQDN / wildcard — excludes email and literal IP.
 *  Mirrors backend cn_looks_like_hostname: this used to be `v.includes('.')`,
 *  which previewed a DNS SAN for `Example, Inc.` that the backend then wrote
 *  into the certificate verbatim. */
export function isCnHostname(cn) {
  const v = (cn || '').trim()
  if (!v || isCnEmail(v)) return false
  if (looksLikeIp(v)) return false
  return looksLikeHostname(v)
}

/** Literal IP suitable for IP SAN when used as CN. */
export function isCnIp(cn) {
  return looksLikeIp((cn || '').trim())
}

/**
 * Auto-included SAN rows for Issue Certificate (mirrors backend auto_san_buckets_from_cn).
 * @returns {{ type: string, value: string }[]}
 */
export function getAutoSansFromCn({ cn, certType, subjectEmail }) {
  const value = (cn || '').trim()
  if (!value) return []

  const items = []
  const type = certType || 'server'

  if (['server', 'combined'].includes(type)) {
    if (isCnHostname(value)) {
      items.push({ type: 'dns', value })
    } else if (isCnIp(value)) {
      items.push({ type: 'ip', value })
    }
  }
  if (['email', 'combined'].includes(type) && isCnEmail(value)) {
    items.push({ type: 'email', value })
  }

  const subj = (subjectEmail || '').trim()
  if (
    ['email', 'combined'].includes(type)
    && subj
    && isCnEmail(subj)
    && subj !== value
    && !items.some((s) => s.type === 'email' && s.value === subj)
  ) {
    items.push({ type: 'email', value: subj })
  }

  return items
}

/**
 * @param {'DNS'|'IP'|'Email'|'URI'|'UPN'|string} type
 * @param {string} value
 * @param {{ i18nNs?: 'csrs' | 'certificates' }} [options]
 * @returns {{ key: string, params?: object } | null}
 */
export function getSanValidationError(type, value, options = {}) {
  const i18nNs = options.i18nNs || 'csrs'
  const key = (name) => `${i18nNs}.${name}`
  const v = (value || '').trim()
  if (!v) return null

  switch (normalizeSanType(type)) {
    case 'IP':
      if (!looksLikeIp(v)) {
        return { key: key('sanFqdnUseDns'), params: { value: v } }
      }
      return null
    case 'DNS':
      if (v.includes('://')) {
        return { key: key('sanUriUseUri'), params: { value: v } }
      }
      if (looksLikeIp(v)) {
        return { key: key('sanIpForAddress'), params: { value: v } }
      }
      if (v.includes('@')) {
        return { key: key('sanEmailUseEmail'), params: { value: v } }
      }
      return null
    case 'Email':
      if (!isValidEmail(v)) {
        return v.includes('@')
          ? { key: key('sanEmailInvalid'), params: { value: v } }
          : { key: key('sanHostnameUseDns'), params: { value: v } }
      }
      return null
    case 'URI':
      if (!isValidUri(v)) {
        return { key: key('sanUriInvalid'), params: { value: v } }
      }
      return null
    case 'UPN':
      if (!isValidUpn(v)) {
        return { key: key('sanUpnInvalid'), params: { value: v } }
      }
      return null
    default:
      return null
  }
}
