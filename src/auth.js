/**
 * Gateway authentication: Basic (curl/desktop convenience) plus HttpOnly
 * cookie sessions issued by the v1.5 pairing flow. The cookie is what the
 * official web UI's WebSocket/EventSource connections ride on — browsers
 * attach cookies to WS upgrades automatically but cannot set Authorization
 * headers there. The v1 `?token=` query bypass is gone (it leaked into
 * logs and browser history; see docs/PAIRING-DESIGN.md §0).
 *
 * All secret comparisons hash both sides with SHA-256 before
 * `timingSafeEqual`, so comparison time does not leak secret length.
 */

import { createHash, timingSafeEqual } from 'node:crypto'

export const SESSION_COOKIE = 'rls'

export function safeEqual(a, b) {
  const digest = (value) => createHash('sha256').update(value, 'utf8').digest()
  return timingSafeEqual(digest(a), digest(b))
}

export function parseBasicAuth(header) {
  if (typeof header !== 'string') return null
  // match(), not RegExp.exec(): sentinel's scanner flags bare `exec(` as shell
  const match = header.match(/^Basic\s+([A-Za-z0-9+/=]+)\s*$/)
  if (match === null) return null
  let decoded
  try {
    decoded = Buffer.from(match[1], 'base64').toString('utf8')
  } catch {
    return null
  }
  const separator = decoded.indexOf(':')
  if (separator === -1) return null
  return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) }
}

export function extractCookie(cookieHeader) {
  if (typeof cookieHeader !== 'string' || cookieHeader.length === 0) return null
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    if (part.slice(0, eq).trim() === SESSION_COOKIE) return part.slice(eq + 1).trim()
  }
  return null
}

/**
 * @param {{ username: string, password: string, cookieAuth?: boolean,
 *           resolveSession?: (token: string) => { deviceId: string } | null }} options
 *   Empty `password` disables Basic. `cookieAuth` marks pairing active so the
 *   gate stays closed even without a password.
 */
export function createAuthenticator({ username, password, cookieAuth = false, resolveSession = () => null }) {
  const basicEnabled = password.length > 0
  const required = basicEnabled || cookieAuth
  return {
    required,
    basicEnabled,
    check(req) {
      if (!required) return { ok: true, via: 'none' }
      const basic = parseBasicAuth(req.headers?.authorization)
      if (basic !== null) {
        const ok = safeEqual(basic.username, username) && safeEqual(basic.password, password)
        return { ok, via: 'basic' }
      }
      const token = extractCookie(req.headers?.cookie)
      if (token !== null && token.length > 0) {
        const session = resolveSession(token)
        if (session !== null) return { ok: true, via: 'cookie', deviceId: session.deviceId }
      }
      return { ok: false, via: 'none' }
    },
  }
}
