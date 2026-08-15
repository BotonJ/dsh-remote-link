/**
 * Gateway authentication: HTTP Basic plus a `?token=` query bypass.
 *
 * The token bypass exists because the browser WebSocket and EventSource APIs
 * cannot set an Authorization header — the official web UI's event streams
 * (WS upgrades to /api/events.*) would be impossible to authorize from a phone
 * without it. MiMo's mobile server solves this the same way.
 *
 * All secret comparisons hash both sides with SHA-256 before
 * `timingSafeEqual`, so comparison time does not leak secret length.
 */

import { createHash, timingSafeEqual } from 'node:crypto'

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

export function extractToken(url) {
  if (typeof url !== 'string' || url.length === 0) return null
  try {
    return new URL(url, 'http://gateway.local').searchParams.get('token')
  } catch {
    return null
  }
}

/**
 * @param {{ username: string, password: string }} credentials
 *   Empty `password` disables authentication entirely (loopback-only binds).
 * @returns {{ required: boolean, check(req: { headers: object, url: string }): { ok: boolean, via: 'basic'|'token'|'none' } }}
 */
export function createAuthenticator({ username, password }) {
  const required = password.length > 0
  return {
    required,
    check(req) {
      if (!required) return { ok: true, via: 'none' }
      const basic = parseBasicAuth(req.headers?.authorization)
      if (basic !== null) {
        const ok = safeEqual(basic.username, username) && safeEqual(basic.password, password)
        return { ok, via: 'basic' }
      }
      const token = extractToken(req.url)
      if (token !== null && token.length > 0) {
        return { ok: safeEqual(token, password), via: 'token' }
      }
      return { ok: false, via: 'none' }
    },
  }
}
