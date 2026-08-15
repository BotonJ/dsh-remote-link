/**
 * The authenticated LAN gateway: an HTTP server on its own port that fronts
 * the loopback DSH webserver (official web UI static assets, /api RPC, and
 * the /api/events.* WebSocket upgrades).
 *
 * Request path per client IP:
 *   /pair*                    → pairing endpoints (own tight rate budget)
 *   banned (auth brute-force) → 429
 *   over rate budget          → 429
 *   failed credentials        → 401 (+ failure counter)
 *   valid                     → proxied
 * WebSocket upgrades run the same gates and answer with a raw HTTP status
 * line, since a WS client cannot render an error body.
 */

import { createServer } from 'node:http'
import { proxyRequest, proxyUpgrade } from './proxy.js'
import { SESSION_COOKIE } from './auth.js'

const REALM = 'dsh-remote-link'
const LOOPBACK = /^(127\.0\.0\.1|::1|localhost)$/

function clientIp(req) {
  const raw = req.socket?.remoteAddress ?? 'unknown'
  return raw.startsWith('::ffff:') ? raw.slice(7) : raw
}

function plainResponse(res, status, headers, body) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...headers })
  res.end(body)
}

function jsonResponse(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers })
  res.end(JSON.stringify(body))
}

function socketResponse(socket, status, reason, headers = {}) {
  const headerBlock = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join('')
  socket.end(`HTTP/1.1 ${status} ${reason}\r\n${headerBlock}Connection: close\r\n\r\n`)
}

function readBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > limitBytes) { reject(new Error('body too large')); req.destroy(); return }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

export function createGateway({
  auth, limiter, failureBan, target, log = () => {},
  pairing = null, pairingPage = '', pairLimiter = null, cookieMaxAgeSeconds = 30 * 86_400,
  qrImage = null,
}) {
  const sockets = new Set()
  let server = null

  /** Returns true when the request was a pairing endpoint and is fully handled. */
  function handlePairingRoute(req, res) {
    if (pairing === null) return false
    const path = req.url.split('?', 1)[0]
    if (path !== '/pair' && path !== '/pair/' && path !== '/pair/challenge' && path !== '/pair/verify' && path !== '/qr.png') return false

    // /qr.png exposes the LIVE pairing image — desktop chat only. Loopback
    // source AND no proxy chain: localtunnel forwards arrive on loopback
    // sockets but carry x-forwarded-for, so tunnelled requests never see it.
    if (path === '/qr.png') {
      const viaLoopback = LOOPBACK.test(clientIp(req))
      const viaProxy = req.headers['x-forwarded-for'] !== undefined
      if (!viaLoopback || viaProxy || typeof qrImage !== 'function') {
        plainResponse(res, 403, {}, 'forbidden')
        return true
      }
      const png = qrImage()
      if (png === null) {
        plainResponse(res, 404, {}, 'no pairing')
        return true
      }
      res.writeHead(200, { 'content-type': 'image/png', 'cache-control': 'no-store' })
      res.end(png)
      return true
    }

    const budget = pairLimiter.check(clientIp(req))
    if (!budget.allowed) {
      plainResponse(res, 429, { 'retry-after': String(Math.max(1, Math.ceil(budget.retryAfterMs / 1000))) }, 'slow down')
      return true
    }

    if (path === '/pair' || path === '/pair/') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(pairingPage)
      return true
    }
    if (path === '/pair/challenge') {
      const query = new URL(req.url, 'http://pairing.local').searchParams
      const sidOrCode = query.get('sid') ?? query.get('code')
      const challenge = sidOrCode !== null && sidOrCode.length > 0 ? pairing.challenge(sidOrCode) : null
      jsonResponse(res, challenge === null ? 404 : 200, challenge ?? { error: 'PAIRING_NOT_FOUND' })
      return true
    }
    // /pair/verify
    readBody(req, 4096)
      .then((text) => {
        let body = null
        try { body = JSON.parse(text) } catch { /* handled below */ }
        if (body === null || typeof body !== 'object') return jsonResponse(res, 400, { error: 'BAD_REQUEST' })
        return pairing.verify(body).then((result) => {
          if (result.ok !== true) return jsonResponse(res, 401, { error: result.error })
          jsonResponse(res, 200, { deviceId: result.deviceId }, {
            'set-cookie': `${SESSION_COOKIE}=${result.sessionToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${cookieMaxAgeSeconds}`,
          })
        })
      })
      .catch(() => jsonResponse(res, 400, { error: 'BAD_REQUEST' }))
    return true
  }

  function gate(req) {
    const ip = clientIp(req)
    const ban = failureBan.isBanned(ip)
    if (ban.banned) return { allowed: false, status: 429, retryAfterMs: ban.retryAfterMs, reason: 'banned' }
    const budget = limiter.check(ip)
    if (!budget.allowed) return { allowed: false, status: 429, retryAfterMs: budget.retryAfterMs, reason: 'rate-limited' }
    const verdict = auth.check(req)
    if (!verdict.ok) {
      failureBan.recordFailure(ip)
      return { allowed: false, status: 401, reason: 'unauthorized' }
    }
    failureBan.recordSuccess(ip)
    return { allowed: true, verdict }
  }

  function onRequest(req, res) {
    if (handlePairingRoute(req, res)) return
    const decision = gate(req)
    if (!decision.allowed) {
      if (decision.status === 429) {
        return plainResponse(res, 429, { 'retry-after': String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000))) }, 'slow down')
      }
      // Only advertise Basic when it is actually enabled; cookie-only mode
      // must not pop a browser auth dialog.
      const challenge = auth.basicEnabled ? { 'www-authenticate': `Basic realm="${REALM}"` } : {}
      return plainResponse(res, 401, challenge, 'unauthorized')
    }
    proxyRequest(req, res, target(), (error) => log(`gateway: proxy error: ${String(error?.message ?? error)}`))
  }

  function onUpgrade(req, socket, head) {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    const decision = gate(req)
    if (!decision.allowed) {
      if (decision.status === 429) {
        return socketResponse(socket, 429, 'Too Many Requests', { 'retry-after': String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000))) })
      }
      return socketResponse(socket, 401, 'Unauthorized', { 'www-authenticate': `Basic realm="${REALM}"` })
    }
    proxyUpgrade(req, socket, head, target(), (error) => log(`gateway: upgrade error: ${String(error?.message ?? error)}`))
  }

  return {
    listen({ host, port } = {}) {
      if (server !== null) return Promise.resolve()
      return new Promise((resolve, reject) => {
        server = createServer(onRequest)
        server.on('upgrade', onUpgrade)
        server.on('connection', (socket) => {
          sockets.add(socket)
          socket.on('close', () => sockets.delete(socket))
        })
        server.on('clientError', (err, socket) => socketResponse(socket, 400, 'Bad Request'))
        server.on('error', reject)
        server.listen(port, host, () => {
          server.removeListener('error', reject)
          server.on('error', (error) => log(`gateway: server error: ${String(error)}`))
          log(`gateway: listening on ${host}:${server.address().port}`)
          resolve()
        })
      })
    },
    get port() {
      return server === null ? null : server.address()?.port ?? null
    },
    close() {
      if (server === null) return Promise.resolve()
      for (const socket of sockets) socket.destroy()
      return new Promise((resolve) => {
        server.close(() => { server = null; resolve() })
        server.closeAllConnections?.()
      })
    },
  }
}
