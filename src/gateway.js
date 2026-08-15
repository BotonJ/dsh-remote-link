/**
 * The authenticated LAN gateway: an HTTP server on its own port that fronts
 * the loopback DSH webserver (official web UI static assets, /api RPC, and
 * the /api/events.* WebSocket upgrades).
 *
 * Request path per client IP:
 *   banned (auth brute-force) → 429
 *   over rate budget          → 429
 *   failed credentials        → 401 (+ failure counter)
 *   valid                     → proxied
 * WebSocket upgrades run the same gates and answer with a raw HTTP status
 * line, since a WS client cannot render an error body.
 */

import { createServer } from 'node:http'
import { proxyRequest, proxyUpgrade } from './proxy.js'

const REALM = 'dsh-remote-link'

function clientIp(req) {
  const raw = req.socket?.remoteAddress ?? 'unknown'
  return raw.startsWith('::ffff:') ? raw.slice(7) : raw
}

function plainResponse(res, status, headers, body) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...headers })
  res.end(body)
}

function socketResponse(socket, status, reason, headers = {}) {
  const headerBlock = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join('')
  socket.end(`HTTP/1.1 ${status} ${reason}\r\n${headerBlock}Connection: close\r\n\r\n`)
}

export function createGateway({ auth, limiter, failureBan, target, log = () => {} }) {
  const sockets = new Set()
  let server = null

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
    const decision = gate(req)
    if (!decision.allowed) {
      if (decision.status === 429) {
        return plainResponse(res, 429, { 'retry-after': String(Math.max(1, Math.ceil(decision.retryAfterMs / 1000))) }, 'slow down')
      }
      return plainResponse(res, 401, { 'www-authenticate': `Basic realm="${REALM}"` }, 'unauthorized')
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
