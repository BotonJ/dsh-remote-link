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
import { readFileSync } from 'node:fs'
import { proxyRequest, proxyUpgrade } from './proxy.js'
import { SESSION_COOKIE } from './auth.js'
import { attachLinkKeepalive } from './ws-keepalive.js'
import { createHostProbe } from './host-probe.js'
import { STATUS_PAGE_HTML } from './status-page.js'

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
  qrImage = null, qrPage = null,
  keepaliveIntervalMs = 25_000, pairingSnapshot = null,
  resolveDevice = null, tunnelHeartbeatFile = null,
  hostProbeIntervalMs = 30_000, notifySnapshot = null,
}) {
  const sockets = new Set()
  const legs = new Map() // leg id → { id, path, connectedAt, keepalive }
  let generation = 0
  const startedAt = Date.now()
  const recentUpstreamErrors = [] // bounded ring: { at, where, message }
  let lastUpstreamOkAt = null
  let server = null
  // Full-stack host telemetry (RPC probe + host event tap); non-DSH
  // upstreams turn this off themselves after a few 404s (host-probe.js).
  const hostProbe = createHostProbe({ target, intervalMs: hostProbeIntervalMs, log })

  /** Returns true when the request was a pairing endpoint and is fully handled. */
  function handlePairingRoute(req, res) {
    if (pairing === null && req.url.split('?', 1)[0] !== '/status' && req.url.split('?', 1)[0] !== '/status.json') return false
    const path = req.url.split('?', 1)[0]
    if (path !== '/pair' && path !== '/pair/' && path !== '/pair/challenge' && path !== '/pair/verify' && path !== '/pair/recover' && path !== '/qr.png' && path !== '/qr' && path !== '/status' && path !== '/status.json') return false

    // Local-only observability surface: same fence as the QR image — loopback
    // source AND no proxy chain, so tunneled clients never see link telemetry.
    if (path === '/status' || path === '/status.json') {
      const viaLoopback = LOOPBACK.test(clientIp(req))
      const viaProxy = req.headers['x-forwarded-for'] !== undefined
      if (!viaLoopback || viaProxy) {
        plainResponse(res, 403, {}, 'forbidden')
        return true
      }
      const payload = statusSnapshot()
      // Each status view nudges a fresh full-stack probe (fire-and-forget):
      // the page refreshes every 5s, so telemetry stays current without
      // waiting out the periodic interval.
      hostProbe.refresh().catch(() => {})
      if (path === '/status.json') {
        jsonResponse(res, 200, payload)
        return true
      }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
      res.end(STATUS_PAGE_HTML(payload))
      return true
    }

    // /qr.png exposes the LIVE pairing image — desktop chat only. Loopback
    // source AND no proxy chain: localtunnel forwards arrive on loopback
    // sockets but carry x-forwarded-for, so tunnelled requests never see it.
    if (path === '/qr.png' || path === '/qr') {
      const viaLoopback = LOOPBACK.test(clientIp(req))
      const viaProxy = req.headers['x-forwarded-for'] !== undefined
      if (!viaLoopback || viaProxy || typeof qrImage !== 'function') {
        plainResponse(res, 403, {}, 'forbidden')
        return true
      }
      if (path === '/qr' && typeof qrPage === 'function') {
        const html = qrPage()
        if (html !== null) {
          res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
          res.end(html)
          return true
        }
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

    // Pairing endpoints always rate-limit: an explicit tighter budget when
    // provided, else the general per-IP limiter (never unlimited).
    const budget = (pairLimiter ?? limiter).check(clientIp(req))
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
    // /pair/verify and /pair/recover — both mint device cookies.
    readBody(req, 4096)
      .then((text) => {
        let body = null
        try { body = JSON.parse(text) } catch { /* handled below */ }
        if (body === null || typeof body !== 'object') return jsonResponse(res, 400, { error: 'BAD_REQUEST' })
        const outcome = path === '/pair/recover' ? pairing.redeemRecovery(body) : pairing.verify(body)
        return Promise.resolve(outcome).then((result) => {
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

  /** Aggregated payload for the loopback status page/JSON. */
  function statusSnapshot() {
    const now = Date.now()
    const pairingInfo = pairingSnapshot?.() ?? null
    let tunnel = null
    if (tunnelHeartbeatFile !== null) {
      tunnel = { file: tunnelHeartbeatFile, available: false }
      try {
        // scripts/cf-tunnel.sh writes epoch SECONDS via `date +%s`
        const beat = Number(readFileSync(tunnelHeartbeatFile, 'utf8').trim())
        if (Number.isFinite(beat) && beat > 0) {
          const lastBeatAt = beat * 1000
          tunnel = { file: tunnelHeartbeatFile, available: true, lastBeatAt, ageMs: now - lastBeatAt }
        }
      } catch { /* missing/unreadable heartbeat stays "unavailable" */ }
    }
    return {
      uptimeMs: now - startedAt,
      generation,
      keepaliveIntervalMs,
      legs: [...legs.values()].map((leg) => ({
        id: leg.id,
        path: leg.path,
        ip: leg.ip,
        auth: leg.auth,
        deviceId: leg.deviceId,
        deviceName: leg.deviceName,
        connectedAt: leg.connectedAt,
        ageMs: now - leg.connectedAt,
        keepalive: leg.keepalive.stats(),
      })),
      upstream: {
        target: target(),
        lastOkAt: lastUpstreamOkAt,
        recentErrors: [...recentUpstreamErrors],
      },
      host: hostProbe.state(),
      tunnel,
      notify: notifySnapshot?.() ?? null,
      pairing: pairingInfo === null ? null : {
        shortCode: pairingInfo.shortCode,
        secondsLeft: Math.max(0, Math.round((pairingInfo.expiresAt - now) / 1000)),
      },
    }
  }

  /** Bounded ring of recent upstream failures for the status page. */
  function recordUpstreamError(where, error) {
    recentUpstreamErrors.push({ at: Date.now(), where, message: String(error?.message ?? error) })
    if (recentUpstreamErrors.length > 10) recentUpstreamErrors.shift()
    log(`gateway: ${where} error: ${String(error?.message ?? error)}`)
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
    proxyRequest(req, res, target(), (error) => recordUpstreamError('proxy', error), {
      onResponded: () => { lastUpstreamOkAt = Date.now() },
    })
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
    // Per-leg keepalive: ping the browser direction when idle so tunnel edges
    // and carrier NATs never reap a live but quiet event stream (see
    // ws-keepalive.js). The leg registers for the status page and unregisters
    // on teardown; identity comes from the auth verdict (pairing cookie →
    // device) plus the source IP.
    generation += 1
    const legId = generation
    const deviceId = decision.verdict?.deviceId ?? null
    const leg = {
      id: legId,
      path: req.url.split('?', 1)[0],
      ip: clientIp(req),
      auth: decision.verdict?.via ?? 'none',
      deviceId,
      deviceName: deviceId === null ? null : resolveDevice?.(deviceId) ?? null,
      connectedAt: Date.now(),
      keepalive: null,
    }
    legs.set(legId, leg)
    proxyUpgrade(req, socket, head, target(), (error) => recordUpstreamError('upgrade', error), {
      onEstablished: (downSocket, upstreamSocket, upstreamHead) => {
        leg.keepalive = attachLinkKeepalive(downSocket, upstreamSocket, {
          intervalMs: keepaliveIntervalMs,
          seedDown: head,
          seedUp: upstreamHead,
          log,
        })
        const drop = () => { legs.delete(legId); leg.keepalive?.dispose() }
        downSocket.on('close', drop)
        downSocket.on('error', drop)
        return drop
      },
    })
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
          server.on('error', (error) => log(`gateway: server error: ${String(error?.message ?? error)}`))
          hostProbe.start()
          log(`gateway: listening on ${host}:${server.address().port}`)
          resolve()
        })
      })
    },
    get port() {
      return server === null ? null : server.address()?.port ?? null
    },
    /** Live WS legs (phone/desktop browsers). Drives the offline-notify
     * policy: interactions with nobody connected are worth a push. */
    activeLegCount() {
      return legs.size
    },
    close() {
      hostProbe.close()
      if (server === null) return Promise.resolve()
      for (const socket of sockets) socket.destroy()
      return new Promise((resolve) => {
        server.close(() => { server = null; resolve() })
        server.closeAllConnections?.()
      })
    },
  }
}
