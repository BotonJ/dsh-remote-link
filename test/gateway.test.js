import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { connect as tcpConnect } from 'node:net'
import { createHmac } from 'node:crypto'
import { createGateway } from '../src/gateway.js'
import { createPairingService } from '../src/pairing.js'
import { PAIRING_PAGE_HTML } from '../src/pairing-page.js'

function startUpstream() {
  const seen = []
  const upgradedSockets = new Set() // Node never releases upgraded sockets on server.close by itself
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, host: req.headers.host, body: Buffer.concat(chunks).toString() })
      if (req.url.startsWith('/api/')) {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: true, path: req.url }))
      } else {
        res.writeHead(200, { 'content-type': 'text/html' })
        res.end('<html>official ui</html>')
      }
    })
  })
  server.on('upgrade', (req, socket) => {
    upgradedSockets.add(socket)
    socket.on('close', () => upgradedSockets.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.on('data', (chunk) => socket.write(chunk)) // raw echo over the upgraded pipe
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen, upgradedSockets }))
  })
}

function startGateway(upstream, overrides = {}) {
  const pairing = overrides.pairing ?? null
  const gateway = createGateway({
    auth: overrides.auth ?? authWith({
      username: 'dsh', password: 's3cret',
      cookieAuth: pairing !== null,
      resolveSession: pairing === null ? () => null : (token) => pairing.resolveSession(token),
    }),
    limiter: overrides.limiter ?? limiterWith({ windowMs: 60_000, max: 1000 }),
    failureBan: overrides.failureBan ?? banWith({ windowMs: 60_000, max: 1000, banMs: 60_000 }),
    target: () => ({ host: '127.0.0.1', port: upstream.port }),
    log: () => {},
    pairing,
    pairingPage: PAIRING_PAGE_HTML,
    pairLimiter: overrides.pairLimiter ?? limiterWith({ windowMs: 60_000, max: 1000 }),
    cookieMaxAgeSeconds: 30 * 86_400,
    // These tests assert on the upstream's recorded traffic; the host probe's
    // own /api requests would pollute `seen`. Telemetry has its own suite.
    hostProbeIntervalMs: 0,
    ...overrides.gateway,
  })
  return gateway.listen({ host: '127.0.0.1', port: 0 }).then(() => gateway)
}

function pairingService() {
  const store = { load: () => [], save() {} }
  return createPairingService({ store, ttlMs: 300_000 })
}

const proofFor = (secret, sid, nonce, ts) =>
  createHmac('sha256', Buffer.from(secret, 'utf8')).update(`${sid}|${nonce}|${ts}`, 'utf8').digest('hex')

async function completePairing(gateway, service) {
  const p = service.createPairing()
  const challenge = await (await fetch(`http://127.0.0.1:${gateway.port}/pair/challenge?sid=${encodeURIComponent(p.sid)}`)).json()
  const proof = proofFor(p.secret, challenge.sid, challenge.nonce, challenge.ts)
  return {
    p,
    verify: await fetch(`http://127.0.0.1:${gateway.port}/pair/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sid: challenge.sid, ts: challenge.ts, proof }),
    }),
  }
}

// tiny local factories so the integration tests do not depend on unit-test doubles
import { createAuthenticator } from '../src/auth.js'
import { createRateLimiter, createFailureBan } from '../src/ratelimit.js'
const authWith = createAuthenticator
const limiterWith = createRateLimiter
const banWith = createFailureBan

const basic = (u, p) => `Basic ${Buffer.from(`${u}:${p}`).toString('base64')}`

test('unauthenticated requests get 401 with a Basic challenge; credentials pass through to the official UI', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream)
  try {
    const denied = await fetch(`http://127.0.0.1:${gw.port}/`)
    assert.equal(denied.status, 401)
    assert.match(denied.headers.get('www-authenticate'), /Basic/)

    const ok = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: { authorization: basic('dsh', 's3cret') } })
    assert.equal(ok.status, 200)
    assert.equal(await ok.text(), '<html>official ui</html>')
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('GET /pair serves the pairing page without authentication', async () => {
  const upstream = await startUpstream()
  const service = pairingService()
  const gw = await startGateway(upstream, { pairing: service })
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/pair`)
    assert.equal(res.status, 200)
    assert.match(res.headers.get('content-type'), /text\/html/)
    assert.match(await res.text(), /DSH Remote Link 配对/)
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('full pairing flow: challenge → proof → HttpOnly cookie → official UI without Basic', async () => {
  const upstream = await startUpstream()
  const service = pairingService()
  const gw = await startGateway(upstream, { pairing: service })
  try {
    const { verify } = await completePairing(gw, service)
    assert.equal(verify.status, 200)
    const setCookie = verify.headers.get('set-cookie')
    assert.match(setCookie, /rls=/)
    assert.match(setCookie, /HttpOnly/)
    assert.match(setCookie, /SameSite=Strict/)
    assert.match(setCookie, /Max-Age=2592000/)
    const body = await verify.json()
    assert.ok(body.deviceId)

    const cookie = setCookie.split(';')[0]
    const ui = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: { cookie } })
    assert.equal(ui.status, 200)
    assert.equal(await ui.text(), '<html>official ui</html>')
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('WebSocket upgrade rides the pairing cookie', async () => {
  const upstream = await startUpstream()
  const service = pairingService()
  const gw = await startGateway(upstream, { pairing: service })
  try {
    const { verify } = await completePairing(gw, service)
    const cookie = verify.headers.get('set-cookie').split(';')[0]
    const upgraded = await rawUpgrade(gw.port, '/api/events.mux', { cookie })
    assert.match(upgraded.statusLine, /101/)
    upgraded.socket.destroy()
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('bad proof is rejected without a cookie; pairing endpoints have their own budget', async () => {
  const upstream = await startUpstream()
  const service = pairingService()
  const gw = await startGateway(upstream, { pairing: service, pairLimiter: limiterWith({ windowMs: 60_000, max: 3 }) })
  try {
    const p = service.createPairing()
    const challenge = await (await fetch(`http://127.0.0.1:${gw.port}/pair/challenge?sid=${encodeURIComponent(p.sid)}`)).json()
    const bad = await fetch(`http://127.0.0.1:${gw.port}/pair/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sid: challenge.sid, ts: challenge.ts, proof: '00'.repeat(32) }),
    })
    assert.equal(bad.status, 401)
    assert.equal(bad.headers.get('set-cookie'), null)

    // independent bucket: challenge + verify + page count 3, the 4th pairing hit is limited
    const unknown = await fetch(`http://127.0.0.1:${gw.port}/pair/challenge?sid=nope`)
    assert.equal(unknown.status, 404)
    for (let i = 0; i < 2; i += 1) {
      await fetch(`http://127.0.0.1:${gw.port}/pair/challenge?sid=nope`)
    }
    const limited = await fetch(`http://127.0.0.1:${gw.port}/pair/challenge?sid=nope`)
    assert.equal(limited.status, 429)
    // …while normal traffic through the main gate is unaffected
    const ok = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: { authorization: basic('dsh', 's3cret') } })
    assert.equal(ok.status, 200)
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('upstream receives the loopback Host rewrite required by the trust fence', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream)
  try {
    await fetch(`http://127.0.0.1:${gw.port}/api/session.list`, { headers: { authorization: basic('dsh', 's3cret') } })
    assert.equal(upstream.seen.length, 1)
    assert.equal(upstream.seen[0].host, `127.0.0.1:${upstream.port}`)
    assert.equal(upstream.seen[0].url, '/api/session.list')
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('method and body survive the proxy round trip', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream)
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/api/respond`, {
      method: 'POST',
      headers: { authorization: basic('dsh', 's3cret'), 'content-type': 'application/json' },
      body: '{"answer":"approve"}',
    })
    assert.equal(res.status, 200)
    assert.equal(upstream.seen[0].method, 'POST')
    assert.equal(upstream.seen[0].body, '{"answer":"approve"}')
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('dead upstream yields 502, not a crash', async () => {
  const dead = { port: 1 } // nothing listens on port 1 in the test sandbox
  const gw = await startGateway(dead)
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: { authorization: basic('dsh', 's3cret') } })
    assert.equal(res.status, 502)
  } finally {
    await gw.close()
  }
})

test('WebSocket upgrade is authenticated and piped bidirectionally', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream)
  try {
    const denied = await rawUpgrade(gw.port, '/api/events.mux', {})
    assert.match(denied.statusLine, /401/)

    const upgraded = await rawUpgrade(gw.port, '/api/events.mux', { authorization: basic('dsh', 's3cret') })
    assert.match(upgraded.statusLine, /101/)
    upgraded.socket.write('ping-from-phone')
    const echoed = await upgraded.nextMessage()
    assert.equal(echoed, 'ping-from-phone')
    upgraded.socket.destroy()
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('rate limit kicks in with 429 + Retry-After', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream, {
    limiter: limiterWith({ windowMs: 60_000, max: 2 }),
  })
  try {
    const auth = { authorization: basic('dsh', 's3cret') }
    assert.equal((await fetch(`http://127.0.0.1:${gw.port}/`, { headers: auth })).status, 200)
    assert.equal((await fetch(`http://127.0.0.1:${gw.port}/`, { headers: auth })).status, 200)
    const limited = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: auth })
    assert.equal(limited.status, 429)
    assert.ok(Number(limited.headers.get('retry-after')) > 0)
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('repeated auth failures get banned even before the rate limit budget', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream, {
    failureBan: banWith({ windowMs: 60_000, max: 2, banMs: 60_000 }),
  })
  try {
    const wrong = { authorization: basic('dsh', 'wrong') }
    assert.equal((await fetch(`http://127.0.0.1:${gw.port}/`, { headers: wrong })).status, 401)
    assert.equal((await fetch(`http://127.0.0.1:${gw.port}/`, { headers: wrong })).status, 401)
    // now banned: even correct credentials are refused with 429
    const banned = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: { authorization: basic('dsh', 's3cret') } })
    assert.equal(banned.status, 429)
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

test('no password configured: gateway forwards without auth (loopback-only deployments)', async () => {
  const upstream = await startUpstream()
  const gw = await startGateway(upstream, { auth: authWith({ username: 'dsh', password: '' }) })
  try {
    const res = await fetch(`http://127.0.0.1:${gw.port}/`)
    assert.equal(res.status, 200)
  } finally {
    await Promise.all([gw.close(), closeServer(upstream)])
  }
})

// ---- helpers ----

function closeServer(upstream) {
  return new Promise((resolve) => {
    for (const socket of upstream.upgradedSockets) socket.destroy()
    upstream.server.close(() => resolve())
    upstream.server.closeAllConnections?.()
  })
}

function rawUpgrade(port, path, headers) {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect(port, '127.0.0.1')
    let buffer = Buffer.alloc(0)
    let resolved = false
    const fail = (err) => { if (!resolved) { resolved = true; reject(err) } }
    socket.on('error', fail)
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      if (!resolved && buffer.includes('\r\n\r\n')) {
        resolved = true
        const [statusLine] = buffer.toString('latin1').split('\r\n')
        resolve({
          statusLine,
          socket,
          nextMessage: () => new Promise((res2, rej2) => {
            const rest = buffer.subarray(buffer.indexOf('\r\n\r\n') + 4)
            if (rest.length > 0) return res2(rest.toString())
            socket.once('data', (c) => res2(c.toString()))
            socket.once('error', rej2)
          }),
        })
      }
    })
    socket.on('connect', () => {
      const extra = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join('')
      socket.write(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n${extra}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`)
    })
  })
}
