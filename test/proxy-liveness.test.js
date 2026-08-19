import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createServer as createNetServer, connect as tcpConnect } from 'node:net'
import { createGateway } from '../src/gateway.js'
import { createAuthenticator } from '../src/auth.js'
import { createRateLimiter, createFailureBan } from '../src/ratelimit.js'
import { createHostProbe } from '../src/host-probe.js'
import { createEventTap } from '../src/event-tap.js'

const basic = (u, p) => `Basic ${Buffer.from(`${u}:${p}`).toString('base64')}`
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function buildGateway(targetPort, gatewayOverrides = {}) {
  const gateway = createGateway({
    auth: createAuthenticator({ username: 'dsh', password: 's3cret' }),
    limiter: createRateLimiter({ windowMs: 60_000, max: 10_000 }),
    failureBan: createFailureBan({ windowMs: 60_000, max: 10_000, banMs: 60_000 }),
    target: () => ({ host: '127.0.0.1', port: targetPort }),
    log: () => {},
    hostProbeIntervalMs: 0,
    keepaliveIntervalMs: 0,
    upgradeTimeoutMs: gatewayOverrides.upgradeTimeoutMs ?? 10_000,
  })
  return gateway.listen({ host: '127.0.0.1', port: 0 }).then(() => gateway)
}

/** Fails a stalled assertion instead of hanging the suite forever. */
function withGuard(promise, ms = 2_000, label = 'operation') {
  let timer
  const guard = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} stalled over ${ms}ms`)), ms) })
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer))
}

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
const closeAll = (server) => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()) })

test('upstream dying mid-response terminates the client response instead of hanging it', async () => {
  const upstream = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '1000' })
    res.write('partial')
    setTimeout(() => res.socket.destroy(), 30)
  })
  const upPort = await listen(upstream)
  const gw = await buildGateway(upPort)
  try {
    const resp = await fetch(`http://127.0.0.1:${gw.port}/big`, { headers: { authorization: basic('dsh', 's3cret') } })
    assert.equal(resp.status, 200)
    // Pre-fix this await never settled: the proxy had no response-stream
    // death handling and the client waited on a half-delivered body forever.
    await assert.rejects(withGuard(resp.text(), 2_000, 'body read'),
      /terminated|network|aborted|ECONNRESET/i)
  } finally {
    await gw.close()
    await closeAll(upstream)
  }
})

test('client disconnecting mid-response tears down the upstream connection', async () => {
  const upstreamSockets = new Set()
  const upstream = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.write('streaming…')
    // never end: an endless body only ends when someone destroys the socket
  })
  upstream.on('connection', (s) => { upstreamSockets.add(s); s.on('close', () => upstreamSockets.delete(s)) })
  const upPort = await listen(upstream)
  const gw = await buildGateway(upPort)
  try {
    const controller = new AbortController()
    const resp = await fetch(`http://127.0.0.1:${gw.port}/endless`, {
      headers: { authorization: basic('dsh', 's3cret') }, signal: controller.signal,
    })
    const reader = resp.body.getReader()
    await withGuard(reader.read(), 2_000, 'first chunk')
    assert.equal(upstreamSockets.size, 1, 'upstream connection established')
    controller.abort()
    await sleep(150)
    assert.equal(upstreamSockets.size, 0, 'upstream connection destroyed after client disconnect')
  } finally {
    await gw.close()
    await closeAll(upstream)
  }
})

test('an upstream that never answers the upgrade gets a 504 after the handshake deadline', async () => {
  // Accepts TCP, never writes a byte — the handshake must time out. The
  // socket must be resumed: a paused read end never consumes the peer's
  // FIN and server.close() would wait forever (a real HTTP server reads).
  const upstream = createNetServer((socket) => socket.resume())
  const upPort = await listen(upstream)
  const gw = await buildGateway(upPort, { upgradeTimeoutMs: 150 })
  try {
    const verdict = await withGuard(new Promise((resolve, reject) => {
      const socket = tcpConnect(gw.port, '127.0.0.1')
      socket.on('error', reject)
      socket.on('data', (chunk) => resolve(String(chunk)))
      socket.on('connect', () => {
        socket.write(`GET /api/events.mux HTTP/1.1\r\nHost: 127.0.0.1:${gw.port}\r\nAuthorization: ${basic('dsh', 's3cret')}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`)
      })
    }), 3_000, '504 verdict')
    assert.match(verdict, /504/)
  } finally {
    await gw.close()
    upstream.closeAllConnections?.()
    await new Promise((r) => upstream.close(r))
  }
})

test('an established WS leg survives a quiet period longer than the handshake deadline', async () => {
  const upgradedSockets = new Set() // Node never releases upgraded sockets on server.close by itself
  const upstream = createServer()
  upstream.on('upgrade', (req, socket) => {
    upgradedSockets.add(socket)
    socket.on('close', () => upgradedSockets.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.on('data', (chunk) => socket.write(chunk)) // raw echo
  })
  const upPort = await listen(upstream)
  const gw = await buildGateway(upPort, { upgradeTimeoutMs: 150 })
  try {
    const socket = await withGuard(new Promise((resolve, reject) => {
      const s = tcpConnect(gw.port, '127.0.0.1')
      s.on('error', reject)
      s.on('data', (chunk) => { if (String(chunk).includes('101')) resolve(s) })
      s.on('connect', () => {
        s.write(`GET /api/events.mux HTTP/1.1\r\nHost: 127.0.0.1:${gw.port}\r\nAuthorization: ${basic('dsh', 's3cret')}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`)
      })
    }), 2_000, '101 handshake')

    // Quiet longer than the 150ms handshake deadline: the deadline only
    // guards the handshake, never an established (possibly idle) leg.
    await sleep(450)
    const echo = await withGuard(new Promise((resolve, reject) => {
      socket.once('error', reject)
      socket.once('data', resolve)
      socket.write('still-alive')
    }), 2_000, 'echo after quiet period')
    assert.equal(String(echo).endsWith('still-alive') || String(echo).includes('still-alive'), true)
    socket.destroy()
  } finally {
    await gw.close()
    for (const s of upgradedSockets) s.destroy()
    await closeAll(upstream)
  }
})

test('event tap: an SSE handshake that never completes times out and the backoff retries', async () => {
  const connections = []
  const upstream = createNetServer((socket) => { connections.push(socket); socket.resume() })
  const upPort = await listen(upstream)
  const tap = createEventTap({
    target: () => ({ host: '127.0.0.1', port: upPort }),
    onRequested: () => {},
    handshakeTimeoutMs: 100,
    log: () => {},
  })
  tap.start()
  try {
    // 100ms handshake deadline + 1s first backoff → the retry lands ~1.1s in.
    await sleep(1_300)
    assert.ok(connections.length >= 2, `backoff must reconnect (attempts: ${connections.length})`)
    assert.equal(tap.state().connected, false)
  } finally {
    tap.close()
    upstream.closeAllConnections?.()
    await new Promise((r) => upstream.close(r))
  }
})

test('host probe: mid-body upstream death settles the probe with an error instead of hanging', async () => {
  const upstream = createServer((req, res) => {
    if (req.url === '/api/host.describe') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.write('{"result":{"ok":true,"val') // truncated mid-JSON
      setTimeout(() => res.socket.destroy(), 30)
      return
    }
    res.writeHead(404).end()
  })
  const upPort = await listen(upstream)
  const probe = createHostProbe({ target: () => ({ host: '127.0.0.1', port: upPort }), intervalMs: 50, log: () => {} })
  try {
    // refresh() only probes when enabled, but never start() the interval —
    // this test exercises exactly one probe roundtrip.
    await withGuard(probe.refresh(), 2_000, 'probe settle')
    assert.equal(probe.state().probe.ok, false)
    assert.ok(probe.state().probe.error, 'error must be surfaced')
  } finally {
    probe.close()
    await closeAll(upstream)
  }
})
