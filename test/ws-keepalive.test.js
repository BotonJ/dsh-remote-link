import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { connect as tcpConnect } from 'node:net'
import { EventEmitter } from 'node:events'
import { createHmac } from 'node:crypto'
import fs from 'node:fs/promises'
import { createBoundaryParser, attachLinkKeepalive } from '../src/ws-keepalive.js'
import { createGateway } from '../src/gateway.js'
import { createAuthenticator } from '../src/auth.js'
import { createPairingService } from '../src/pairing.js'
import { createRateLimiter, createFailureBan } from '../src/ratelimit.js'

// ---------- frame builders (RFC 6455) ----------

/** Unmasked server→client frame. */
function serverFrame(opcode, payload = Buffer.alloc(0), fin = true) {
  const len = payload.length
  let header
  if (len < 126) header = Buffer.from([(fin ? 0x80 : 0) | opcode, len])
  else if (len < 65536) {
    header = Buffer.alloc(4)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  return Buffer.concat([header, payload])
}

/** Masked client→server frame (browsers always mask). */
function clientFrame(opcode, payload = Buffer.alloc(0), fin = true, key = Buffer.from([0x01, 0x02, 0x03, 0x04])) {
  const masked = Buffer.from(payload)
  for (let i = 0; i < masked.length; i += 1) masked[i] ^= key[i % 4]
  const len = payload.length
  let header
  if (len < 126) header = Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | len])
  else if (len < 65536) {
    header = Buffer.alloc(4)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 0x80 | 126
    header.writeUInt16BE(len, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(len), 2)
  }
  return Buffer.concat([header, key, masked])
}

function chunksOf(buffer, size) {
  const out = []
  for (let i = 0; i < buffer.length; i += size) out.push(buffer.subarray(i, i + size))
  return out
}

// ---------- boundary parser ----------

test('parser reports frame boundaries and opcodes across arbitrary chunk splits', () => {
  const stream = Buffer.concat([
    serverFrame(0x1, Buffer.from('hello')),
    serverFrame(0x2, Buffer.alloc(200)),          // 16-bit length path
    serverFrame(0x2, Buffer.alloc(70_000)),       // 64-bit length path
    serverFrame(0x1, Buffer.from('frag-a'), false),
    serverFrame(0x0, Buffer.from('frag-b'), false),
    serverFrame(0x0, Buffer.from('frag-c'), true), // fragmented message
    serverFrame(0x9, Buffer.from('ping!')),        // interleaved control
    clientFrame(0x1, Buffer.from('masked text')),
  ])
  const frames = []
  const parser = createBoundaryParser((meta) => frames.push(meta))
  for (const chunk of chunksOf(stream, 7)) parser.feed(chunk)

  assert.equal(parser.desynced, false)
  assert.equal(parser.framesSeen, 8)
  assert.deepEqual(
    frames.map((f) => [f.opcode, f.length, f.fin]),
    [[0x1, 5, true], [0x2, 200, true], [0x2, 70_000, true], [0x1, 6, false], [0x0, 6, false], [0x0, 6, true], [0x9, 5, true], [0x1, 11, true]],
  )
  assert.equal(frames.at(-1).masked, true)
  assert.equal(frames.at(-1).peek.toString('utf8'), 'masked t') // peek caps at 8 bytes, unmasked
})

test('parser is at a boundary exactly between frames and mid-frame inside one', () => {
  const parser = createBoundaryParser(() => {})
  const small = serverFrame(0x1, Buffer.from('abc'))
  parser.feed(small)
  assert.equal(parser.atBoundary, true)
  const big = serverFrame(0x2, Buffer.alloc(500))
  parser.feed(big.subarray(0, 300))
  assert.equal(parser.atBoundary, false) // header + partial payload consumed
  parser.feed(big.subarray(300))
  assert.equal(parser.atBoundary, true)
})

test('reserved opcodes and oversized lengths desync the parser and stop reporting', () => {
  const reserved = createBoundaryParser(() => assert.fail('no frame may be reported after desync'))
  reserved.feed(Buffer.from([0x83, 0x00])) // opcode 3 is reserved
  assert.equal(reserved.desynced, true)

  const huge = createBoundaryParser(() => {}, { maxFrameBytes: 1000 })
  huge.feed(serverFrame(0x2, Buffer.alloc(2000)))
  assert.equal(huge.desynced, true)
})

// ---------- keepalive over real sockets through the gateway ----------

/** Minimal WS-flavored echo upstream: 101 + raw byte echo (as gateway.test.js). */
function startEchoUpstream() {
  const sockets = new Set()
  const server = createServer((req, res) => res.writeHead(200).end('ok'))
  server.on('upgrade', (req, socket) => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.on('data', (chunk) => socket.write(chunk))
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, sockets }))
  })
}

function startGatewayWithKeepalive(upstream, keepaliveIntervalMs, overrides = {}) {
  const gateway = createGateway({
    auth: createAuthenticator({ username: 'dsh', password: 's3cret' }),
    limiter: createRateLimiter({ windowMs: 60_000, max: 10_000 }),
    failureBan: createFailureBan({ windowMs: 60_000, max: 10_000, banMs: 60_000 }),
    target: () => ({ host: '127.0.0.1', port: upstream.port }),
    log: () => {},
    keepaliveIntervalMs,
    ...overrides,
  })
  return gateway.listen({ host: '127.0.0.1', port: 0 }).then(() => gateway)
}

/** Upgrade through the gateway, keep the raw socket, parse arriving WS bytes.
 * Resolves only after the 101 settled — a real browser sends no bytes before
 * the handshake completes (bytes bundled into the upgrade request end up in
 * the echo upstream's dropped head buffer, a pattern no WS client produces). */
function browserSocket(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect(port, '127.0.0.1')
    let buffer = Buffer.alloc(0)
    const frames = []
    let parser = null
    const settled = { done: false }
    socket.on('error', reject)
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      if (!settled.done) {
        if (!buffer.includes('\r\n\r\n')) return
        settled.done = true
        buffer = buffer.subarray(buffer.indexOf('\r\n\r\n') + 4)
        // From here on, bytes are WS frames from the gateway (unmasked).
        parser = createBoundaryParser((meta) => frames.push({ ...meta, at: Date.now() }))
        resolve({ socket, frames: () => frames, upgraded: settled })
      }
      if (parser !== null) parser.feed(buffer)
      buffer = Buffer.alloc(0)
    })
    socket.on('connect', () => {
      const extra = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join('')
      // Default Basic only when the caller supplied no credentials at all.
      const hasOwnAuth = headers.authorization !== undefined || headers.cookie !== undefined
      const basic = hasOwnAuth ? '' : `Authorization: Basic ${Buffer.from('dsh:s3cret').toString('base64')}\r\n`
      socket.write(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n${basic}${extra}Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`)
    })
  })
}

/** Browser-like ponger: answers every injected ping (kernels do this). */
function autoPong(browser) {
  const seen = new Set()
  return setInterval(() => {
    for (const frame of browser.frames()) {
      if (frame.opcode !== 0x9 || seen.has(frame) || frame.peek.length < 4) continue
      seen.add(frame)
      browser.socket.write(clientFrame(0xa, frame.peek))
    }
  }, 15)
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function closeUpstream(upstream) {
  return new Promise((resolve) => {
    for (const socket of upstream.sockets) socket.destroy()
    upstream.server.close(() => resolve())
    upstream.server.closeAllConnections?.()
  })
}

test('idle leg receives injected pings; pong answers update stats; status page reports the leg', async () => {
  const upstream = await startEchoUpstream()
  const gw = await startGatewayWithKeepalive(upstream, 80)
  const browser = await browserSocket(gw.port, '/api/events.mux')
  const ponger = autoPong(browser)
  try {
    // Wait past two keepalive intervals with no upstream traffic; the ponger
    // answers every ping like a browser kernel would.
    await sleep(300)
    const pings = browser.frames().filter((f) => f.opcode === 0x9)
    assert.ok(pings.length >= 2, `expected >=2 injected pings, got ${pings.length}`)
    assert.equal(pings[0].peek.length, 4, 'ping payload carries the 4-byte counter')

    const res = await fetch(`http://127.0.0.1:${gw.port}/status.json`)
    const payload = await res.json()
    assert.equal(res.status, 200)
    assert.equal(payload.generation, 1)
    assert.equal(payload.legs.length, 1)
    assert.equal(payload.legs[0].path, '/api/events.mux')
    assert.ok(payload.legs[0].keepalive.pingsSent >= 2)
    assert.ok(payload.legs[0].keepalive.pongsReceived >= 2)
    assert.ok(payload.legs[0].keepalive.lastRttMs !== null)
  } finally {
    clearInterval(ponger)
    browser.socket.destroy()
    await gw.close()
    await closeUpstream(upstream)
  }
})

test('active data traffic suppresses ping injection', async () => {
  const upstream = await startEchoUpstream()
  const gw = await startGatewayWithKeepalive(upstream, 80)
  const browser = await browserSocket(gw.port, '/api/events.mux')
  try {
    // Feed a data frame from the browser every 40ms; the echo upstream
    // reflects it back, keeping the gateway→browser direction busy.
    const feeder = setInterval(() => browser.socket.write(clientFrame(0x1, Buffer.from('busy'))), 40)
    await sleep(350)
    clearInterval(feeder)
    const pings = browser.frames().filter((f) => f.opcode === 0x9)
    assert.equal(pings.length, 0, 'no pings may be injected while data flows')
    // Data integrity through the keepalive-observed pipe: echo round-trip.
    browser.socket.write(clientFrame(0x2, Buffer.alloc(70_000))) // 64-bit length path
    await sleep(200)
    const echoed = browser.frames().filter((f) => f.opcode === 0x2 && f.length === 70_000)
    assert.equal(echoed.length, 1)
  } finally {
    browser.socket.destroy()
    await gw.close()
    await closeUpstream(upstream)
  }
})

test('a mid-frame idle gap never receives an injected ping; the frame completes intact', async () => {
  const upstream = await startEchoUpstream()
  const gw = await startGatewayWithKeepalive(upstream, 60)
  const browser = await browserSocket(gw.port, '/api/events.host')
  try {
    // Start a large frame, then stall mid-frame far past the keepalive
    // interval: the tick fires while the parser is mid-frame (not at a
    // boundary) and must skip. Injecting there would corrupt the stream —
    // the browser-side parser would desync and the frame would never land.
    const big = clientFrame(0x2, Buffer.alloc(4_000))
    browser.socket.write(big.subarray(0, 300))
    await sleep(250) // ~4 keepalive intervals elapse mid-frame
    browser.socket.write(big.subarray(300))
    await sleep(250) // echo completes the round-trip

    const completed = browser.frames().filter((f) => f.opcode === 0x2 && f.length === 4_000)
    assert.equal(completed.length, 1, 'large frame must round-trip exactly once, intact')
  } finally {
    browser.socket.destroy()
    await gw.close()
    await closeUpstream(upstream)
  }
})

test('status page is loopback-fenced like the QR image', async () => {
  const upstream = await startEchoUpstream()
  const gw = await startGatewayWithKeepalive(upstream, 25_000)
  try {
    const denied = await fetch(`http://127.0.0.1:${gw.port}/status`, { headers: { 'x-forwarded-for': '203.0.113.9' } })
    assert.equal(denied.status, 403)
    const deniedJson = await fetch(`http://127.0.0.1:${gw.port}/status.json`, { headers: { 'x-forwarded-for': '203.0.113.9' } })
    assert.equal(deniedJson.status, 403)

    const page = await fetch(`http://127.0.0.1:${gw.port}/status`)
    assert.equal(page.status, 200)
    assert.match(page.headers.get('content-type'), /text\/html/)
    assert.match(await page.text(), /DSH Remote Link — 链路状态/)
  } finally {
    await gw.close()
    await closeUpstream(upstream)
  }
})

test('intervalMs = 0 disables injection but keeps leg stats on the status page', async () => {
  const upstream = await startEchoUpstream()
  const gw = await startGatewayWithKeepalive(upstream, 0)
  const browser = await browserSocket(gw.port, '/api/events.mux')
  try {
    await sleep(150)
    assert.equal(browser.frames().filter((f) => f.opcode === 0x9).length, 0)
    const payload = await (await fetch(`http://127.0.0.1:${gw.port}/status.json`)).json()
    assert.equal(payload.legs.length, 1)
    assert.equal(payload.legs[0].keepalive.enabled, false)
    assert.equal(payload.keepaliveIntervalMs, 0)
  } finally {
    browser.socket.destroy()
    await gw.close()
    await closeUpstream(upstream)
  }
})

// ---------- v1.6.1: eviction, identity, upstream & tunnel health ----------

test('parser tolerates RSV bits (permessage-deflate frames keep valid boundaries)', () => {
  // A future DSH build may negotiate permessage-deflate: RSV1 set on data
  // frames. Framing stays length-authoritative, so the parser must keep
  // reporting boundaries instead of desyncing.
  const frames = []
  const parser = createBoundaryParser((m) => frames.push(m))
  parser.feed(Buffer.concat([
    Buffer.from([0xc1, 0x03, 0x61, 0x62, 0x63]), // text, RSV1 set, "abc"
    serverFrame(0x1, Buffer.from('next')),       // ordinary frame follows
  ]))
  assert.equal(parser.desynced, false)
  assert.equal(parser.framesSeen, 2)
  assert.equal(frames[0].rsv, 0b100) // RSV1 is the MSB of the 3-bit field
  assert.equal(frames[1].rsv, 0)
})

test('dispose removes every listener and stops the timer', async () => {
  const down = new EventEmitter()
  const up = new EventEmitter()
  down.write = () => { throw new Error('no ping may be written after dispose') }
  up.write = () => {}
  const downBefore = down.listenerCount('data')
  const upBefore = up.listenerCount('data')
  const keep = attachLinkKeepalive(down, up, { intervalMs: 20 })
  assert.equal(down.listenerCount('data'), downBefore + 1)
  assert.equal(up.listenerCount('data'), upBefore + 1)
  keep.dispose()
  assert.equal(down.listenerCount('data'), downBefore)
  assert.equal(up.listenerCount('data'), upBefore)
  await sleep(80) // intervalMs × 4: any surviving timer would write and throw
})

test('three unanswered pings evict the dead leg and clear it from the status page', async () => {
  const upstream = await startEchoUpstream()
  const gw = await startGatewayWithKeepalive(upstream, 50)
  const browser = await browserSocket(gw.port, '/api/events.mux')
  // No ponger: the leg never answers pings.
  try {
    const closed = new Promise((resolve) => browser.socket.on('close', resolve))
    await closed.then(() => undefined, () => undefined).catch(() => {})
    await Promise.race([closed, sleep(1500).then(() => assert.fail('dead leg was not evicted within 1.5s'))])
    await sleep(50)
    const payload = await (await fetch(`http://127.0.0.1:${gw.port}/status.json`)).json()
    assert.equal(payload.legs.length, 0, 'evicted leg must leave the registry')
    assert.ok(payload.generation >= 1)
  } finally {
    browser.socket.destroy()
    await gw.close()
    await closeUpstream(upstream)
  }
})

test('legs carry device identity when the upgrade rides the pairing cookie', async () => {
  const upstream = await startEchoUpstream()
  const service = createPairingService({ store: { load: () => [], save() {} }, ttlMs: 300_000 })
  const gw = await startGatewayWithKeepalive(upstream, 0, {
    auth: createAuthenticator({
      username: 'dsh', password: 's3cret',
      cookieAuth: true,
      resolveSession: (token) => service.resolveSession(token),
    }),
    pairing: service,
    resolveDevice: (deviceId) => service.listDevices().find((d) => d.deviceId === deviceId)?.name ?? null,
  })
  try {
    const p = service.createPairing()
    const challenge = await (await fetch(`http://127.0.0.1:${gw.port}/pair/challenge?sid=${encodeURIComponent(p.sid)}`)).json()
    const proof = createHmac('sha256', Buffer.from(p.secret, 'utf8')).update(`${challenge.sid}|${challenge.nonce}|${challenge.ts}`, 'utf8').digest('hex')
    const verify = await fetch(`http://127.0.0.1:${gw.port}/pair/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sid: challenge.sid, ts: challenge.ts, proof }),
    })
    const cookie = verify.headers.get('set-cookie').split(';')[0]
    const [device] = service.listDevices()
    service.renameDevice(device.deviceId, 'pixel-9')
    const browser = await browserSocket(gw.port, '/api/events.mux', { cookie })
    await sleep(60)
    const payload = await (await fetch(`http://127.0.0.1:${gw.port}/status.json`)).json()
    browser.socket.destroy()
    assert.equal(payload.legs.length, 1)
    assert.equal(payload.legs[0].ip, '127.0.0.1')
    assert.equal(payload.legs[0].auth, 'cookie')
    assert.equal(payload.legs[0].deviceId, device.deviceId)
    assert.equal(payload.legs[0].deviceName, 'pixel-9')
  } finally {
    await gw.close()
    await closeUpstream(upstream)
  }
})

test('status reports upstream health: recent errors on a dead target, lastOkAt on a live one', async () => {
  // Dead target: nothing listens on that port.
  const deadTarget = { host: '127.0.0.1', port: 1 }
  const gwDead = createGateway({
    auth: createAuthenticator({ username: 'dsh', password: 's3cret' }),
    limiter: createRateLimiter({ windowMs: 60_000, max: 10_000 }),
    failureBan: createFailureBan({ windowMs: 60_000, max: 10_000, banMs: 60_000 }),
    target: () => deadTarget,
    log: () => {},
  })
  await gwDead.listen({ host: '127.0.0.1', port: 0 })
  try {
    const res = await fetch(`http://127.0.0.1:${gwDead.port}/`, { headers: { authorization: `Basic ${Buffer.from('dsh:s3cret').toString('base64')}` } })
    assert.equal(res.status, 502)
    const payload = await (await fetch(`http://127.0.0.1:${gwDead.port}/status.json`)).json()
    assert.deepEqual(payload.upstream.target, deadTarget)
    assert.equal(payload.upstream.lastOkAt, null)
    assert.ok(payload.upstream.recentErrors.length >= 1)
    assert.match(payload.upstream.recentErrors[0].message, /ECONNREFUSED|connect/)
  } finally {
    await gwDead.close()
  }

  const upstream = await startEchoUpstream()
  const gwLive = await startGatewayWithKeepalive(upstream, 0)
  try {
    await fetch(`http://127.0.0.1:${gwLive.port}/`, { headers: { authorization: `Basic ${Buffer.from('dsh:s3cret').toString('base64')}` } })
    const payload = await (await fetch(`http://127.0.0.1:${gwLive.port}/status.json`)).json()
    assert.ok(payload.upstream.lastOkAt !== null)
    assert.deepEqual(payload.upstream.recentErrors, [])
  } finally {
    await gwLive.close()
    await closeUpstream(upstream)
  }
})

test('tunnel heartbeat surfaces connector age; a missing file reports unavailable', async () => {
  const upstream = await startEchoUpstream()
  const beatFile = `/tmp/rl-beat-${process.pid}.test`
  const gw = await startGatewayWithKeepalive(upstream, 0, { tunnelHeartbeatFile: beatFile })
  try {
    const missing = await (await fetch(`http://127.0.0.1:${gw.port}/status.json`)).json()
    assert.equal(missing.tunnel.available, false)
    assert.equal(missing.tunnel.file, beatFile)

    await fs.writeFile(beatFile, String(Math.floor(Date.now() / 1000) - 2), 'utf8')
    const fresh = await (await fetch(`http://127.0.0.1:${gw.port}/status.json`)).json()
    assert.equal(fresh.tunnel.available, true)
    assert.ok(fresh.tunnel.ageMs >= 1500 && fresh.tunnel.ageMs < 60_000)

    await fs.writeFile(beatFile, 'garbage', 'utf8')
    const corrupt = await (await fetch(`http://127.0.0.1:${gw.port}/status.json`)).json()
    assert.equal(corrupt.tunnel.available, false)
  } finally {
    await fs.rm(beatFile, { force: true })
    await gw.close()
    await closeUpstream(upstream)
  }
})
