import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createGateway } from '../src/gateway.js'
import { createAuthenticator } from '../src/auth.js'
import { createRateLimiter, createFailureBan } from '../src/ratelimit.js'
import { normalizeConfig } from '../src/config.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const basic = `Basic ${Buffer.from('dsh:s3cret').toString('base64')}`

/** Minimal DSH-shaped upstream: host.describe RPC + host event SSE stream. */
function startDshUpstream(describeValue) {
  const seen = []
  const sseSockets = new Set()
  const server = createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/api/host.describe') {
      const chunks = []
      req.on('data', (c) => chunks.push(c))
      req.on('end', () => {
        const envelope = JSON.parse(Buffer.concat(chunks).toString('utf8'))
        seen.push({ method: envelope.method, rpcId: envelope.rpcId })
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ rpcId: envelope.rpcId, result: { ok: true, value: describeValue } }))
      })
      return
    }
    if (req.method === 'GET' && req.url === '/api/events.host') {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      const frame = (payload) => res.write(`data: ${JSON.stringify({ rpcId: 'srv', payload })}\n\n`)
      frame({ type: 'host/session-added', sessionId: 's1' })
      frame({ type: 'host/session-added', sessionId: 's2' })
      frame({ type: 'host/session-status', sessionId: 's1', running: true })
      sseSockets.add(res)
      return
    }
    res.writeHead(404).end('nope')
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen, sseSockets }))
  })
}

/** Non-DSH upstream: no /api surface at all. */
function startAlienUpstream() {
  const server = createServer((req, res) => {
    if (req.url.startsWith('/api/')) return res.writeHead(404).end('not found')
    res.writeHead(200, { 'content-type': 'text/html' }).end('<html>alien ui</html>')
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

function gatewayTo(upstream, hostProbeIntervalMs, log = () => {}) {
  const gateway = createGateway({
    auth: createAuthenticator({ username: 'dsh', password: 's3cret' }),
    limiter: createRateLimiter({ windowMs: 60_000, max: 10_000 }),
    failureBan: createFailureBan({ windowMs: 60_000, max: 10_000, banMs: 60_000 }),
    target: () => ({ host: '127.0.0.1', port: upstream.port }),
    log,
    hostProbeIntervalMs,
  })
  return gateway.listen({ host: '127.0.0.1', port: 0 }).then(() => gateway)
}

async function closeAll(gateway, ...upstreams) {
  await gateway.close()
  for (const up of upstreams) {
    up.sseSockets?.forEach((res) => res.destroy())
    up.server.closeAllConnections?.()
    await new Promise((r) => up.server.close(r))
  }
}

const statusJson = (gw) => fetch(`http://127.0.0.1:${gw.port}/status.json`).then((r) => r.json())

test('host probe: full-stack RPC health + live host events on /status', async () => {
  const upstream = await startDshUpstream({
    version: '0.1.0-rc.6', model: 'deepseek-v4', attachedSessions: 2, cwd: '/private/cwd', canOpenPath: true,
  })
  const gw = await gatewayTo(upstream, 30_000)
  try {
    // The status view itself nudges a fresh probe; poll until it lands.
    let host = null
    for (let i = 0; i < 20 && host?.probe?.ok !== true; i += 1) {
      await statusJson(gw).then((p) => { host = p.host })
      await sleep(100)
    }
    assert.equal(host.enabled, true)
    assert.equal(host.probe.ok, true)
    assert.ok(host.probe.ms >= 0)
    assert.deepEqual(host.probe.describe, { version: '0.1.0-rc.6', model: 'deepseek-v4', attachedSessions: 2 })

    // SSE tap: wait for the three frames wired into the mock stream.
    for (let i = 0; i < 30 && host.events.framesSeen < 3; i += 1) {
      await statusJson(gw).then((p) => { host = p.host })
      await sleep(100)
    }
    assert.equal(host.events.connected, true)
    assert.equal(host.events.sessionCount, 2)
    assert.equal(host.events.runningCount, 1)

    // The probe spoke the client-request envelope, rpcId echoed back.
    assert.equal(upstream.seen.at(-1).method, 'host.describe')
  } finally {
    await closeAll(gw, upstream)
  }
})

test('non-DSH upstream: telemetry self-disables after 404s, error ring stays clean', async () => {
  const upstream = await startAlienUpstream()
  const gw = await gatewayTo(upstream, 40)
  try {
    let host = null
    for (let i = 0; i < 40 && host?.supported !== false; i += 1) {
      await statusJson(gw).then((p) => { host = p.host })
      await sleep(50)
    }
    assert.equal(host.supported, false, 'upstream should be marked non-DSH')
    assert.equal(host.events.connected, false)
    const payload = await statusJson(gw)
    assert.deepEqual(payload.upstream.recentErrors, [], 'probe failures must not pollute the proxy error ring')
  } finally {
    await closeAll(gw, upstream)
  }
})

test('config: hostProbeIntervalMs default 30s, 0 disables, range checked', () => {
  assert.equal(normalizeConfig({}).hostProbeIntervalMs, 30_000)
  assert.equal(normalizeConfig({ hostProbeIntervalMs: 0 }).hostProbeIntervalMs, 0)
  assert.equal(normalizeConfig({ hostProbeIntervalMs: 5_000 }).hostProbeIntervalMs, 5_000)
  assert.throws(() => normalizeConfig({ hostProbeIntervalMs: 3_600_001 }), { code: 'E_CONFIG' })
  assert.throws(() => normalizeConfig({ hostProbeIntervalMs: '30' }), { code: 'E_CONFIG' })
})

test('hostProbeIntervalMs 0 keeps the host section off entirely', async () => {
  const upstream = await startAlienUpstream()
  const gw = await gatewayTo(upstream, 0)
  try {
    const payload = await statusJson(gw)
    assert.equal(payload.host.enabled, false)
    assert.equal(payload.host.probe.ok, null)
  } finally {
    await closeAll(gw, upstream)
  }
})

test('catch-all 200-HTML upstream (MiMo-style UI route) also self-disables', async () => {
  // MiMo's UIRoutes .all("/*") answers EVERY path — including /api/* — with
  // 200 HTML. The probe must classify that as "not a DSH host", not retry
  // forever against a green status code.
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<!DOCTYPE html><html>mimo ui</html>')
  })
  const upstream = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })))
  const gw = await gatewayTo(upstream, 30_000)
  try {
    let host = null
    for (let i = 0; i < 25 && host?.supported !== false; i += 1) {
      await statusJson(gw).then((p) => { host = p.host })
      await sleep(80)
    }
    assert.equal(host.supported, false, '200-HTML answers must degrade to unsupported')
    assert.equal(host.events.connected, false)
    assert.equal(host.probe.ok, false)
  } finally {
    await closeAll(gw, upstream)
  }
})
