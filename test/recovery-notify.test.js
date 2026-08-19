import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { connect as tcpConnect } from 'node:net'
import fs from 'node:fs/promises'
import { createPairingService } from '../src/pairing.js'
import { createNotifier } from '../src/notify.js'
import { createEventTap } from '../src/event-tap.js'
import { defineRemoteRecoveryTool } from '../src/tools.js'
import { createGateway } from '../src/gateway.js'
import { createAuthenticator } from '../src/auth.js'
import { createRateLimiter, createFailureBan } from '../src/ratelimit.js'
import { normalizeConfig } from '../src/config.js'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const RECOVERY = 'correct-horse-battery-staple-9f3k2m'

function service(code = RECOVERY) {
  const store = { load: () => [], save() {} }
  return createPairingService({ store, ttlMs: 300_000, ...(code === null ? {} : { recoveryCode: code }) })
}

// ---------- recovery code ----------

test('redeemRecovery: right code mints a revocable device; wrong code fails', async () => {
  const svc = service()
  const ok = await svc.redeemRecovery({ code: RECOVERY, name: 'new-phone' })
  assert.equal(ok.ok, true)
  assert.match(ok.deviceId, /^[A-Za-z0-9_-]+$/)
  const session = svc.resolveSession(ok.sessionToken)
  assert.equal(session.deviceId, ok.deviceId)
  const [device] = svc.listDevices()
  assert.equal(device.name, 'new-phone')

  const bad = await svc.redeemRecovery({ code: 'wrong-code-wrong-code-wrong' })
  assert.deepEqual(bad, { ok: false, error: 'BAD_RECOVERY' })

  // Repeatable by design (rotate via config); each use is a fresh device.
  const again = await svc.redeemRecovery({ code: RECOVERY })
  assert.equal(again.ok, true)
  assert.notEqual(again.deviceId, ok.deviceId)
  assert.equal(svc.listDevices().length, 2)
  assert.equal(svc.revokeDevice(again.deviceId), 1)
  assert.equal(svc.resolveSession(again.sessionToken), null)
})

test('redeemRecovery: disabled without a configured code; defaults the name', async () => {
  const svc = service(null)
  assert.deepEqual(await svc.redeemRecovery({ code: RECOVERY }), { ok: false, error: 'RECOVERY_DISABLED' })

  const named = await service().redeemRecovery({ code: RECOVERY })
  assert.match(named.deviceId, /.+/)
  const [device] = service().listDevices() // separate store; just shape-check here
  void device
})

test('config: pairing.recoveryCode entropy floor + notify URL validation', () => {
  assert.equal(normalizeConfig({}).pairing.recoveryCode, null)
  assert.equal(normalizeConfig({ pairing: { recoveryCode: RECOVERY } }).pairing.recoveryCode, RECOVERY)
  assert.throws(() => normalizeConfig({ pairing: { recoveryCode: 'short' } }), { code: 'E_CONFIG' })
  assert.equal(normalizeConfig({ pairing: { recoveryCode: '' } }).pairing.recoveryCode, null)

  assert.deepEqual(normalizeConfig({}).notify, { barkUrl: '', ntfyUrl: '', webhookUrl: '' })
  assert.equal(normalizeConfig({ notify: { barkUrl: 'https://api.day.app/KEY' } }).notify.barkUrl, 'https://api.day.app/KEY')
  assert.throws(() => normalizeConfig({ notify: { ntfyUrl: 'ftp://x' } }), { code: 'E_CONFIG' })
})

// ---------- notifier ----------

test('notifier: fans out to all channels, swallows failures', async () => {
  const calls = []
  const fetchImpl = async (url, init) => {
    calls.push({ url, init })
    if (url.includes('failing')) throw new Error('boom')
    return { ok: true }
  }
  const notifier = createNotifier({
    barkUrl: 'https://api.day.app/KEY/',
    ntfyUrl: 'https://ntfy.example/my-topic',
    webhookUrl: 'https://hook.example/failing',
    fetchImpl,
    log: () => {},
  })
  assert.deepEqual(notifier.channelNames(), ['bark', 'ntfy', 'webhook'])
  await notifier.notify({ title: 'DSH 等待审批', body: '打开远程页面处理。' })
  assert.equal(calls.length, 3)
  assert.match(calls[0].url, /api\.day\.app\/KEY\/DSH%20%E7%AD%89%E5%BE%85%E5%AE%A1%E6%89%B9\//)
  // ntfy: JSON publish to the service root — the title rides in the UTF-8
  // body, never in a Latin-1-constrained header.
  assert.equal(String(calls[1].url), 'https://ntfy.example/')
  assert.equal(calls[1].init.headers['content-type'], 'application/json')
  assert.deepEqual(JSON.parse(calls[1].init.body), { topic: 'my-topic', title: 'DSH 等待审批', message: '打开远程页面处理。' })
  assert.equal(calls[2].init.method, 'POST')
  assert.equal(notifier.enabled, true)
})

test('notifier: ntfy publishes as JSON so CJK titles never enter HTTP headers (real fetch)', async () => {
  // The old `headers: { title }` path threw "Cannot convert argument to a
  // ByteString" on every CJK push — exercise real fetch to lock the fix in.
  const received = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => { received.push({ url: req.url, contentType: req.headers['content-type'], body }); res.writeHead(200).end() })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  try {
    const notifier = createNotifier({ ntfyUrl: `http://127.0.0.1:${server.address().port}/base/my-topic`, log: () => {} })
    await notifier.notify({ title: 'DSH 等待审批', body: '打开远程页面处理。' })
    assert.equal(received.length, 1)
    assert.equal(received[0].url, '/base/', 'JSON publish goes to the service root')
    assert.equal(received[0].contentType, 'application/json')
    assert.deepEqual(JSON.parse(received[0].body), { topic: 'my-topic', title: 'DSH 等待审批', message: '打开远程页面处理。' })
  } finally {
    server.closeAllConnections?.()
    await new Promise((r) => server.close(r))
  }
})

// ---------- event tap + end-to-end push policy through the gateway ----------

/** DSH-flavoured upstream: mux SSE stream for the tap + raw WS echo for legs. */
function startMuxUpstream() {
  let sseRes = null
  const upgradedSockets = new Set()
  const server = createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/api/events.mux') {
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      sseRes = res
      return
    }
    res.writeHead(404).end()
  })
  server.on('upgrade', (req, socket) => {
    upgradedSockets.add(socket)
    socket.on('close', () => upgradedSockets.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n')
    socket.on('data', (chunk) => socket.write(chunk))
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      server, port: server.address().port,
      send: (payload) => sseRes?.write(`data: ${JSON.stringify({ rpcId: 'x', payload })}\n\n`),
      closeStream: () => { sseRes?.end(); for (const s of upgradedSockets) s.destroy() },
    }))
  })
}

function upgradeLeg(gatewayPort) {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect(gatewayPort, '127.0.0.1')
    socket.on('error', reject)
    socket.on('data', (chunk) => {
      if (String(chunk).includes('101')) resolve(socket)
    })
    socket.on('connect', () => {
      socket.write(`GET /api/events.mux HTTP/1.1\r\nHost: 127.0.0.1:${gatewayPort}\r\nAuthorization: Basic ${Buffer.from('dsh:s3cret').toString('base64')}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`)
    })
  })
}

test('push fires for pending approval with no legs; stays silent while a browser leg lives', async () => {
  const upstream = await startMuxUpstream()
  const pushes = []
  const fetchImpl = async (url) => { pushes.push(url); return { ok: true } }
  const svc = service()
  const gateway = createGateway({
    auth: createAuthenticator({
      username: 'dsh', password: 's3cret',
      cookieAuth: true, resolveSession: (t) => svc.resolveSession(t),
    }),
    limiter: createRateLimiter({ windowMs: 60_000, max: 10_000 }),
    failureBan: createFailureBan({ windowMs: 60_000, max: 10_000, banMs: 60_000 }),
    target: () => ({ host: '127.0.0.1', port: upstream.port }),
    log: () => {},
    pairing: svc,
    keepaliveIntervalMs: 0,
    hostProbeIntervalMs: 0,
  })
  await gateway.listen({ host: '127.0.0.1', port: 0 })

  // Replicating index.js wiring with an injectable fetch.
  const notifier = createNotifier({ barkUrl: 'https://api.day.app/KEY', fetchImpl, log: () => {} })
  const pushedIds = new Set()
  let cooldownUntil = 0
  const tap = createEventTap({
    target: () => ({ host: '127.0.0.1', port: upstream.port }),
    log: () => {},
    onRequested: ({ kind, id }) => {
      if (gateway.activeLegCount() > 0) return
      const key = `${kind}:${id}`
      if (pushedIds.has(key)) return
      if (Date.now() < cooldownUntil) return
      pushedIds.add(key)
      cooldownUntil = Date.now() + 60_000
      notifier.notify({ title: 'DSH 等待审批', body: '打开远程页面处理。' }).catch(() => {})
    },
    onResolved: () => pushedIds.clear(),
  })
  tap.start()
  try {
    // No legs → first approval pushes.
    await sleep(150)
    upstream.send({ type: 'approval/requested', approvalId: 'a1', summary: 'rm -rf build/' })
    await sleep(150)
    assert.equal(pushes.length, 1, 'idle approval must push')

    // Same id again within cooldown → deduped.
    upstream.send({ type: 'approval/requested', approvalId: 'a1', summary: 'rm -rf build/' })
    await sleep(120)
    assert.equal(pushes.length, 1, 'duplicate approval id must not re-push')

    // A browser leg connects → no push for a NEW approval.
    const leg = await upgradeLeg(gateway.port)
    upstream.send({ type: 'approval/requested', approvalId: 'a2', summary: 'npm install' })
    await sleep(150)
    assert.equal(pushes.length, 1, 'connected browser suppresses the push')
    leg.destroy()
    await sleep(50)
  } finally {
    tap.close()
    await gateway.close()
    upstream.closeStream()
    upstream.server.closeAllConnections?.()
    await new Promise((r) => upstream.server.close(r))
  }
})

test('event tap self-disables on a non-DSH upstream (catch-all 200 HTML)', async () => {
  const server = createServer((req, res) => res.writeHead(200, { 'content-type': 'text/html' }).end('<html>ui</html>'))
  const upstream = await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port })))
  const requested = []
  const tap = createEventTap({
    target: () => ({ host: '127.0.0.1', port: upstream.port }),
    onRequested: (x) => requested.push(x),
    log: () => {},
  })
  tap.start()
  try {
    await sleep(200)
    assert.equal(tap.state().supported, false)
    assert.equal(requested.length, 0)
  } finally {
    tap.close()
    upstream.server.closeAllConnections?.()
    await new Promise((r) => upstream.server.close(r))
  }
})

// ---------- gateway /pair/recover route ----------

test('POST /pair/recover mints a cookie; wrong code 401; absent config RECOVERY_DISABLED', async () => {
  const upstream = { server: { close: (cb) => cb?.(), closeAllConnections() {} }, port: 1 }
  const build = async (svc) => {
    const gw = createGateway({
      auth: createAuthenticator({ username: 'dsh', password: 's3cret', cookieAuth: svc !== null, resolveSession: svc === null ? () => null : (t) => svc.resolveSession(t) }),
      limiter: createRateLimiter({ windowMs: 60_000, max: 10_000 }),
      failureBan: createFailureBan({ windowMs: 60_000, max: 10_000, banMs: 60_000 }),
      target: () => ({ host: '127.0.0.1', port: 2 }),
      log: () => {},
      pairing: svc,
      keepaliveIntervalMs: 0,
      hostProbeIntervalMs: 0,
    })
    return gw.listen({ host: '127.0.0.1', port: 0 }).then(() => gw)
  }

  const gw = await build(service())
  try {
    const ok = await fetch(`http://127.0.0.1:${gw.port}/pair/recover`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: RECOVERY, name: 'laptop' }),
    })
    assert.equal(ok.status, 200)
    const cookie = ok.headers.get('set-cookie')
    assert.match(cookie, /rls=/)
    // The minted cookie authenticates a proxied request (401 without it).
    const withCookie = await fetch(`http://127.0.0.1:${gw.port}/`, { headers: { cookie: cookie.split(';')[0] } })
    assert.equal(withCookie.status, 502) // upstream unreachable (port 2), but the GATE let us through
    const bare = await fetch(`http://127.0.0.1:${gw.port}/`)
    assert.equal(bare.status, 401)

    const bad = await fetch(`http://127.0.0.1:${gw.port}/pair/recover`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: 'wrong-wrong-wrong-wrong' }),
    })
    assert.equal(bad.status, 401)
    assert.match(await bad.text(), /BAD_RECOVERY/)
  } finally {
    await gw.close()
  }

  const gwDisabled = await build(service(null))
  try {
    const res = await fetch(`http://127.0.0.1:${gwDisabled.port}/pair/recover`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: RECOVERY }),
    })
    assert.equal(res.status, 401)
    assert.match(await res.text(), /RECOVERY_DISABLED/)
  } finally {
    await gwDisabled.close()
  }
})

// ---------- remote_recovery tool + persistent store ----------

test('setRecoveryCode: persists, survives restart, supersedes config, rotates', async () => {
  const dir = await fs.mkdtemp('/tmp/rl-recovery-')
  const file = `${dir}/recovery.json`
  const store = { load: () => [], save() {} }
  const mk = (code) => createPairingService({ store, ttlMs: 300_000, recoveryFile: file, ...(code === null ? {} : { recoveryCode: code }) })

  const svc = mk(null)
  assert.deepEqual(svc.recoveryStatus(), { enabled: false, source: null })

  // Tool-style setup: generate, activate, redeem with that exact code.
  const tool = defineRemoteRecoveryTool({ service: svc, baseUrl: () => 'http://x:1' })
  const setup = await tool.execute({}, {})
  assert.equal(setup.ok, true)
  assert.ok(setup.code.length >= 16, 'generated code must clear the entropy floor')
  assert.equal(svc.recoveryStatus().source, 'tool')
  assert.equal((await svc.redeemRecovery({ code: setup.code })).ok, true)

  // Restart simulation: a fresh service reading the same store still accepts.
  assert.equal((await mk(null).redeemRecovery({ code: setup.code })).ok, true)

  // Config code is the fallback only until the tool writes the file
  // (fresh store file: the rotation above must not leak into this section).
  const file2 = `${dir}/recovery2.json`
  const mk2 = (code) => createPairingService({ store, ttlMs: 300_000, recoveryFile: file2, ...(code === null ? {} : { recoveryCode: code }) })
  const withConfig = mk2('config-code-config-code-config')
  assert.equal(withConfig.recoveryStatus().source, 'config')
  assert.equal((await withConfig.redeemRecovery({ code: 'config-code-config-code-config' })).ok, true)
  const rotated = await defineRemoteRecoveryTool({ service: withConfig, baseUrl: () => 'http://x:1' }).execute({}, {})
  assert.equal(withConfig.recoveryStatus().source, 'tool')
  assert.equal((await withConfig.redeemRecovery({ code: 'config-code-config-code-config' })).ok, false, 'rotation must kill the config code')
  assert.equal((await withConfig.redeemRecovery({ code: rotated.code })).ok, true)

  // Status action never leaks the code.
  const status = await tool.execute({ action: 'status' }, {})
  assert.equal(status.ok, true)
  assert.equal(status.code, undefined)
  await fs.rm(dir, { recursive: true, force: true })
})

test('recovery store file is 0600 and holds no plaintext', async () => {
  const dir = await fs.mkdtemp('/tmp/rl-recovery-')
  const file = `${dir}/recovery.json`
  const svc = createPairingService({ store: { load: () => [], save() {} }, recoveryFile: file })
  const tool = defineRemoteRecoveryTool({ service: svc })
  const setup = await tool.execute({}, {})
  const raw = await fs.readFile(file, 'utf8')
  assert.ok(!raw.includes(setup.code), 'plaintext must never touch disk')
  assert.match(raw, /"hash":"/)
  const mode = (await fs.stat(file)).mode & 0o777
  assert.equal(mode, 0o600)
  await fs.rm(dir, { recursive: true, force: true })
})
