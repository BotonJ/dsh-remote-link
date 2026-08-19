import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHmac } from 'node:crypto'
import { apply, pickLanAddress } from '../src/index.js'

function fakeCtx() {
  const registered = []
  const disposers = []
  const provided = {}
  return {
    registered,
    disposers,
    provided,
    tools: { register(def) { registered.push(def) } },
    provide(name, value) { provided[name] = value; return () => {} },
    inject(names, cb) {
      // v1 tests don't exercise fork_session; satisfy the lazy captures with
      // whatever services exist on this fake context.
      const scoped = {}
      for (const n of names) scoped[n] = this[n]
      cb(scoped)
    },
    // cordis semantics: the argument runs immediately and returns the disposer
    effect(setup) { disposers.push(setup()); return () => {} },
  }
}

async function startUpstream() {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' })
    res.end('<html>dsh ui</html>')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, port: server.address().port }
}

const devicesFile = () => join(mkdtempSync(join(tmpdir(), 'rl-devices-')), 'devices.json')
const waitStartup = () => new Promise((resolve) => setTimeout(resolve, 150))

test('pickLanAddress prefers a real LAN IPv4 over loopback/internal/v6', () => {
  const pick = (ifaces) => pickLanAddress(ifaces)?.address ?? null
  assert.equal(pick({
    lo0: [{ family: 'IPv4', address: '127.0.0.1', internal: true }],
    en0: [{ family: 'IPv4', address: '192.168.1.23', internal: false }],
  }), '192.168.1.23')
  assert.equal(pick({
    en0: [{ family: 'IPv6', address: 'fe80::1', internal: false }],
    en1: [{ family: 'IPv4', address: '10.0.0.5', internal: false }],
  }), '10.0.0.5')
  assert.equal(pick({ lo0: [{ family: 'IPv4', address: '127.0.0.1', internal: true }] }), null)
})

test('apply registers fork_session + remote_qr + remote_devices + remote_recovery; Basic still works', async () => {
  const upstream = await startUpstream()
  const ctx = fakeCtx()
  ctx.webServer = { port: upstream.port }

  apply(ctx, { host: '127.0.0.1', port: 0, password: 'pw', pairing: { devicesFile: devicesFile() } })
  await waitStartup()

  try {
    assert.deepEqual(ctx.registered.map((t) => t.name), ['fork_session', 'remote_qr', 'remote_devices', 'remote_recovery'])
    const auth = `Basic ${Buffer.from('dsh:pw').toString('base64')}`
    const ok = await fetch(`http://127.0.0.1:${ctx.provided.remoteLinkGateway.port}/`, { headers: { authorization: auth } })
    assert.equal(ok.status, 200)
    assert.equal(await ok.text(), '<html>dsh ui</html>')
  } finally {
    for (const dispose of ctx.disposers) await dispose()
    await new Promise((resolve) => { upstream.server.close(resolve); upstream.server.closeAllConnections?.() })
  }
})

test('pairing-enabled flow: /pair page, cookie issuance, UI access without password', async () => {
  const upstream = await startUpstream()
  const ctx = fakeCtx()
  ctx.webServer = { port: upstream.port }

  apply(ctx, { host: '127.0.0.1', port: 0, pairing: { devicesFile: devicesFile() } })
  await waitStartup()
  const port = ctx.provided.remoteLinkGateway.port

  try {
    const page = await fetch(`http://127.0.0.1:${port}/pair`)
    assert.equal(page.status, 200)
    assert.match(await page.text(), /DSH Remote Link 配对/)

    const denied = await fetch(`http://127.0.0.1:${port}/`)
    assert.equal(denied.status, 401)
    assert.equal(denied.headers.get('www-authenticate'), null, 'no Basic popup in cookie-only mode')

    // remote_qr tool mints the pairing; replay the page's protocol by hand
    const qrTool = ctx.registered.find((t) => t.name === 'remote_qr')
    const qr = await qrTool.execute({}, { token: 't' })
    assert.equal(qr.ok, true)
    const [, sid, secret] = qr.url.match(/#p=([^.]+)\.(.+)$/)
    const challenge = await (await fetch(`http://127.0.0.1:${port}/pair/challenge?sid=${encodeURIComponent(sid)}`)).json()
    assert.equal(challenge.sid, sid)
    const proof = createHmac('sha256', Buffer.from(secret)).update(`${sid}|${challenge.nonce}|${challenge.ts}`).digest('hex')
    const verify = await fetch(`http://127.0.0.1:${port}/pair/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sid, ts: challenge.ts, proof, name: 'test-suite' }),
    })
    assert.equal(verify.status, 200)
    assert.match(verify.headers.get('set-cookie'), /HttpOnly/)

    const cookie = verify.headers.get('set-cookie').split(';')[0]
    const ui = await fetch(`http://127.0.0.1:${port}/`, { headers: { cookie } })
    assert.equal(ui.status, 200)
    assert.equal(await ui.text(), '<html>dsh ui</html>')

    // remote_devices sees the paired device; revoke kills the session
    const devicesTool = ctx.registered.find((t) => t.name === 'remote_devices')
    const listed = await devicesTool.execute({ action: 'list' }, { token: 't' })
    assert.equal(listed.devices.length, 1)
    assert.equal(listed.devices[0].name, 'test-suite')
    await devicesTool.execute({ action: 'revoke', target: 'test-suite' }, { token: 't' })
    const revoked = await fetch(`http://127.0.0.1:${port}/`, { headers: { cookie } })
    assert.equal(revoked.status, 401, 'revoked device loses access immediately')
  } finally {
    for (const dispose of ctx.disposers) await dispose()
    await new Promise((resolve) => { upstream.server.close(resolve); upstream.server.closeAllConnections?.() })
  }
})

test('security baseline: non-loopback without password AND without pairing refuses to load', () => {
  const ctx = fakeCtx()
  assert.throws(() => apply(ctx, { host: '0.0.0.0', port: 3081, pairing: { enabled: false } }), { code: 'E_NO_PASSWORD' })
  assert.equal(ctx.registered.length, 0)
})

test('remote_qr re-mints after the pairing is consumed — no dead QR on any surface (P2-6 regression)', async () => {
  const upstream = await startUpstream()
  const ctx = fakeCtx()
  ctx.webServer = { port: upstream.port }
  apply(ctx, { host: '127.0.0.1', port: 0, pairing: { devicesFile: devicesFile() } })
  await waitStartup()
  const port = ctx.provided.remoteLinkGateway.port

  try {
    const qrTool = ctx.registered.find((t) => t.name === 'remote_qr')
    const first = await qrTool.execute({}, { token: 't' })
    const [, sid, secret] = first.url.match(/#p=([^.]+)\.(.+)$/)

    // Consume the pairing exactly like the phone would.
    const challenge = await (await fetch(`http://127.0.0.1:${port}/pair/challenge?sid=${encodeURIComponent(sid)}`)).json()
    const proof = createHmac('sha256', Buffer.from(secret)).update(`${sid}|${challenge.nonce}|${challenge.ts}`).digest('hex')
    const verify = await fetch(`http://127.0.0.1:${port}/pair/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sid, ts: challenge.ts, proof }),
    })
    assert.equal(verify.status, 200)

    // Within the old TTL, the tool must hand out a FRESH pairing — before
    // the fix it returned the consumed one and phones scanned a dead QR.
    const second = await qrTool.execute({}, { token: 't' })
    assert.equal(second.ok, true)
    assert.notEqual(second.url, first.url, 'consumed pairing must never be re-displayed')
    assert.notEqual(second.shortCode, first.shortCode)

    // And the fresh one is genuinely redeemable.
    const [, sid2, secret2] = second.url.match(/#p=([^.]+)\.(.+)$/)
    const ch2 = await (await fetch(`http://127.0.0.1:${port}/pair/challenge?sid=${encodeURIComponent(sid2)}`)).json()
    assert.equal(ch2.sid, sid2, 're-minted pairing answers challenges')
    void secret2
  } finally {
    for (const dispose of ctx.disposers) await dispose()
    await new Promise((resolve) => { upstream.server.close(resolve); upstream.server.closeAllConnections?.() })
  }
})

test('disposers shut the gateway down', async () => {
  const upstream = await startUpstream()
  const ctx = fakeCtx()
  ctx.webServer = { port: upstream.port }
  apply(ctx, { host: '127.0.0.1', port: 0, password: 'pw', pairing: { devicesFile: devicesFile() } })
  await waitStartup()
  const port = ctx.provided.remoteLinkGateway.port
  try {
    for (const dispose of ctx.disposers) await dispose()
    let refused = false
    try {
      await fetch(`http://127.0.0.1:${port}/`)
    } catch {
      refused = true
    }
    assert.equal(refused, true, 'gateway no longer accepts connections')
  } finally {
    for (const dispose of ctx.disposers) await dispose()
    await new Promise((resolve) => { upstream.server.close(resolve); upstream.server.closeAllConnections?.() })
  }
})
