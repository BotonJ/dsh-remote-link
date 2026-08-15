import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
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

test('apply registers fork_session and proxies the webserver through an ephemeral gateway', async () => {
  const upstream = await startUpstream()
  const ctx = fakeCtx()
  ctx.webServer = { port: upstream.port }

  apply(ctx, { host: '127.0.0.1', port: 0, password: 'pw' })
  await new Promise((resolve) => setTimeout(resolve, 100)) // let the gateway start listening

  try {
    assert.equal(ctx.registered.length, 1)
    assert.equal(ctx.registered[0].name, 'fork_session')

    const denied = await fetch(`http://127.0.0.1:${ctx.provided.remoteLinkGateway.port}/`)
    assert.equal(denied.status, 401)
    const auth = `Basic ${Buffer.from('dsh:pw').toString('base64')}`
    const ok = await fetch(`http://127.0.0.1:${ctx.provided.remoteLinkGateway.port}/`, { headers: { authorization: auth } })
    assert.equal(ok.status, 200)
    assert.equal(await ok.text(), '<html>dsh ui</html>')
  } finally {
    for (const dispose of ctx.disposers) await dispose()
    await new Promise((resolve) => upstream.server.close(resolve))
  }
})

test('disposers shut the gateway down', async () => {
  const upstream = await startUpstream()
  const ctx = fakeCtx()
  ctx.webServer = { port: upstream.port }
  apply(ctx, { host: '127.0.0.1', port: 0, password: 'pw' })
  await new Promise((resolve) => setTimeout(resolve, 100))
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

test('apply enforces the security baseline for non-loopback binds', () => {
  const ctx = fakeCtx()
  assert.throws(() => apply(ctx, { host: '0.0.0.0', port: 3081 }), { code: 'E_NO_PASSWORD' })
  assert.equal(ctx.registered.length, 0)
})
