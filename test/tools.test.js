import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPairingService } from '../src/pairing.js'
import { defineRemoteQrTool, defineRemoteDevicesTool } from '../src/tools.js'

function serviceFixture(now = () => 1_000_000) {
  const store = { load: () => [], save() {} }
  return createPairingService({ store, ttlMs: 300_000, now })
}

function qrTool(overrides = {}) {
  const service = overrides.service ?? createPairingService({ store: { load: () => [], save() {} }, ttlMs: 300_000, now: () => 1_000_000 })
  return defineRemoteQrTool({
    createPairing: () => service.createPairing(),
    baseUrl: () => 'http://192.168.1.23:3081',
    qrImageUrl: () => 'http://127.0.0.1:3081/qr.png?v=1234',
    now: () => 1_000_000,
    ...overrides,
    service,
  })
}

test('remote_qr mints a fresh pairing with URL, short code, and expiry evidence', async () => {
  const service = serviceFixture()
  const tool = qrTool({ service })
  assert.equal(tool.name, 'remote_qr')
  const result = await tool.execute({}, { token: 't' })
  assert.equal(result.ok, true)
  assert.match(result.url, /^http:\/\/192\.168\.1\.23:3081\/pair#p=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
  assert.match(result.shortCode, /^\d{6}$/)
  assert.equal(result.expiresAt, 1_300_000)
  assert.equal(result.secondsLeft, 300)
  assert.equal(service.challenge(result.url.split('#p=')[1].split('.')[0]) !== null, true, 'URL sid is live')
})

test('remote_qr render inlines the PNG image markdown, the URL, and the short code', async () => {
  const tool = qrTool({ service: serviceFixture() })
  const result = await tool.execute({}, { token: 't' })
  const text = tool.output.render({}, result).map((b) => b.text).join('\n')
  assert.match(text, /!\[[^\]]*\]\(http:\/\/127\.0\.0\.1:3081\/qr\.png\?v=\d+\)/, 'inlines the gateway PNG as markdown image')
  assert.ok(!text.includes('▀') && !text.includes('▄') && !text.includes('█'), 'no half-block art in chat (chat fonts garble it)')
  assert.ok(!text.includes('```'), 'no code fence needed for a raster image')
  assert.ok(text.includes(result.url))
  assert.ok(text.includes(result.shortCode))
  assert.doesNotThrow(() => tool.output.render({}, null))
})

test('remote_devices lists, revokes by id/name, and revoke-all', async () => {
  const service = serviceFixture()
  const tool = defineRemoteDevicesTool({ service })
  assert.equal(tool.name, 'remote_devices')

  const a = service.createPairing()
  const cha = service.challenge(a.sid)
  const { createHmac } = await import('node:crypto')
  const proof = createHmac('sha256', Buffer.from(a.secret)).update(`${a.sid}|${cha.nonce}|${cha.ts}`).digest('hex')
  const ok = await service.verify({ sid: a.sid, ts: cha.ts, proof })
  service.renameDevice(ok.deviceId, 'my-phone')

  const listed = await tool.execute({ action: 'list' }, { token: 't' })
  assert.equal(listed.ok, true)
  assert.equal(listed.devices.length, 1)
  assert.equal(listed.devices[0].name, 'my-phone')
  assert.ok(listed.devices[0].lastSeenAt !== undefined)

  const revoked = await tool.execute({ action: 'revoke', target: 'my-phone' }, { token: 't' })
  assert.deepEqual(revoked, { ok: true, revoked: 1 })
  assert.deepEqual((await tool.execute({ action: 'list' }, { token: 't' })).devices, [])

  const b = service.createPairing()
  const chb = service.challenge(b.sid)
  const proofB = createHmac('sha256', Buffer.from(b.secret)).update(`${b.sid}|${chb.nonce}|${chb.ts}`).digest('hex')
  await service.verify({ sid: b.sid, ts: chb.ts, proof: proofB })
  assert.deepEqual(await tool.execute({ action: 'revoke-all' }, { token: 't' }), { ok: true, revoked: 1 })
})

test('remote_devices validates its inputs', async () => {
  const tool = defineRemoteDevicesTool({ service: serviceFixture() })
  assert.equal((await tool.execute({}, { token: 't' })).error, 'BAD_ACTION')
  assert.equal((await tool.execute({ action: 'explode' }, { token: 't' })).error, 'BAD_ACTION')
  assert.equal((await tool.execute({ action: 'revoke' }, { token: 't' })).error, 'BAD_TARGET')
  assert.equal((await tool.execute({ action: 'revoke', target: 'ghost' }, { token: 't' })).revoked, 0)
  assert.doesNotThrow(() => tool.output.render({}, null))
})
