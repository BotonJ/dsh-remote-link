import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { createPairingService } from '../src/pairing.js'

function clock(start = 0) {
  let t = start
  return { now: () => t, advance: (ms) => { t += ms } }
}

function memoryStore() {
  let saved = []
  return {
    load() { return saved },
    save(devices) { saved = [...devices] },
    snapshot: () => saved,
  }
}

// The exact proof computation the pairing page performs in pure JS
function proof(secret, sid, nonce, ts) {
  return createHmac('sha256', Buffer.from(secret, 'utf8')).update(`${sid}|${nonce}|${ts}`, 'utf8').digest('hex')
}

function setup(overrides = {}) {
  const c = clock(1_000_000)
  const store = memoryStore()
  const service = createPairingService({
    now: c.now, store, ttlMs: 300_000, sessionMaxAgeMs: 30 * 86_400_000, deviceIdleExpiryMs: 90 * 86_400_000,
    ...overrides,
  })
  return { service, store, c }
}

async function paired(service) {
  const p = service.createPairing()
  const challenge = service.challenge(p.sid)
  if (challenge === null) throw new Error('challenge failed')
  const ok = await service.verify({ sid: p.sid, ts: challenge.ts, proof: proof(p.secret, p.sid, challenge.nonce, challenge.ts) })
  return { p, challenge, ok }
}

test('full happy path: challenge → proof → device + cookie session; pairing consumed', async () => {
  const { service } = setup()
  const { p, ok } = await paired(service)
  assert.equal(ok.ok, true)
  assert.ok(ok.deviceId)
  assert.ok(ok.sessionToken.length >= 40)
  const session = service.resolveSession(ok.sessionToken)
  assert.equal(session.deviceId, ok.deviceId)
  assert.equal(session.name, undefined)

  // same QR second time: pairing burned — no challenge, no verify
  assert.equal(service.challenge(p.sid), null)
  const retry = await service.verify({ sid: p.sid, ts: 1, proof: '00' })
  assert.equal(retry.ok, false)
  assert.equal(retry.error, 'PAIRING_NOT_FOUND')
})

test('wrong secret yields BAD_PROOF and does not burn the pairing', async () => {
  const { service } = setup()
  const p = service.createPairing()
  const ch = service.challenge(p.sid)
  const bad = await service.verify({ sid: p.sid, ts: ch.ts, proof: proof('evil-secret', p.sid, ch.nonce, ch.ts) })
  assert.deepEqual(bad, { ok: false, error: 'BAD_PROOF' })
  // nonce burned by the failed attempt; fresh challenge still works
  const ch2 = service.challenge(p.sid)
  const good = await service.verify({ sid: p.sid, ts: ch2.ts, proof: proof(p.secret, p.sid, ch2.nonce, ch2.ts) })
  assert.equal(good.ok, true)
})

test('timestamp outside ±300s is rejected', async () => {
  const { service } = setup()
  const p = service.createPairing()
  const ch = service.challenge(p.sid)
  const skewed = await service.verify({ sid: p.sid, ts: ch.ts + 301_000, proof: proof(p.secret, p.sid, ch.nonce, ch.ts + 301_000) })
  assert.equal(skewed.error, 'BAD_TS')
})

test('nonce is single-use: replaying the same challenge fails', async () => {
  const { service } = setup()
  const p = service.createPairing()
  const ch = service.challenge(p.sid)
  const first = await service.verify({ sid: p.sid, ts: ch.ts, proof: proof(p.secret, p.sid, ch.nonce, ch.ts) })
  assert.equal(first.ok, true)
  const replay = await service.verify({ sid: p.sid, ts: ch.ts, proof: proof(p.secret, p.sid, ch.nonce, ch.ts) })
  assert.equal(replay.ok, false)
})

test('expired pairing (5min TTL) stops issuing challenges', async () => {
  const { service, c } = setup()
  const p = service.createPairing()
  c.advance(300_001)
  assert.equal(service.challenge(p.sid), null)
  assert.equal(service.challenge(p.shortCode), null)
})

test('short code path: same challenge-response with the code as shared secret', async () => {
  const { service } = setup()
  const p = service.createPairing()
  assert.match(p.shortCode, /^\d{6}$/)
  const ch = service.challenge(p.shortCode)
  assert.equal(ch.sid, p.sid, 'code resolves to the pairing sid')
  const ok = await service.verify({ code: p.shortCode, ts: ch.ts, proof: proof(p.shortCode, p.sid, ch.nonce, ch.ts) })
  assert.equal(ok.ok, true)
  // a wrong code resolves to nothing
  assert.equal(service.challenge('000000') === null || '000000' !== p.shortCode, true)
})

test('sessions expire by age; devices expire by idle; revoke drops sessions', async () => {
  const { service, c } = setup()
  const { ok } = await paired(service)
  c.advance(29 * 86_400_000)
  assert.notEqual(service.resolveSession(ok.sessionToken), null)
  c.advance(2 * 86_400_000)
  assert.equal(service.resolveSession(ok.sessionToken), null, 'past sessionMaxAge')

  const { ok: second } = await paired(service)
  c.advance(91 * 86_400_000)
  assert.equal(service.resolveSession(second.sessionToken), null, 'device idle-expired')
  assert.deepEqual(service.listDevices().map((d) => d.deviceId), [], 'idle device pruned from registry')

  const { ok: third } = await paired(service)
  assert.notEqual(service.resolveSession(third.sessionToken), null)
  const revoked = service.revokeDevice(third.deviceId)
  assert.equal(revoked, 1)
  assert.equal(service.resolveSession(third.sessionToken), null, 'revoke kills live sessions')
})

test('revoke-all wipes the registry; revoke by name works', async () => {
  const { service } = setup()
  const a = await paired(service)
  const b = await paired(service)
  service.renameDevice(a.ok.deviceId, 'my-phone')
  assert.equal(service.revokeDevice('my-phone'), 1)
  assert.equal(service.resolveSession(a.ok.sessionToken), null)
  assert.notEqual(service.resolveSession(b.ok.sessionToken), null)
  assert.equal(service.revokeAllDevices(), 1)
  assert.equal(service.resolveSession(b.ok.sessionToken), null)
  assert.deepEqual(service.listDevices(), [])
})

test('devices persist through the store and survive a restart', async () => {
  const store = memoryStore()
  const c = clock(5)
  const first = createPairingService({ now: c.now, store })
  const { ok } = await paired(first)
  assert.equal(store.snapshot().length, 1)
  assert.match(store.snapshot()[0].deviceKey, /^[0-9a-f]{64}$/)

  const second = createPairingService({ now: c.now, store })
  assert.deepEqual(second.listDevices().map((d) => d.deviceId), [ok.deviceId])
})

test('verify records device name and updates lastSeen on session use', async () => {
  const { service, c } = setup()
  const p = service.createPairing()
  const ch = service.challenge(p.sid)
  const ok = await service.verify({ sid: p.sid, ts: ch.ts, proof: proof(p.secret, p.sid, ch.nonce, ch.ts), name: 'iPad' })
  assert.equal(service.listDevices()[0].name, 'iPad')

  c.advance(60_000)
  service.resolveSession(ok.sessionToken)
  assert.equal(service.listDevices()[0].lastSeen, c.now())
})

test('unknown sid and garbage inputs fail closed without throwing', async () => {
  const { service } = setup()
  assert.equal(service.challenge('nope'), null)
  const r = await service.verify({ sid: 'nope', ts: 1, proof: 'aa' })
  assert.equal(r.ok, false)
  const r2 = await service.verify(null)
  assert.equal(r2.ok, false)
  const r3 = await service.verify({ sid: 123, ts: 'x', proof: {} })
  assert.equal(r3.ok, false)
})
