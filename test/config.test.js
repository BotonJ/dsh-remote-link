import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeConfig } from '../src/config.js'

test('default non-loopback bind without a password is allowed because pairing is on (v1.5)', () => {
  const cfg = normalizeConfig({})
  assert.equal(cfg.pairing.enabled, true)
  assert.equal(cfg.password, '')
})

test('loopback bind without a password is allowed', () => {
  const cfg = normalizeConfig({ host: '127.0.0.1', password: '' })
  assert.equal(cfg.host, '127.0.0.1')
  assert.equal(cfg.password, '')
  assert.equal(cfg.port, 3081)
  assert.equal(cfg.username, 'dsh')
  assert.equal(cfg.mdns, true)
})

test('non-loopback bind with a password passes and gets defaults', () => {
  const cfg = normalizeConfig({ password: 's3cret' })
  assert.equal(cfg.host, '0.0.0.0')
  assert.equal(cfg.password, 's3cret')
  assert.equal(cfg.username, 'dsh')
  assert.equal(cfg.port, 3081)
  assert.deepEqual(cfg.rateLimit, { windowMs: 60_000, max: 300 })
  assert.deepEqual(cfg.authFailure, { windowMs: 300_000, max: 10, banMs: 300_000 })
  assert.deepEqual(cfg.target, { host: '127.0.0.1', port: null })
})

test('explicit values override defaults', () => {
  const cfg = normalizeConfig({
    host: '192.168.1.5', port: 4000, username: 'alice', password: 'pw',
    targetHost: '127.0.0.2', targetPort: 9999, mdns: false,
    rateLimit: { windowMs: 1000, max: 5 },
  })
  assert.equal(cfg.host, '192.168.1.5')
  assert.equal(cfg.port, 4000)
  assert.equal(cfg.username, 'alice')
  assert.equal(cfg.mdns, false)
  assert.equal(cfg.target.host, '127.0.0.2')
  assert.equal(cfg.target.port, 9999)
  assert.deepEqual(cfg.rateLimit, { windowMs: 1000, max: 5 })
  // authFailure keeps defaults when only rateLimit is overridden
  assert.deepEqual(cfg.authFailure, { windowMs: 300_000, max: 10, banMs: 300_000 })
})

test('rejects invalid ports but allows 0 for an ephemeral gateway port', () => {
  assert.equal(normalizeConfig({ password: 'x', port: 0 }).port, 0)
  for (const port of [-1, 65536, '3081', 1.5]) {
    assert.throws(() => normalizeConfig({ password: 'x', port }), { code: 'E_CONFIG' })
  }
})

test('rejects invalid hosts and non-string credentials', () => {
  assert.throws(() => normalizeConfig({ host: '', password: 'x' }), { code: 'E_CONFIG' })
  assert.throws(() => normalizeConfig({ host: 123, password: 'x' }), { code: 'E_CONFIG' })
  assert.throws(() => normalizeConfig({ password: 123 }), { code: 'E_CONFIG' })
  assert.throws(() => normalizeConfig({ password: 'x', username: 5 }), { code: 'E_CONFIG' })
})

test('pairing defaults: enabled, 5min TTL, 30d sessions, 90d device idle expiry', () => {
  const cfg = normalizeConfig({ password: 'x' })
  assert.deepEqual(cfg.pairing, { enabled: true, ttlMs: 300_000, sessionMaxAgeDays: 30, deviceIdleExpiryDays: 90, devicesFile: null })
  const custom = normalizeConfig({ password: 'x', pairing: { enabled: false, ttlMs: 60_000 } })
  assert.deepEqual(custom.pairing, { enabled: false, ttlMs: 60_000, sessionMaxAgeDays: 30, deviceIdleExpiryDays: 90, devicesFile: null })
  assert.throws(() => normalizeConfig({ password: 'x', pairing: { ttlMs: 0 } }), { code: 'E_CONFIG' })
  assert.throws(() => normalizeConfig({ password: 'x', pairing: { bogus: 1 } }), { code: 'E_CONFIG' })
})

test('security baseline passes on non-loopback with pairing enabled and no password', () => {
  const cfg = normalizeConfig({ host: '0.0.0.0', pairing: { enabled: true } })
  assert.equal(cfg.password, '')
  // pairing disabled restores the v1 rule: non-loopback needs a password
  assert.throws(() => normalizeConfig({ host: '0.0.0.0', pairing: { enabled: false } }), { code: 'E_NO_PASSWORD' })
})
