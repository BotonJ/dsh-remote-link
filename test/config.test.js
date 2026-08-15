import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeConfig } from '../src/config.js'

test('refuses default non-loopback bind without a password (security baseline)', () => {
  assert.throws(
    () => normalizeConfig({}),
    { code: 'E_NO_PASSWORD' },
  )
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
