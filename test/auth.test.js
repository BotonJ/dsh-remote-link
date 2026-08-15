import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createAuthenticator, safeEqual, parseBasicAuth, extractCookie } from '../src/auth.js'

function req({ authorization, url = '/', cookie } = {}) {
  const headers = {}
  if (authorization !== undefined) headers.authorization = authorization
  if (cookie !== undefined) headers.cookie = cookie
  return { headers, url }
}

test('safeEqual matches identical and rejects different strings at any length', () => {
  assert.equal(safeEqual('abc', 'abc'), true)
  assert.equal(safeEqual('abc', 'abd'), false)
  assert.equal(safeEqual('abc', 'abcdef'), false)
  assert.equal(safeEqual('', ''), true)
})

test('parseBasicAuth decodes well-formed headers and rejects malformed ones', () => {
  const b64 = (s) => Buffer.from(s).toString('base64')
  assert.deepEqual(parseBasicAuth(`Basic ${b64('dsh:s3cret')}`), { username: 'dsh', password: 's3cret' })
  assert.deepEqual(parseBasicAuth(`Basic ${b64('user:pa:ss:word')}`), { username: 'user', password: 'pa:ss:word' })
  assert.equal(parseBasicAuth('Bearer xyz'), null)
  assert.equal(parseBasicAuth('Basic !!!not-base64!!!'), null)
  assert.equal(parseBasicAuth(`Basic ${b64('nocolon')}`), null)
  assert.equal(parseBasicAuth(undefined), null)
})

test('extractCookie pulls the rls session cookie from a cookie header', () => {
  assert.equal(extractCookie('rls=tok123'), 'tok123')
  assert.equal(extractCookie('a=1; rls=tok123; b=2'), 'tok123')
  assert.equal(extractCookie('other=tok123'), null)
  assert.equal(extractCookie(undefined), null)
  assert.equal(extractCookie(''), null)
})

test('no password configured: every request passes without auth', () => {
  const auth = createAuthenticator({ username: 'dsh', password: '' })
  assert.equal(auth.required, false)
  assert.deepEqual(auth.check(req()), { ok: true, via: 'none' })
  assert.deepEqual(auth.check(req({ authorization: 'garbage' })), { ok: true, via: 'none' })
})

test('correct Basic credentials pass', () => {
  const auth = createAuthenticator({ username: 'dsh', password: 's3cret' })
  const b64 = Buffer.from('dsh:s3cret').toString('base64')
  assert.deepEqual(auth.check(req({ authorization: `Basic ${b64}` })), { ok: true, via: 'basic' })
})

test('wrong password, wrong username, and missing header all fail', () => {
  const auth = createAuthenticator({ username: 'dsh', password: 's3cret' })
  const b64 = (s) => `Basic ${Buffer.from(s).toString('base64')}`
  assert.equal(auth.check(req({ authorization: b64('dsh:wrong') })).ok, false)
  assert.equal(auth.check(req({ authorization: b64('eve:s3cret') })).ok, false)
  assert.equal(auth.check(req()).ok, false)
  assert.equal(auth.check(req({ authorization: b64('nocolon') })).ok, false)
})

test('valid cookie session authenticates (browser WS/EventSource carrier)', () => {
  const sessions = new Map([['good-token', { deviceId: 'dev-1' }]])
  const auth = createAuthenticator({
    username: 'dsh', password: 's3cret',
    cookieAuth: true, resolveSession: (t) => sessions.get(t) ?? null,
  })
  assert.deepEqual(auth.check(req({ cookie: 'rls=good-token' })), { ok: true, via: 'cookie', deviceId: 'dev-1' })
  assert.equal(auth.check(req({ cookie: 'rls=revoked' })).ok, false)
  assert.equal(auth.check(req({})).ok, false)
})

test('Basic header takes precedence over a stale cookie', () => {
  const auth = createAuthenticator({
    username: 'dsh', password: 's3cret',
    cookieAuth: true, resolveSession: () => null,
  })
  const good = `Basic ${Buffer.from('dsh:s3cret').toString('base64')}`
  assert.deepEqual(auth.check(req({ authorization: good, cookie: 'rls=stale' })).via, 'basic')
  const bad = `Basic ${Buffer.from('dsh:wrong').toString('base64')}`
  assert.equal(auth.check(req({ authorization: bad, cookie: 'rls=stale' })).ok, false)
})

test('cookie-only mode: no password, pairing sessions carry the gate', () => {
  const sessions = new Map([['tok', { deviceId: 'd' }]])
  const auth = createAuthenticator({ username: 'dsh', password: '', cookieAuth: true, resolveSession: (t) => sessions.get(t) ?? null })
  assert.equal(auth.required, true)
  assert.equal(auth.basicEnabled, false)
  assert.equal(auth.check(req({ cookie: 'rls=tok' })).ok, true)
  assert.equal(auth.check(req({})).ok, false)
})

test('query token no longer authenticates (removed in v1.5)', () => {
  const auth = createAuthenticator({ username: 'dsh', password: 's3cret' })
  assert.equal(auth.check(req({ url: '/?token=s3cret' })).ok, false)
})
