import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createAuthenticator, safeEqual, parseBasicAuth, extractToken } from '../src/auth.js'

function req({ authorization, url = '/' } = {}) {
  return { headers: authorization === undefined ? {} : { authorization }, url }
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

test('extractToken pulls the token query param from request URLs', () => {
  assert.equal(extractToken('/api/events.mux?token=abc'), 'abc')
  assert.equal(extractToken('/?a=1&token=x%20y'), 'x y')
  assert.equal(extractToken('/plain'), null)
  assert.equal(extractToken(''), null)
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

test('token query param authenticates (browser WebSocket cannot set headers)', () => {
  const auth = createAuthenticator({ username: 'dsh', password: 's3cret' })
  assert.deepEqual(auth.check(req({ url: '/api/events.mux?token=s3cret' })), { ok: true, via: 'token' })
  assert.equal(auth.check(req({ url: '/api/events.mux?token=wrong' })).ok, false)
  assert.equal(auth.check(req({ url: '/api/events.mux?token=' })).ok, false)
})

test('Basic header takes precedence over token when both are present', () => {
  const auth = createAuthenticator({ username: 'dsh', password: 's3cret' })
  const bad = `Basic ${Buffer.from('dsh:wrong').toString('base64')}`
  assert.equal(auth.check(req({ authorization: bad, url: '/?token=s3cret' })).ok, false)
})
