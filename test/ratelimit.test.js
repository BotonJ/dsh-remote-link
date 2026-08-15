import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRateLimiter, createFailureBan } from '../src/ratelimit.js'

function clock(start = 0) {
  let t = start
  return { now: () => t, advance: (ms) => { t += ms } }
}

test('rate limiter allows up to max requests per window then blocks with retry time', () => {
  const c = clock()
  const limiter = createRateLimiter({ windowMs: 1000, max: 3, now: c.now })
  assert.deepEqual(limiter.check('a'), { allowed: true, remaining: 2, retryAfterMs: 1000 })
  assert.equal(limiter.check('a').allowed, true)
  const third = limiter.check('a')
  assert.equal(third.allowed, true)
  assert.equal(third.remaining, 0)
  const blocked = limiter.check('a')
  assert.equal(blocked.allowed, false)
  assert.equal(blocked.retryAfterMs, 1000)
})

test('rate limiter window resets after windowMs and keys are independent', () => {
  const c = clock()
  const limiter = createRateLimiter({ windowMs: 1000, max: 1, now: c.now })
  assert.equal(limiter.check('a').allowed, true)
  assert.equal(limiter.check('a').allowed, false)
  assert.equal(limiter.check('b').allowed, true, 'separate key has its own budget')
  c.advance(1001)
  assert.equal(limiter.check('a').allowed, true, 'window rolled over')
})

test('failure ban activates after max failures within the window and expires after banMs', () => {
  const c = clock()
  const ban = createFailureBan({ windowMs: 1000, max: 3, banMs: 5000, now: c.now })
  ban.recordFailure('1.2.3.4')
  ban.recordFailure('1.2.3.4')
  assert.equal(ban.isBanned('1.2.3.4').banned, false)
  ban.recordFailure('1.2.3.4')
  const banned = ban.isBanned('1.2.3.4')
  assert.equal(banned.banned, true)
  assert.equal(banned.retryAfterMs, 5000)
  assert.equal(ban.isBanned('5.6.7.8').banned, false, 'other clients unaffected')

  c.advance(5001)
  assert.equal(ban.isBanned('1.2.3.4').banned, false, 'ban expired')
})

test('failure window slides: stale failures drop out, success clears the client', () => {
  const c = clock()
  const ban = createFailureBan({ windowMs: 1000, max: 2, banMs: 10_000, now: c.now })
  ban.recordFailure('ip')
  c.advance(1500)
  ban.recordFailure('ip')
  assert.equal(ban.isBanned('ip').banned, false, 'first failure aged out of the window')

  ban.recordFailure('ip')
  assert.equal(ban.isBanned('ip').banned, true)

  const fresh = createFailureBan({ windowMs: 1000, max: 2, banMs: 10_000, now: c.now })
  fresh.recordFailure('ip')
  fresh.recordSuccess('ip')
  fresh.recordFailure('ip')
  assert.equal(fresh.isBanned('ip').banned, false, 'success reset the failure count')
})

test('banned client is not re-banned forever: ban window outranks failures', () => {
  const c = clock(10_000)
  const ban = createFailureBan({ windowMs: 1000, max: 1, banMs: 3000, now: c.now })
  ban.recordFailure('ip')
  assert.equal(ban.isBanned('ip').banned, true)
  c.advance(1000)
  ban.recordFailure('ip')
  const still = ban.isBanned('ip')
  assert.equal(still.banned, true)
  assert.ok(still.retryAfterMs <= 2000, `retryAfterMs reflects the original ban end, got ${still.retryAfterMs}`)
})
