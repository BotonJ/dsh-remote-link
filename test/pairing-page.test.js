import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { HMAC_SHA256_JS, PAIRING_PAGE_HTML } from '../src/pairing-page.js'

const pageHmac = new Function(`${HMAC_SHA256_JS}; return hmacSha256Hex`)()
const nodeHmac = (key, msg) => createHmac('sha256', Buffer.from(key, 'utf8')).update(msg, 'utf8').digest('hex')

test('embedded pure-JS HMAC matches node:crypto across key sizes and charsets', () => {
  const cases = [
    ['kui-test-3081', 'sid|nonce|1755234567890'],
    ['a'.repeat(64), 'x'],                 // key exactly at block size
    ['b'.repeat(65), 'longer-than-block-key gets rehashed inside HMAC'],
    ['c'.repeat(200), 'even longer key'],
    ['', 'empty key'],
    ['secret', ''],
    ['AbC123_-~.+=/\\u4e2d\\u6587' + String.fromCharCode(0xf0f0), 'non-ascii message € 你好'],
    ['k', 'm'.repeat(1000)],
  ]
  for (const [key, msg] of cases) {
    assert.equal(pageHmac(key, msg), nodeHmac(key, msg), `mismatch for key length ${key.length}`)
  }
})

test('page wires the v1.5 protocol: fragment secret, short-code entry, verify body', () => {
  assert.match(PAIRING_PAGE_HTML, /#p=/, 'reads the pairing fragment')
  assert.match(PAIRING_PAGE_HTML, /\/pair\/challenge\?/, 'fetches a challenge')
  assert.match(PAIRING_PAGE_HTML, /\/pair\/verify/, 'posts the proof')
  assert.match(PAIRING_PAGE_HTML, /maxlength="?6"?/, 'short-code input')
  assert.match(PAIRING_PAGE_HTML, /inputmode=["']?numeric/, 'numeric keyboard on phones')
  assert.ok(PAIRING_PAGE_HTML.includes(HMAC_SHA256_JS), 'embeds the HMAC implementation')
  assert.match(PAIRING_PAGE_HTML, /encodeURIComponent\(/, 'sid/code URL-encoded')
  assert.doesNotMatch(PAIRING_PAGE_HTML, /crypto\.subtle/, 'must not rely on secure-context APIs')
  // proof message must match the server convention sid|nonce|ts
  assert.match(PAIRING_PAGE_HTML, /sid\s*\+\s*['"]\|['"]\s*\+\s*[^+]+\+\s*['"]\|['"]\s*\+\s*[A-Za-z.]*ts/)
})
