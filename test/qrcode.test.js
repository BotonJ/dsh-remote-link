import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeQr, pickVersion, rsComputeEcc, renderAscii } from '../src/qrcode.js'

// Independent GF(2^8) implementation (log/antilog tables) to cross-check the
// encoder's Reed-Solomon output — deliberately a different style from src.
const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)
;(function initGf() {
  let x = 1
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x
    LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255]
})()
function gfMul(a, b) {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]
}
function independentEcc(data, degree) {
  // generator g(x) = prod (x - alpha^i)
  let gen = [1]
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(gen.length + 1).fill(0)
    for (let j = 0; j < gen.length; j += 1) {
      next[j] ^= gfMul(gen[j], EXP[i])
      next[j + 1] ^= gen[j]
    }
    gen = next
  }
  // remainder of data·x^degree mod gen (synthetic division, MSB first)
  const rem = new Array(degree).fill(0)
  for (const byte of data) {
    const factor = byte ^ rem[0]
    rem.shift()
    rem.push(0)
    for (let i = 0; i < degree; i += 1) rem[i] ^= gfMul(gen[i + 1], factor)
  }
  return rem
}

test('picks the smallest version that fits a byte-mode payload', () => {
  assert.equal(pickVersion('hello'), 1)
  assert.equal(pickVersion('x'.repeat(17)), 1)         // V1-L byte capacity is 17
  assert.equal(pickVersion('x'.repeat(18)), 2)
  const url = `http://192.168.1.100:3081/#p=${'a'.repeat(22)}.${'b'.repeat(43)}`
  assert.ok(pickVersion(url) >= 4 && pickVersion(url) <= 6, `pairing URL → ${pickVersion(url)}`)
  assert.throws(() => pickVersion('x'.repeat(300)), /too long/i)
})

test('matrix structure: size, finders, timing, dark module, completeness', () => {
  const { size, get } = encodeQr('hello')
  assert.equal(size, 21)
  const finderAt = (r0, c0) => {
    for (let r = 0; r < 7; r += 1) {
      for (let c = 0; c < 7; c += 1) {
        const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3))
        if (get(r0 + r, c0 + c) !== (ring !== 1)) return false
      }
    }
    return true
  }
  assert.ok(finderAt(0, 0) && finderAt(0, size - 7) && finderAt(size - 7, 0), 'three finder patterns')
  for (let i = 8; i < size - 8; i += 1) {
    assert.equal(get(6, i), i % 2 === 0, 'timing row')
    assert.equal(get(i, 6), i % 2 === 0, 'timing column')
  }
  assert.equal(get(size - 8, 8), true, 'dark module')
  // every module assigned (no undefined in the grid)
  for (let r = 0; r < size; r += 1) for (let c = 0; c < size; c += 1) assert.ok(typeof get(r, c) === 'boolean')
})

test('alignment pattern appears at (18,18) for version 2', () => {
  const { size, get } = encodeQr('x'.repeat(25))
  assert.equal(size, 25)
  for (let r = -2; r <= 2; r += 1) {
    for (let c = -2; c <= 2; c += 1) {
      const ring = Math.max(Math.abs(r), Math.abs(c))
      assert.equal(get(18 + r, 18 + c), ring !== 1, 'alignment ring')
    }
  }
})

test('format info: 15-bit BCH parity is valid and mask id is recoverable', () => {
  const { size, get } = encodeQr('hello')
  // collect format bits (copy 1)
  let bits = 0
  const take = (bit, i) => { if (bit) bits |= 1 << i }
  for (let i = 0; i <= 5; i += 1) take(get(8, i), i)
  take(get(8, 7), 6)
  take(get(8, 8), 7)
  take(get(7, 8), 8)
  for (let i = 9; i < 15; i += 1) take(get(14 - i, 8), i)
  const unmasked = bits ^ 0x5412
  // BCH(15,5) check with generator 0x537
  let rem = unmasked
  for (let i = 14; i >= 10; i -= 1) {
    if (rem & (1 << i)) rem ^= 0x537 << (i - 10)
  }
  assert.equal(rem, 0, 'format parity holds')
  const data = unmasked >> 10
  assert.equal(data >> 3, 0b01, 'ECC level L')
  const maskId = data & 7
  assert.ok(maskId >= 0 && maskId < 8, 'mask id in range')
})

test('Reed-Solomon ecc matches an independent GF implementation (multi-block versions too)', () => {
  assert.deepEqual(rsComputeEcc([0x10, 0x20, 0x0c, 0x56, 0x71, 0x80, 0xe6], 7),
    Uint8Array.from(independentEcc([0x10, 0x20, 0x0c, 0x56, 0x71, 0x80, 0xe6], 7)))
  const data = Array.from({ length: 120 }, (_, i) => (i * 37 + 11) & 0xff)
  assert.deepEqual(rsComputeEcc(data, 26), Uint8Array.from(independentEcc(data, 26)))
  assert.deepEqual(rsComputeEcc(data, 18), Uint8Array.from(independentEcc(data, 18)))
})

test('ASCII render is square-ish and uses half blocks', () => {
  const ascii = renderAscii(encodeQr('hello'))
  const lines = ascii.split('\n').filter((l) => l.length > 0)
  assert.ok(lines.length >= 10)
  assert.ok(ascii.includes('█') || ascii.includes('▀') || ascii.includes('▄'))
})

test('quiet-zone border: all-white margin around the symbol', () => {
  const { size, get, bordered } = encodeQr('hello', { border: 2 })
  assert.equal(bordered.length, size + 4)
  for (let r = 0; r < 2; r += 1) {
    for (let c = 0; c < bordered.length; c += 1) {
      assert.equal(bordered[r][c], false)
      assert.equal(bordered[bordered.length - 1 - r][c], false)
    }
  }
})
