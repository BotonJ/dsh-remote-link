/**
 * QR encoding for dsh-remote-link, built on the battle-tested
 * Kazuhiko Arase "QRCode for JavaScript" engine (vendored from
 * qrcode-terminal@0.12.0, MIT; see src/vendor/QRCode/NOTICE.md).
 *
 * The plugin's earlier hand-written encoder produced structurally
 * self-consistent but scanner-invalid codes (finder ring polarity, a
 * transposed format-info layout, and reversed Reed–Solomon coefficient
 * order), so encoding was swapped to the vendored, globally-verified
 * implementation. ECC level is L (matching the pairing URLs' needs).
 *
 * Exported surface (unchanged from before, used by index.js, tools.js and
 * scripts/vision-decode.mjs):
 *   pickVersion(text) → smallest fitting version (1–40, auto)
 *   encodeQr(text, {border}) → { version, mask, size, get(row,col), bordered }
 *   rsComputeEcc(dataBytes, degree) → Uint8Array
 *   renderAscii(qr) → half-block terminal art
 */

import QRCode from './vendor/QRCode/index.js'
import { deflateSync } from 'node:zlib'
import QRErrorCorrectLevel from './vendor/QRCode/QRErrorCorrectLevel.js'
import QRUtil from './vendor/QRCode/QRUtil.js'
import QRPolynomial from './vendor/QRCode/QRPolynomial.js'
import qrcodeTerminal from './vendor/qrcode-terminal.js'

const ECC_LEVEL = QRErrorCorrectLevel.L // 1

export function pickVersion(text) {
  const qrcode = new QRCode(-1, ECC_LEVEL) // -1 = auto version (1–40)
  qrcode.addData(String(text))
  qrcode.make()
  return qrcode.typeNumber
}

/** Thin wrapper over the vendored RS machinery (createBytes convention). */
export function rsComputeEcc(data, degree) {
  const rsPoly = QRUtil.getErrorCorrectPolynomial(degree)
  const rawPoly = new QRPolynomial(data, rsPoly.getLength() - 1)
  const modPoly = rawPoly.mod(rsPoly)
  const out = new Array(degree).fill(0)
  const offset = modPoly.getLength() - degree
  for (let i = 0; i < degree; i += 1) {
    out[i] = offset + i >= 0 ? modPoly.get(offset + i) : 0
  }
  return Uint8Array.from(out)
}

/** Recover the chosen mask id from format-info copy 1 (true positions). */
function readMask(qrcode) {
  let bits = 0
  const take = (v, i) => { if (v) bits |= 1 << i }
  for (let i = 0; i <= 5; i += 1) take(qrcode.isDark(i, 8), i)
  take(qrcode.isDark(7, 8), 6)
  take(qrcode.isDark(8, 8), 7)
  take(qrcode.isDark(8, 7), 8)
  for (let i = 9; i < 15; i += 1) take(qrcode.isDark(8, 14 - i), i)
  return ((bits ^ 0x5412) >> 10) & 7
}

export function encodeQr(text, { border = 0 } = {}) {
  const qrcode = new QRCode(-1, ECC_LEVEL)
  qrcode.addData(String(text))
  qrcode.make()
  const size = qrcode.getModuleCount()
  const get = (row, col) => qrcode.isDark(row, col)
  const bordered = Array.from({ length: size + 2 * border }, () => new Array(size + 2 * border).fill(false))
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) bordered[r + border][c + border] = get(r, c)
  }
  return {
    version: qrcode.typeNumber,
    mask: readMask(qrcode),
    size,
    bordered,
    get,
  }
}

/**
 * Terminal QR art via the vendored qrcode-terminal renderer (the same
 * engine MiMo uses: `QRCode.generate(url, { small: !large })`). Small mode
 * uses half-block Unicode characters (compact); `small:false` uses ANSI
 * background-color blocks (needs a color terminal). Wrap the output in a
 * fenced code block when embedding in chat so it renders monospace.
 */
export function renderQr(text, { small = true } = {}) {
  let out = ''
  qrcodeTerminal.generate(String(text), { small }, (qr) => { out = qr })
  return out
}

/** Half-block terminal art: two symbol rows per text row. */
export function renderAscii(qr, { border = 2 } = {}) {
  const grid = qr.bordered.length > qr.size ? qr.bordered : withBorder(qr, border)
  const lines = []
  for (let r = 0; r < grid.length; r += 2) {
    let line = ''
    for (let c = 0; c < grid[r].length; c += 1) {
      const top = grid[r][c]
      const bottom = grid[r + 1] !== undefined && grid[r + 1][c]
      line += top && bottom ? '█' : top ? '▀' : bottom ? '▄' : ' '
    }
    lines.push(line)
  }
  return lines.join('\n')
}

function withBorder(qr, border) {
  const size = qr.size + 2 * border
  const grid = Array.from({ length: size }, () => new Array(size).fill(false))
  for (let r = 0; r < qr.size; r += 1) {
    for (let c = 0; c < qr.size; c += 1) grid[r + border][c + border] = qr.get(r, c)
  }
  return grid
}

/**
 * Render the QR as a real PNG (8-bit grayscale, quiet zone `border` modules,
 * `scale` px per module) — the chat-friendly form: the official Web UI's
 * markdown renders absolute http(s) images directly, and a raster PNG cannot
 * be broken by chat fonts the way half-block terminal art can.
 */
export function renderPng(text, { scale = 12, border = 4 } = {}) {
  const qr = encodeQr(text, { border })
  const modules = qr.bordered.length
  const px = modules * scale
  const rows = Buffer.alloc(px * (px + 1))
  for (let r = 0; r < px; r += 1) {
    const base = r * (px + 1)
    rows[base] = 0 // filter type 0 per scanline
    for (let c = 0; c < px; c += 1) {
      rows[base + 1 + c] = qr.bordered[Math.floor(r / scale)][Math.floor(c / scale)] ? 0 : 255
    }
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(px, 0)
  ihdr.writeUInt32BE(px, 4)
  ihdr[8] = 8 // bit depth
  ihdr[9] = 0 // grayscale
  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(rows)),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])

function pngChunk(type, data) {
  const out = Buffer.alloc(8 + data.length + 4)
  out.writeUInt32BE(data.length, 0)
  out.write(type, 4, 'ascii')
  data.copy(out, 8)
  out.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])), 8 + data.length)
  return out
}

function crc32(buf) {
  let c
  const table = []
  for (let n = 0; n < 256; n += 1) {
    c = n
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[n] = c >>> 0
  }
  let crc = 0xffffffff
  for (const byte of buf) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}
