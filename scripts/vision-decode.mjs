/**
 * OPTIONAL real-decoder round-trip for manual verification:
 *   node scripts/vision-decode.mjs "payload"
 * Renders the QR to a PNG (hand-rolled chunks + zlib) and decodes it with
 * macOS Vision via a tiny Swift snippet. Not part of the test suite.
 */
import { deflateSync } from 'node:zlib'
import { writeFileSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { encodeQr } from '../src/qrcode.js'

const payload = process.argv[2] ?? 'http://192.168.1.100:3081/pair#p=AAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const qr = encodeQr(payload, { border: 4 })
const scale = 8
const px = qr.bordered.length * scale

const rows = []
for (let r = 0; r < px; r += 1) {
  const row = Buffer.alloc(1 + Math.ceil(px / 8), 0)
  row[0] = 0 // filter: none
  for (let c = 0; c < px; c += 1) {
    // 1-bit grayscale PNG: 0 = black, 1 = white. Dark modules must render
    // black, so set bits for the light (background) modules only.
    if (!qr.bordered[Math.floor(r / scale)][Math.floor(c / scale)]) {
      row[1 + (c >> 3)] |= 0x80 >> (c & 7)
    }
  }
  rows.push(row)
}
const ihdr = Buffer.alloc(13)
ihdr.writeUInt32BE(px, 0)
ihdr.writeUInt32BE(px, 4)
ihdr[8] = 1 // 1-bit grayscale
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
const chunk = (type, data) => {
  const out = Buffer.alloc(8 + data.length + 4)
  out.writeUInt32BE(data.length, 0)
  out.write(type, 4, 'ascii')
  data.copy(out, 8)
  out.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])), 8 + data.length)
  return out
}
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(Buffer.concat(rows))),
  chunk('IEND', Buffer.alloc(0)),
])
const dir = mkdtempSync(join(tmpdir(), 'qr-'))
const pngPath = join(dir, 'qr.png')
writeFileSync(pngPath, png)
console.log('png written:', pngPath)

const swift = `
import Vision
import CoreImage
let img = CIImage(contentsOf: URL(fileURLWithPath: "${pngPath}"))!
let req = VNDetectBarcodesRequest()
try VNImageRequestHandler(ciImage: img).perform([req])
var out = ""
for obs in (req.results ?? []) {
  if let payload = obs.payloadStringValue { out += payload }
}
if out.isEmpty { exit(2) }
FileHandle.standardOutput.write(Data(out.utf8))
`
const swiftPath = join(dir, 'decode.swift')
writeFileSync(swiftPath, swift)
const decoded = execFileSync('swift', [swiftPath], { encoding: 'utf8', timeout: 120_000 }).trim()
console.log('decoded:', decoded)
console.log(decoded === payload ? 'ROUND-TRIP OK' : `MISMATCH\nexpected: ${payload}`)
