/**
 * Zero-dependency QR encoder (byte mode, ECC level L, versions 1–10) with a
 * terminal-friendly half-block ASCII renderer, replacing the bonjour-service
 * era habit of pulling a dependency for one job. Block/ecc tables follow the
 * QR specification (cross-checked against nayuki/QR-Code-generator, MIT).
 *
 * Exported surface used by tests and the remote_qr tool:
 *   pickVersion(text) → smallest fitting version (1–10)
 *   encodeQr(text, {border}) → { version, size, get(row, col), bordered, mask }
 *   rsComputeEcc(dataBytes, degree) → Uint8Array
 *   renderAscii(qr) → half-block art string
 */

const DATA_CODEWORDS = [19, 34, 55, 80, 108, 136, 156, 194, 232, 274] // L, v1–10
const ECC_PER_BLOCK = [7, 10, 15, 20, 26, 18, 20, 24, 30, 18]
const BLOCKS = [1, 1, 1, 1, 1, 2, 2, 2, 2, 4]
const ALIGNMENT = {
  2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
  7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}
const MAX_BYTES = DATA_CODEWORDS[9]

// ---- GF(2^8), reduction polynomial 0x11D ----
const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)
for (let i = 0, x = 1; i < 255; i += 1) {
  EXP[i] = x
  LOG[x] = i
  x <<= 1
  if (x & 0x100) x ^= 0x11d
}
for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255]
const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]])

export function rsComputeEcc(data, degree) {
  let gen = [1]
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(gen.length + 1).fill(0)
    for (let j = 0; j < gen.length; j += 1) {
      next[j] ^= gfMul(gen[j], EXP[i])
      next[j + 1] ^= gen[j]
    }
    gen = next
  }
  const rem = new Array(degree).fill(0)
  for (const byte of data) {
    const factor = byte ^ rem.shift()
    rem.push(0)
    for (let i = 0; i < degree; i += 1) rem[i] ^= gfMul(gen[i + 1], factor)
  }
  return Uint8Array.from(rem)
}

export function pickVersion(text) {
  const bytes = Buffer.from(String(text), 'utf8')
  if (bytes.length > MAX_BYTES) throw new Error(`payload too long for QR v10 (${bytes.length} bytes)`)
  for (let v = 1; v <= 10; v += 1) {
    const countBits = v <= 9 ? 8 : 16
    if (4 + countBits + 8 * bytes.length <= 8 * DATA_CODEWORDS[v - 1]) return v
  }
  throw new Error('payload too long')
}

function buildCodewords(text, version) {
  const bytes = Buffer.from(String(text), 'utf8')
  const capacity = DATA_CODEWORDS[version - 1]
  const bits = []
  const push = (value, count) => { for (let i = count - 1; i >= 0; i -= 1) bits.push((value >> i) & 1) }
  push(0b0100, 4) // byte mode
  push(bytes.length, version <= 9 ? 8 : 16)
  for (const byte of bytes) push(byte, 8)
  const capacityBits = capacity * 8
  push(0, Math.min(4, capacityBits - bits.length)) // terminator
  while (bits.length % 8 !== 0) bits.push(0)
  const data = []
  for (let i = 0; i < bits.length; i += 8) {
    data.push(bits.slice(i, i + 8).reduce((acc, b) => (acc << 1) | b, 0))
  }
  for (let pad = 0xec; data.length < capacity; pad ^= 0xec ^ 0x11) data.push(pad)

  const blockCount = BLOCKS[version - 1]
  const eccLen = ECC_PER_BLOCK[version - 1]
  const shortLen = Math.floor(capacity / blockCount)
  const remainder = capacity % blockCount
  const blocks = []
  let offset = 0
  for (let i = 0; i < blockCount; i += 1) {
    const len = shortLen + (i >= blockCount - remainder ? 1 : 0)
    blocks.push({ data: data.slice(offset, offset + len), ecc: rsComputeEcc(data.slice(offset, offset + len), eccLen) })
    offset += len
  }
  const out = []
  const maxLen = shortLen + (remainder > 0 ? 1 : 0)
  for (let i = 0; i < maxLen; i += 1) {
    for (const block of blocks) {
      if (i < block.data.length) out.push(block.data[i])
    }
  }
  for (let i = 0; i < eccLen; i += 1) {
    for (const block of blocks) out.push(block.ecc[i])
  }
  return Uint8Array.from(out)
}

function newMatrix(version) {
  const size = 17 + 4 * version
  const modules = Array.from({ length: size }, () => new Array(size).fill(false))
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false))
  return { size, modules, isFunction }
}

function mark(matrix, row, col, dark) {
  matrix.modules[row][col] = dark
  matrix.isFunction[row][col] = true
}

function drawFunctionPatterns(matrix, version) {
  const { size } = matrix
  // timing patterns
  for (let i = 0; i < size; i += 1) {
    mark(matrix, 6, i, i % 2 === 0)
    mark(matrix, i, 6, i % 2 === 0)
  }
  // finders + separators
  const finder = (r0, c0) => {
    for (let r = -1; r <= 7; r += 1) {
      for (let c = -1; c <= 7; c += 1) {
        const row = r0 + r
        const col = c0 + c
        if (row < 0 || row >= size || col < 0 || col >= size) continue
        const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3))
        mark(matrix, row, col, r >= 0 && r <= 6 && c >= 0 && c <= 6 ? ring !== 1 : false)
      }
    }
  }
  finder(0, 0)
  finder(0, size - 7)
  finder(size - 7, 0)
  // alignment patterns (skip any overlapping a finder)
  const centers = ALIGNMENT[version] ?? []
  for (const r of centers) {
    for (const c of centers) {
      if (matrix.isFunction[r][c]) continue
      for (let dr = -2; dr <= 2; dr += 1) {
        for (let dc = -2; dc <= 2; dc += 1) {
          mark(matrix, r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1)
        }
      }
    }
  }
  // reserve format areas (real bits written per mask later)
  for (let i = 0; i <= 8; i += 1) {
    if (i !== 6) { mark(matrix, 8, i, false); mark(matrix, i, 8, false) }
  }
  for (let i = 0; i < 8; i += 1) mark(matrix, 8, size - 1 - i, false)
  for (let i = 0; i < 7; i += 1) mark(matrix, size - 1 - i, 8, false)
  mark(matrix, size - 8, 8, true) // dark module
  // version info (v7+), 18 bits, BCH with generator 0x1F25
  if (version >= 7) {
    let rem = version
    for (let i = 0; i < 12; i += 1) rem = (rem << 1) ^ ((rem >> 11) * 0x1f25)
    const bits = (version << 12) | (rem & 0xfff)
    for (let i = 0; i < 18; i += 1) {
      const bit = ((bits >> i) & 1) !== 0
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      mark(matrix, b, a, bit) // top-right
      mark(matrix, a, b, bit) // bottom-left
    }
  }
}

function drawFormatBits(matrix, mask) {
  const data = (0b01 << 3) | mask // ECC level L = 01
  let rem = data
  for (let i = 0; i < 10; i += 1) rem = (rem << 1) ^ ((rem >> 9) * 0x537)
  const bits = ((data << 10) | (rem & 0x3ff)) ^ 0x5412
  const { size } = matrix
  const bit = (i) => ((bits >> i) & 1) !== 0
  for (let i = 0; i <= 5; i += 1) mark(matrix, 8, i, bit(i))
  mark(matrix, 8, 7, bit(6))
  mark(matrix, 8, 8, bit(7))
  mark(matrix, 7, 8, bit(8))
  for (let i = 9; i < 15; i += 1) mark(matrix, 14 - i, 8, bit(i))
  for (let i = 0; i < 8; i += 1) mark(matrix, 8, size - 1 - i, bit(i))
  for (let i = 8; i < 15; i += 1) mark(matrix, size - 15 + i, 8, bit(i))
  mark(matrix, size - 8, 8, true)
}

function placeCodewords(matrix, codewords) {
  const { size, modules, isFunction } = matrix
  let bitIndex = 0
  const totalBits = codewords.length * 8
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < size; vert += 1) {
      for (let j = 0; j < 2; j += 1) {
        const col = right - j
        const upward = ((right + 1) & 2) === 0
        const row = upward ? size - 1 - vert : vert
        if (isFunction[row][col]) continue
        if (bitIndex < totalBits) {
          modules[row][col] = ((codewords[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1) !== 0
          bitIndex += 1
        } else {
          modules[row][col] = false // remainder bits
        }
      }
    }
  }
}

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
]

function applyMask(matrix, mask) {
  const { size, modules, isFunction } = matrix
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (!isFunction[r][c] && MASKS[mask](r, c)) modules[r][c] = !modules[r][c]
    }
  }
}

function penalty(modules) {
  const size = modules.length
  let score = 0
  // N1: runs of same color ≥5
  for (let r = 0; r < size; r += 1) {
    let runC = 1
    for (let c = 1; c < size; c += 1) {
      if (modules[r][c] === modules[r][c - 1]) {
        runC += 1
        if (runC === 5) score += 3
        else if (runC > 5) score += 1
      } else runC = 1
    }
  }
  for (let c = 0; c < size; c += 1) {
    let runR = 1
    for (let r = 1; r < size; r += 1) {
      if (modules[r][c] === modules[r - 1][c]) {
        runR += 1
        if (runR === 5) score += 3
        else if (runR > 5) score += 1
      } else runR = 1
    }
  }
  // N2: 2×2 blocks
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const m = modules[r][c]
      if (m === modules[r][c + 1] && m === modules[r + 1][c] && m === modules[r + 1][c + 1]) score += 3
    }
  }
  // N3: finder-like 1011101 with 4 light on a side
  const pattern = [true, false, true, true, true, false, true, false, false, false, false]
  const matches = (get) => {
    for (let i = 0; i < pattern.length; i += 1) if (get(i) !== pattern[i]) return false
    return true
  }
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c + 11 <= size; c += 1) {
      if (matches((i) => modules[r][c + i])) score += 40
    }
  }
  for (let c = 0; c < size; c += 1) {
    for (let r = 0; r + 11 <= size; r += 1) {
      if (matches((i) => modules[r + i][c])) score += 40
    }
  }
  // N4: dark proportion
  let dark = 0
  for (const row of modules) for (const cell of row) if (cell) dark += 1
  score += Math.floor(Math.abs((dark * 100) / (size * size) - 50) / 5) * 10
  return score
}

function cloneMatrix(matrix) {
  return {
    size: matrix.size,
    modules: matrix.modules.map((row) => [...row]),
    isFunction: matrix.isFunction,
  }
}

export function encodeQr(text, { border = 0 } = {}) {
  const version = pickVersion(text)
  const codewords = buildCodewords(text, version)
  const base = newMatrix(version)
  drawFunctionPatterns(base, version)
  placeCodewords(base, codewords)

  let best = null
  let bestScore = Infinity
  let bestMask = 0
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = cloneMatrix(base)
    applyMask(candidate, mask)
    drawFormatBits(candidate, mask)
    const score = penalty(candidate.modules)
    if (score < bestScore) {
      bestScore = score
      best = candidate
      bestMask = mask
    }
  }

  const bordered = Array.from({ length: best.size + 2 * border }, () => new Array(best.size + 2 * border).fill(false))
  for (let r = 0; r < best.size; r += 1) {
    for (let c = 0; c < best.size; c += 1) bordered[r + border][c + border] = best.modules[r][c]
  }
  return {
    version,
    mask: bestMask,
    size: best.size,
    bordered,
    get: (row, col) => best.modules[row][col],
  }
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
