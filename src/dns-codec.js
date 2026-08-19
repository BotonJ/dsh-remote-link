/**
 * Minimal DNS wire-format codec for the plugin's mDNS responder.
 *
 * Only what DNS-SD browsing needs: parsing queries (with compression-pointer
 * names), and encoding responses carrying A / PTR / SRV / TXT records.
 * Responses are written without name compression — every name is spelled out
 * in full — which is valid DNS and understood by every resolver.
 */

export const TYPE = Object.freeze({ A: 1, PTR: 12, TXT: 16, SRV: 33 })

const CLASS_IN = 1
const MAX_LABEL = 63
// RFC 1035 §4.1.4: a domain name is at most 255 octets. Without this cap a
// crafted query (long label run + compression pointer back into it) makes the
// pointer hops re-traverse the whole run, burning ~1ms of event-loop CPU per
// kilobyte of packet — a cheap remote stall against the gateway process.
const MAX_NAME_BYTES = 255
const MAX_TXT_STRING = 255

export function encodeName(name) {
  const parts = []
  for (const label of String(name).replace(/\.$/, '').split('.')) {
    const bytes = Buffer.from(label, 'utf8')
    if (bytes.length === 0 || bytes.length > MAX_LABEL) {
      throw new Error(`invalid DNS label "${label}"`)
    }
    parts.push(Buffer.from([bytes.length]), bytes)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

/**
 * Read a possibly-compressed domain name. Returns `{ name, next }` with the
 * name lowercased for case-insensitive matching, or null when malformed.
 */
function readName(buf, offset) {
  const labels = []
  let pos = offset
  let jumped = false
  let next = -1
  let hops = 0
  let nameBytes = 0
  for (;;) {
    if (pos >= buf.length) return null
    const length = buf[pos]
    if (length === 0) {
      if (!jumped) next = pos + 1
      break
    }
    if ((length & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) return null
      if (!jumped) next = pos + 2
      pos = ((length & 0x3f) << 8) | buf[pos + 1]
      if (pos >= buf.length || ++hops > 32) return null
      jumped = true
      continue
    }
    if (length > MAX_LABEL || pos + 1 + length > buf.length) return null
    nameBytes += 1 + length
    if (nameBytes > MAX_NAME_BYTES) return null
    labels.push(buf.subarray(pos + 1, pos + 1 + length).toString('utf8'))
    pos += 1 + length
  }
  return { name: labels.join('.').toLowerCase(), next }
}

function readQuestions(buf, count, start) {
  const questions = []
  let pos = start
  for (let i = 0; i < count; i += 1) {
    const name = readName(buf, pos)
    if (name === null || name.next + 4 > buf.length) return null
    questions.push({
      name: name.name,
      type: buf.readUInt16BE(name.next),
      qclass: buf.readUInt16BE(name.next + 2),
    })
    pos = name.next + 4
  }
  return questions
}

export function parseQuery(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null
  const flags = buf.readUInt16BE(2)
  if ((flags & 0x8000) !== 0) return null // response, not query
  if (((flags >> 11) & 0x0f) !== 0) return null // non-standard opcode
  const qdcount = buf.readUInt16BE(4)
  if (qdcount < 1) return null
  const questions = readQuestions(buf, qdcount, 12)
  if (questions === null) return null
  return { id: buf.readUInt16BE(0), questions }
}

function encodeTxt(data) {
  const parts = []
  for (const [key, value] of Object.entries(data)) {
    const entry = Buffer.from(`${key}=${value}`, 'utf8')
    for (let offset = 0; offset < entry.length; offset += MAX_TXT_STRING) {
      const chunk = entry.subarray(offset, Math.min(offset + MAX_TXT_STRING, entry.length))
      parts.push(Buffer.from([chunk.length]), chunk)
    }
  }
  // mDNS requires non-empty TXT rdata
  return parts.length === 0 ? Buffer.from([0]) : Buffer.concat(parts)
}

function encodeRdata(answer) {
  switch (answer.type) {
    case TYPE.PTR:
      return encodeName(answer.data)
    case TYPE.A: {
      const octets = String(answer.data).split('.').map(Number)
      if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
        throw new Error(`invalid IPv4 address "${answer.data}"`)
      }
      return Buffer.from(octets)
    }
    case TYPE.SRV:
      return Buffer.concat([
        Buffer.from([answer.data.priority >> 8, answer.data.priority & 0xff]),
        Buffer.from([answer.data.weight >> 8, answer.data.weight & 0xff]),
        Buffer.from([answer.data.port >> 8, answer.data.port & 0xff]),
        encodeName(answer.data.target),
      ])
    case TYPE.TXT:
      return encodeTxt(answer.data)
    default:
      throw new Error(`unsupported record type ${answer.type}`)
  }
}

/** Build a query response: authoritative answer, one echoed question, answers appended without compression. */
export function buildResponse(query, answers) {
  const question = query.questions[0]
  const sections = [
    Buffer.from([query.id >> 8, query.id & 0xff]),
    Buffer.from([0x84, 0x00]), // QR=1, AA=1
    Buffer.from([0x00, 0x01]), // qdcount
    Buffer.from([answers.length >> 8, answers.length & 0xff]),
    Buffer.from([0x00, 0x00]), // nscount
    Buffer.from([0x00, 0x00]), // arcount
    encodeName(question.name),
    Buffer.from([question.type >> 8, question.type & 0xff, question.qclass >> 8, question.qclass & 0xff]),
  ]
  for (const answer of answers) {
    const rdata = encodeRdata(answer)
    sections.push(
      encodeName(answer.name),
      Buffer.from([answer.type >> 8, answer.type & 0xff]),
      Buffer.from([CLASS_IN >> 8, CLASS_IN & 0xff]),
      Buffer.from([answer.ttl >> 24, (answer.ttl >> 16) & 0xff, (answer.ttl >> 8) & 0xff, answer.ttl & 0xff]),
      Buffer.from([rdata.length >> 8, rdata.length & 0xff]),
      rdata,
    )
  }
  return Buffer.concat(sections)
}

function readRdata(buf, type, offset, length) {
  const end = offset + length
  if (end > buf.length) return null
  if (type === TYPE.PTR) {
    const name = readName(buf, offset)
    return name === null ? null : { name: name.name }
  }
  if (type === TYPE.A) {
    if (length !== 4) return null
    return { address: `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}` }
  }
  if (type === TYPE.SRV) {
    if (length < 7) return null
    const target = readName(buf, offset + 6)
    return target === null ? null : {
      priority: buf.readUInt16BE(offset),
      weight: buf.readUInt16BE(offset + 2),
      port: buf.readUInt16BE(offset + 4),
      target: target.name,
    }
  }
  if (type === TYPE.TXT) {
    const strings = []
    let pos = offset
    while (pos < end) {
      const len = buf[pos]
      if (pos + 1 + len > end) return null
      strings.push(buf.subarray(pos + 1, pos + 1 + len).toString('utf8'))
      pos += 1 + len
    }
    // A string without '=' is a continuation of the previous entry's value
    // (our writer chunks >255-byte values that way).
    const data = {}
    let pending = null
    for (const entry of strings) {
      const eq = entry.indexOf('=')
      if (eq > 0) {
        if (pending !== null) data[pending.key] = pending.value
        pending = { key: entry.slice(0, eq), value: entry.slice(eq + 1) }
      } else if (pending !== null) {
        pending.value += entry
      }
    }
    if (pending !== null) data[pending.key] = pending.value
    return data
  }
  return { opaque: true }
}

export function parseResponse(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null
  const flags = buf.readUInt16BE(2)
  if ((flags & 0x8000) === 0) return null
  const qdcount = buf.readUInt16BE(4)
  const ancount = buf.readUInt16BE(6)
  const questions = qdcount === 0 ? [] : readQuestions(buf, qdcount, 12)
  if (questions === null) return null
  let pos = questions.length === 0 ? 12 : questionsEndOffset(buf, qdcount)
  const answers = []
  for (let i = 0; i < ancount; i += 1) {
    const name = readName(buf, pos)
    if (name === null || name.next + 10 > buf.length) return null
    const type = buf.readUInt16BE(name.next)
    const ttl = buf.readUInt32BE(name.next + 4)
    const rdlength = buf.readUInt16BE(name.next + 8)
    const rdataOffset = name.next + 10
    const rdata = readRdata(buf, type, rdataOffset, rdlength)
    if (rdata === null) return null
    answers.push({ name: name.name, type, ttl, rdata })
    pos = rdataOffset + rdlength
  }
  return { id: buf.readUInt16BE(0), flags, questions, answers }
}

function questionsEndOffset(buf, qdcount) {
  let pos = 12
  for (let i = 0; i < qdcount; i += 1) {
    const name = readName(buf, pos)
    pos = name.next + 4
  }
  return pos
}
