import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeName, parseQuery, buildResponse, parseResponse, TYPE } from '../src/dns-codec.js'

function buildQueryPacket({ id = 0x1234, name = 'dsh._http._tcp.local', type = TYPE.PTR } = {}) {
  const parts = [
    Buffer.from([id >> 8, id & 0xff]), // id
    Buffer.from([0x00, 0x00]), // flags: standard query
    Buffer.from([0x00, 0x01]), // qdcount
    Buffer.from([0x00, 0x00]), // ancount
    Buffer.from([0x00, 0x00]), // nscount
    Buffer.from([0x00, 0x00]), // arcount
    encodeName(name),
    Buffer.from([type >> 8, type & 0xff, 0x00, 0x01]), // type, class IN
  ]
  return Buffer.concat(parts)
}

test('encodeName produces length-prefixed labels with a null terminator', () => {
  assert.deepEqual(
    [...encodeName('_http._tcp.local')],
    [5, ...Buffer.from('_http'), 4, ...Buffer.from('_tcp'), 5, ...Buffer.from('local'), 0],
  )
})

test('parseQuery reads id, question name (case-folded), type, and class', () => {
  const packet = buildQueryPacket({ id: 0xbeef, name: 'DSH.Remote._TCP.local' })
  const query = parseQuery(packet)
  assert.equal(query.id, 0xbeef)
  assert.equal(query.questions.length, 1)
  assert.equal(query.questions[0].name, 'dsh.remote._tcp.local')
  assert.equal(query.questions[0].type, TYPE.PTR)
  assert.equal(query.questions[0].qclass, 1)
})

test('parseQuery returns null for malformed input', () => {
  assert.equal(parseQuery(Buffer.alloc(4)), null) // too short
  assert.equal(parseQuery(Buffer.alloc(64)), null) // claims questions but truncated
  const response = buildQueryPacket()
  response[2] |= 0x80 // QR=1
  assert.equal(parseQuery(response), null, 'responses are not queries')
  const opcode = buildQueryPacket()
  opcode[2] |= 0x08 // opcode 1
  assert.equal(parseQuery(opcode), null, 'non-standard opcode rejected')
})

test('parseQuery follows compression pointers in question names', () => {
  // Two questions: the first carries the full name at offset 12, the second
  // compresses its name to a pointer back at the first one.
  const name = encodeName('dsh._http._tcp.local')
  const typeClass = Buffer.from([TYPE.PTR >> 8, TYPE.PTR & 0xff, 0x00, 0x01])
  const head = Buffer.from([0x12, 0x34, 0x00, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0])
  const pointer = Buffer.from([0xc0, 0x0c])
  const packet = Buffer.concat([head, name, typeClass, pointer, typeClass])
  const query = parseQuery(packet)
  assert.equal(query.questions.length, 2)
  assert.equal(query.questions[0].name, 'dsh._http._tcp.local')
  assert.equal(query.questions[1].name, 'dsh._http._tcp.local', 'pointer resolved to the same name')
})

test('PTR/A/TXT/SRV answers roundtrip through buildResponse and parseResponse', () => {
  const packet = buildQueryPacket({ id: 0x0042, name: 'dsh._http._tcp.local', type: TYPE.PTR })
  const query = parseQuery(packet)
  const response = buildResponse(query, [
    { name: 'dsh._http._tcp.local', type: TYPE.PTR, ttl: 120, data: 'dsh@MacBook.local._http._tcp.local' },
    { name: 'dsh@MacBook.local._http._tcp.local', type: TYPE.SRV, ttl: 120, data: { priority: 0, weight: 0, port: 3081, target: 'MacBook.local' } },
    { name: 'dsh@MacBook.local._http._tcp.local', type: TYPE.TXT, ttl: 120, data: { path: '/', auth: 'basic' } },
    { name: 'MacBook.local', type: TYPE.A, ttl: 120, data: '192.168.1.23' },
  ])
  const parsed = parseResponse(response)
  assert.equal(parsed.id, 0x0042)
  assert.equal(parsed.flags & 0x8000, 0x8000, 'QR set')
  assert.equal(parsed.flags & 0x0400, 0x0400, 'AA set')
  assert.equal(parsed.questions.length, 1)
  assert.equal(parsed.questions[0].name, 'dsh._http._tcp.local', 'question echoed back')
  assert.equal(parsed.answers.length, 4)
  assert.deepEqual(parsed.answers.map((a) => a.type), [TYPE.PTR, TYPE.SRV, TYPE.TXT, TYPE.A])
  assert.equal(parsed.answers[0].rdata.name, 'dsh@macbook.local._http._tcp.local')
  assert.deepEqual(parsed.answers[1].rdata, { priority: 0, weight: 0, port: 3081, target: 'macbook.local' })
  assert.deepEqual(parsed.answers[2].rdata, { path: '/', auth: 'basic' })
  assert.equal(parsed.answers[3].rdata.address, '192.168.1.23')
})

test('TXT entries longer than 255 bytes are chunked into multiple strings', () => {
  const long = 'x'.repeat(300)
  const packet = buildQueryPacket({ name: 'dsh._http._tcp.local', type: TYPE.TXT })
  const response = buildResponse(parseQuery(packet), [
    { name: 'dsh._http._tcp.local', type: TYPE.TXT, ttl: 60, data: { big: long } },
  ])
  const parsed = parseResponse(response)
  assert.equal(parsed.answers[0].rdata.big, long)
})
