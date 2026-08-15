import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createSocket } from 'node:dgram'
import { createAdvertiser } from '../src/mdns.js'
import { TYPE, parseResponse, encodeName } from '../src/dns-codec.js'

const BASE = {
  instance: 'DSH Remote Link on Mac',
  serviceName: 'dsh-remote-link',
  host: 'Mac',
  port: 3081,
  address: '192.168.1.23',
  multicast: false,
  bindPort: 0,
  bindAddress: '127.0.0.1',
}

function queryPacket(id, name, type) {
  return Buffer.concat([
    Buffer.from([id >> 8, id & 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
    encodeName(name),
    Buffer.from([type >> 8, type & 0xff, 0x00, 0x01]),
  ])
}

function ask(port, packet) {
  return new Promise((resolve, reject) => {
    const client = createSocket('udp4')
    const timer = setTimeout(() => { client.close(); resolve(null) }, 1500)
    client.once('message', (msg) => {
      clearTimeout(timer)
      client.close()
      resolve(parseResponse(msg))
    })
    client.once('error', (err) => { clearTimeout(timer); client.close(); reject(err) })
    client.send(packet, port, '127.0.0.1')
  })
}

test('advertiser answers PTR browse queries with PTR+SRV+TXT+A', async () => {
  const ad = createAdvertiser(BASE)
  await ad.start()
  try {
    const res = await ask(ad.port, queryPacket(1, '_http._tcp.local', TYPE.PTR))
    assert.notEqual(res, null, 'got a response')
    const types = res.answers.map((a) => a.type)
    assert.ok(types.includes(TYPE.PTR))
    assert.ok(types.includes(TYPE.SRV))
    assert.ok(types.includes(TYPE.TXT))
    assert.ok(types.includes(TYPE.A))
    const ptr = res.answers.find((a) => a.type === TYPE.PTR)
    assert.equal(ptr.rdata.name, 'dsh remote link on mac._http._tcp.local')
    const srv = res.answers.find((a) => a.type === TYPE.SRV)
    assert.equal(srv.rdata.port, 3081)
    assert.equal(srv.rdata.target, 'mac.local')
    const txt = res.answers.find((a) => a.type === TYPE.TXT)
    assert.equal(txt.rdata.path, '/')
    const a = res.answers.find((r) => r.type === TYPE.A)
    assert.equal(a.rdata.address, '192.168.1.23')
  } finally {
    await ad.stop()
  }
})

test('advertiser answers SRV lookups by instance name and DNS-SD enumeration', async () => {
  const ad = createAdvertiser(BASE)
  await ad.start()
  try {
    const srvRes = await ask(ad.port, queryPacket(2, 'dsh remote link on mac._http._tcp.local', TYPE.SRV))
    assert.notEqual(srvRes, null)
    assert.ok(srvRes.answers.some((a) => a.type === TYPE.SRV && a.rdata.port === 3081))
    assert.ok(srvRes.answers.some((a) => a.type === TYPE.A), 'includes host address for direct connect')

    const enumRes = await ask(ad.port, queryPacket(3, '_services._dns-sd._udp.local', TYPE.PTR))
    assert.notEqual(enumRes, null)
    const ptr = enumRes.answers.find((a) => a.type === TYPE.PTR)
    assert.equal(ptr.rdata.name, '_http._tcp.local')
  } finally {
    await ad.stop()
  }
})

test('advertiser stays silent for unrelated services', async () => {
  const ad = createAdvertiser(BASE)
  await ad.start()
  try {
    const res = await ask(ad.port, queryPacket(4, '_ssh._tcp.local', TYPE.PTR))
    assert.equal(res, null, 'no response for another service type')
  } finally {
    await ad.stop()
  }
})

test('stop closes the socket and is idempotent', async () => {
  const ad = createAdvertiser(BASE)
  await ad.start()
  const port = ad.port
  await ad.stop()
  await ad.stop()
  const res = await ask(port, queryPacket(5, '_http._tcp.local', TYPE.PTR))
  assert.equal(res, null, 'nothing answers after stop')
})
