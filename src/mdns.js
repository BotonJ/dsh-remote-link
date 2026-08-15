/**
 * Zero-dependency mDNS/DNS-SD responder (replaces the bonjour-service
 * dependency MiMo uses, keeping the plugin's zero-runtime-deps convention).
 *
 * It listens for multicast DNS queries on 224.0.0.251:5353 and answers:
 *   - PTR browse queries for the service type (`_http._tcp.local`)
 *   - DNS-SD service enumeration (`_services._dns-sd._udp.local`)
 *   - SRV/TXT lookups by instance name, plus the host's A record
 * Replies are sent unicast to the querier (legacy-unicast style, RFC 6762
 * §6.7 — ttl 120 keeps caches honest without aggressive flushing).
 */

import { createSocket } from 'node:dgram'
import { TYPE, buildResponse, parseQuery } from './dns-codec.js'

const MDNS_GROUP = '224.0.0.251'
const MDNS_PORT = 5353
const ANY = 255
const TTL = 120

function sanitizeLabel(label) {
  const cleaned = String(label).replace(/\./g, '-').trim()
  if (cleaned.length === 0) throw new Error('mDNS label must be non-empty')
  return cleaned
}

export function createAdvertiser(options) {
  const {
    instance,
    serviceName = 'dsh-remote-link',
    type = 'http',
    protocol = 'tcp',
    domain = 'local',
    host,
    port,
    txt = { path: '/' },
    address,
    multicast = true,
    bindPort = MDNS_PORT,
    bindAddress = '0.0.0.0',
    log = () => {},
  } = options

  if (!Number.isInteger(port) || port <= 0) throw new Error('advertiser requires a positive integer port')
  if (address === undefined) throw new Error('advertiser requires the host LAN IPv4 address')

  const instanceLabel = sanitizeLabel(instance ?? `${serviceName} on ${host}`)
  const serviceType = `_${type}._${protocol}.${domain}`
  const instanceFqdn = `${instanceLabel}.${serviceType}`
  const hostFqdn = `${sanitizeLabel(host)}.${domain}`
  const enumerationName = `_services._dns-sd._udp.${domain}`
  // DNS names are case-insensitive; queries arrive lowercased by the codec
  const lc = { serviceType: serviceType.toLowerCase(), instanceFqdn: instanceFqdn.toLowerCase(), hostFqdn: hostFqdn.toLowerCase(), enumerationName: enumerationName.toLowerCase() }

  let socket = null
  let stopped = false

  function answersFor(question) {
    const { name, type: qtype } = question
    const wants = (t) => qtype === t || qtype === ANY
    if (name === lc.serviceType && wants(TYPE.PTR)) {
      return [
        { name: serviceType, type: TYPE.PTR, ttl: TTL, data: instanceFqdn },
        { name: instanceFqdn, type: TYPE.SRV, ttl: TTL, data: { priority: 0, weight: 0, port, target: hostFqdn } },
        { name: instanceFqdn, type: TYPE.TXT, ttl: TTL, data: txt },
        { name: hostFqdn, type: TYPE.A, ttl: TTL, data: address },
      ]
    }
    if (name === lc.instanceFqdn && (wants(TYPE.SRV) || wants(TYPE.TXT) || wants(TYPE.A))) {
      return [
        { name: instanceFqdn, type: TYPE.SRV, ttl: TTL, data: { priority: 0, weight: 0, port, target: hostFqdn } },
        { name: instanceFqdn, type: TYPE.TXT, ttl: TTL, data: txt },
        { name: hostFqdn, type: TYPE.A, ttl: TTL, data: address },
      ]
    }
    if (name === lc.enumerationName && wants(TYPE.PTR)) {
      return [{ name: enumerationName, type: TYPE.PTR, ttl: TTL, data: serviceType }]
    }
    if (name === lc.hostFqdn && wants(TYPE.A)) {
      return [{ name: hostFqdn, type: TYPE.A, ttl: TTL, data: address }]
    }
    return null
  }

  function onMessage(message, rinfo) {
    const query = parseQuery(message)
    if (query === null) return
    for (const question of query.questions) {
      const answers = answersFor(question)
      if (answers === null) continue
      try {
        socket.send(buildResponse({ id: query.id, questions: [question] }, answers), rinfo.port, rinfo.address)
      } catch (error) {
        log(`mdns: failed to answer ${question.name}: ${String(error)}`)
      }
    }
  }

  return {
    get port() {
      return socket === null ? null : socket.address().port
    },
    get instanceName() {
      return instanceFqdn
    },
    start() {
      if (socket !== null || stopped) return Promise.resolve()
      return new Promise((resolve, reject) => {
        const sock = createSocket({ type: 'udp4', reuseAddr: true })
        sock.on('error', (error) => {
          sock.close()
          socket = null
          reject(error)
        })
        sock.bind(bindPort, bindAddress, () => {
          if (multicast) {
            try {
              sock.addMembership(MDNS_GROUP)
              sock.setMulticastTTL(255)
            } catch (error) {
              log(`mdns: multicast unavailable (${String(error)}); responder stays unicast-only`)
            }
          }
          sock.removeAllListeners('error')
          sock.on('error', (error) => log(`mdns: socket error: ${String(error)}`))
          sock.on('message', onMessage)
          socket = sock
          log(`mdns: answering for ${instanceFqdn} on ${bindAddress}:${sock.address().port}`)
          resolve()
        })
      })
    },
    stop() {
      stopped = true
      return new Promise((resolve) => {
        if (socket === null) return resolve()
        socket.close(() => {
          socket = null
          resolve()
        })
      })
    },
  }
}
