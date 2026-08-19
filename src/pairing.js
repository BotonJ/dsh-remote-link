/**
 * QR / short-code pairing core: one-time pairing secrets, HMAC
 * challenge-response with single-use nonces and a ±300s time window,
 * a persistent device registry, and in-memory cookie sessions.
 *
 * Proof convention (must match the pairing page's pure-JS HMAC):
 *   proof = hex( HMAC-SHA256( key = utf8(secret-or-code), msg = `${sid}|${nonce}|${ts}` ) )
 * Nonces are burned on EVERY verify attempt (success or not), so a captured
 * challenge cannot be brute-forced offline against the live endpoint.
 *
 * The device registry persists through a synchronous store (default:
 * $DSH_HOME/remote-link/devices.json, written 0600). Pairing secrets and
 * session tokens never touch disk: sessions are stored as SHA-256 digests.
 */

import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

const B64URL = { encode: (buf) => buf.toString('base64url') }
const TS_WINDOW_MS = 300_000
const NONCE_TTL_MS = 60_000

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function constantTimeEqualHex(aHex, bHex) {
  const da = createHash('sha256').update(aHex, 'utf8').digest()
  const db = createHash('sha256').update(bHex, 'utf8').digest()
  return timingSafeEqual(da, db)
}

function fsStore(filePath) {
  const file = filePath ?? join(homedir(), '.dsh', 'remote-link', 'devices.json')
  return {
    path: file,
    load() {
      try {
        const raw = readFileSync(file, 'utf8')
        const parsed = JSON.parse(raw)
        return Array.isArray(parsed) ? parsed : []
      } catch {
        return []
      }
    },
    save(devices) {
      mkdirSync(join(file, '..'), { recursive: true })
      writeFileSync(file, JSON.stringify(devices, null, 2), { mode: 0o600 })
    },
  }
}

export function createPairingService(options = {}) {
  const {
    now = () => Date.now(),
    random = () => randomBytes(32),
    store = fsStore(options.devicesFile),
    ttlMs = 300_000,
    sessionMaxAgeMs = 30 * 86_400_000,
    deviceIdleExpiryMs = 90 * 86_400_000,
    recoveryCode = null,
    exists = existsSync,
  } = options
  void exists
  // The long-term recovery code (case "no paired device at hand"): stored as
  // a SHA-256 digest only, compared constant-time, redeemable repeatedly —
  // each redemption registers a fresh revocable device in the registry.
  const recoveryHash = typeof recoveryCode === 'string' && recoveryCode.length > 0
    ? sha256Hex(recoveryCode)
    : null

  /** sid/secret → pairing, live until consumed or expired */
  const pairings = new Map() // sid → { sid, secret, shortCode, expiresAt }
  /** sid → { nonce, ts, expiresAt }; one live challenge per pairing */
  const nonces = new Map()
  /** sha256(token) → { deviceId, expiresAt } */
  const sessions = new Map()
  let devices = store.load()

  function pruneStale() {
    const t = now()
    let dirty = false
    for (const device of [...devices]) {
      if (t - device.lastSeen >= deviceIdleExpiryMs) {
        devices = devices.filter((d) => d !== device)
        dirty = true
        for (const [hash, session] of [...sessions]) {
          if (session.deviceId === device.deviceId) sessions.delete(hash)
        }
      }
    }
    if (dirty) store.save(devices)
    for (const [sid, pairing] of [...pairings]) {
      if (t >= pairing.expiresAt) pairings.delete(sid)
    }
    for (const [sid, nonce] of [...nonces]) {
      if (t >= nonce.expiresAt) nonces.delete(sid)
    }
  }

  function shortCodeFor(secret) {
    const digest = createHmac('sha256', Buffer.from(secret, 'utf8')).update('rl-short').digest()
    return String(digest.readUInt32BE(0) % 1_000_000).padStart(6, '0')
  }

  return {
    createPairing() {
      pruneStale()
      const sid = B64URL.encode(random().subarray(0, 16))
      const secret = B64URL.encode(random())
      const pairing = { sid, secret, shortCode: shortCodeFor(secret), expiresAt: now() + ttlMs }
      pairings.set(sid, pairing)
      return pairing
    },

    challenge(sidOrCode) {
      pruneStale()
      if (typeof sidOrCode !== 'string' || sidOrCode.length === 0 || sidOrCode.length > 128) return null
      let pairing
      for (const candidate of pairings.values()) {
        if (candidate.sid === sidOrCode || candidate.shortCode === sidOrCode) { pairing = candidate; break }
      }
      if (pairing === undefined) return null
      const nonce = B64URL.encode(random().subarray(0, 32))
      const ts = now()
      nonces.set(pairing.sid, { nonce, ts, expiresAt: ts + NONCE_TTL_MS })
      return { sid: pairing.sid, nonce, ts, alg: 'HMAC-SHA256' }
    },

    async verify(input) {
      pruneStale()
      if (input === null || typeof input !== 'object') return { ok: false, error: 'BAD_REQUEST' }
      const sid = typeof input.sid === 'string' ? input.sid : null
      const code = typeof input.code === 'string' ? input.code : null
      const ts = typeof input.ts === 'number' && Number.isFinite(input.ts) ? input.ts : null
      const givenProof = typeof input.proof === 'string' ? input.proof : null
      if (givenProof === null || ts === null || (sid === null && code === null)) return { ok: false, error: 'BAD_REQUEST' }

      let pairing = null
      let secret = null
      if (sid !== null) {
        const bySid = pairings.get(sid)
        if (bySid !== undefined) { pairing = bySid; secret = bySid.secret }
      }
      if (pairing === null && code !== null) {
        for (const candidate of pairings.values()) {
          if (candidate.shortCode === code) { pairing = candidate; secret = code; break }
        }
      }
      if (pairing === null) return { ok: false, error: 'PAIRING_NOT_FOUND' }

      const t = now()
      if (Math.abs(t - ts) > TS_WINDOW_MS) return { ok: false, error: 'BAD_TS' }

      // Burn the nonce on every attempt, successful or not.
      const challenge = nonces.get(pairing.sid)
      nonces.delete(pairing.sid)
      if (challenge === undefined || t >= challenge.expiresAt) return { ok: false, error: 'NONCE_MISSING' }

      const expected = createHmac('sha256', Buffer.from(secret, 'utf8'))
        .update(`${pairing.sid}|${challenge.nonce}|${ts}`, 'utf8').digest('hex')
      if (!constantTimeEqualHex(givenProof, expected)) return { ok: false, error: 'BAD_PROOF' }

      pairings.delete(pairing.sid)
      const deviceId = B64URL.encode(random().subarray(0, 12))
      const name = typeof input.name === 'string' && input.name.length > 0 && input.name.length <= 64 ? input.name : undefined
      const device = {
        deviceId,
        ...(name === undefined ? {} : { name }),
        addedAt: t,
        lastSeen: t,
        deviceKey: Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from(pairing.sid, 'utf8'), Buffer.from('rl-device'), 32)).toString('hex'),
      }
      devices = [...devices, device]
      store.save(devices)
      const sessionToken = B64URL.encode(random())
      sessions.set(sha256Hex(sessionToken), { deviceId, expiresAt: t + sessionMaxAgeMs })
      return { ok: true, deviceId, sessionToken }
    },

    /** Redeem the long-term recovery code: mints a device + session like a
     * completed pairing. Not one-shot — treat the code like a password and
     * rotate it via config; every redemption shows up in listDevices(). */
    async redeemRecovery(input) {
      pruneStale()
      if (recoveryHash === null) return { ok: false, error: 'RECOVERY_DISABLED' }
      if (input === null || typeof input !== 'object' || typeof input.code !== 'string' || input.code.length === 0) {
        return { ok: false, error: 'BAD_REQUEST' }
      }
      if (!constantTimeEqualHex(sha256Hex(input.code), recoveryHash)) {
        return { ok: false, error: 'BAD_RECOVERY' }
      }
      const t = now()
      const deviceId = B64URL.encode(random().subarray(0, 12))
      const name = typeof input.name === 'string' && input.name.length > 0 && input.name.length <= 64
        ? input.name
        : `recovery-${new Date(t).toISOString().slice(0, 10)}`
      const device = {
        deviceId,
        name,
        addedAt: t,
        lastSeen: t,
        deviceKey: Buffer.from(hkdfSync('sha256', Buffer.from(input.code, 'utf8'), Buffer.from('rl-recovery', 'utf8'), Buffer.from(deviceId, 'utf8'), 32)).toString('hex'),
      }
      devices = [...devices, device]
      store.save(devices)
      const sessionToken = B64URL.encode(random())
      sessions.set(sha256Hex(sessionToken), { deviceId, expiresAt: t + sessionMaxAgeMs })
      return { ok: true, deviceId, sessionToken }
    },

    resolveSession(token) {
      pruneStale()
      if (typeof token !== 'string' || token.length === 0) return null
      const session = sessions.get(sha256Hex(token))
      if (session === undefined) return null
      const t = now()
      if (t >= session.expiresAt) {
        sessions.delete(sha256Hex(token))
        return null
      }
      const device = devices.find((d) => d.deviceId === session.deviceId)
      if (device === undefined) return null
      device.lastSeen = t
      return { deviceId: session.deviceId }
    },

    listDevices() {
      pruneStale()
      return devices.map(({ deviceKey, ...rest }) => rest)
    },

    renameDevice(deviceId, name) {
      const device = devices.find((d) => d.deviceId === deviceId || d.name === deviceId)
      if (device === undefined) return false
      device.name = name
      store.save(devices)
      return true
    },

    revokeDevice(deviceIdOrName) {
      const before = devices.length
      devices = devices.filter((d) => d.deviceId !== deviceIdOrName && d.name !== deviceIdOrName)
      const removed = before - devices.length
      if (removed > 0) {
        const ids = new Set()
        for (const d of devices) ids.add(d.deviceId)
        for (const [hash, session] of [...sessions]) {
          if (!ids.has(session.deviceId)) sessions.delete(hash)
        }
        store.save(devices)
      }
      return removed
    },

    revokeAllDevices() {
      const removed = devices.length
      devices = []
      sessions.clear()
      store.save(devices)
      return removed
    },
  }
}
