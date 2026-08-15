/**
 * Composition-row configuration for dsh-remote-link.
 *
 * The DSH host passes the cordis row's `config` object to `apply(ctx, config)`
 * unvalidated when the plugin exports no schemastery schema, so this module is
 * the single validation/normalization boundary: every other module receives a
 * frozen, fully-defaulted config object.
 */

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1'])

export class ConfigError extends Error {
  constructor(message, code = 'E_CONFIG') {
    super(message)
    this.name = 'ConfigError'
    this.code = code
  }
}

function requireString(value, field) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ConfigError(`config.${field} must be a non-empty string`)
  }
  return value
}

function intInRange(value, field, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(`config.${field} must be an integer between ${min} and ${max}`)
  }
  return value
}

function section(raw, defaults, intFields) {
  const out = { ...defaults }
  if (raw === undefined) return out
  if (raw === null || typeof raw !== 'object') {
    throw new ConfigError('config section must be an object')
  }
  for (const [key, value] of Object.entries(raw)) {
    if (!(key in defaults)) throw new ConfigError(`unknown config key "${key}"`)
    out[key] = intFields.includes(key)
      ? intInRange(value, key, 1, 2_147_483_647)
      : value
  }
  return out
}

export function normalizeConfig(raw) {
  const input = raw === undefined ? {} : raw
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new ConfigError('config must be an object')
  }

  const host = input.host === undefined ? '0.0.0.0' : requireString(input.host, 'host')
  // 0 = OS-assigned ephemeral port (mirrors dsh web --port 0)
  const port = input.port === undefined ? 3081 : intInRange(input.port, 'port', 0, 65535)
  const username = input.username === undefined ? 'dsh' : requireString(input.username, 'username')
  const password = input.password === undefined || input.password === null || input.password === ''
    ? ''
    : requireString(input.password, 'password')
  const mdns = input.mdns === undefined ? true : input.mdns
  if (typeof mdns !== 'boolean') throw new ConfigError('config.mdns must be a boolean')

  // When set, the pairing QR / short-code URLs are built from this base URL
  // (e.g. a public tunnel like https://xxx.trycloudflare.com) instead of the
  // LAN address — required for phones connecting over cellular/internet.
  const publicUrl = input.publicUrl === undefined || input.publicUrl === null || input.publicUrl === ''
    ? null
    : requireString(input.publicUrl, 'publicUrl')
  if (publicUrl !== null && !/^https?:\/\//.test(publicUrl)) {
    throw new ConfigError('config.publicUrl must start with http:// or https://')
  }

  const pairing = section(input.pairing, { enabled: true, ttlMs: 300_000, sessionMaxAgeDays: 30, deviceIdleExpiryDays: 90, devicesFile: null }, ['ttlMs', 'sessionMaxAgeDays', 'deviceIdleExpiryDays'])
  if (typeof pairing.enabled !== 'boolean') throw new ConfigError('config.pairing.enabled must be a boolean')
  if (pairing.devicesFile !== null && typeof pairing.devicesFile !== 'string') {
    throw new ConfigError('config.pairing.devicesFile must be a string path or null')
  }

  // Security baseline: the gateway proxies a full remote-control surface, so
  // binding it beyond loopback with no way to authenticate would expose the
  // harness to the whole LAN. v1.5 accepts either a Basic password or the
  // pairing flow (one-time QR/short-code → device cookie sessions).
  if (!LOOPBACK_HOSTS.has(host) && password.length === 0 && !pairing.enabled) {
    throw new ConfigError(
      `refusing to bind gateway to ${host} without a password or pairing — set config.password or pairing.enabled`,
      'E_NO_PASSWORD',
    )
  }

  const target = {
    host: input.targetHost === undefined ? '127.0.0.1' : requireString(input.targetHost, 'targetHost'),
    // null = resolve lazily from ctx.webServer.port, falling back to 3080
    port: input.targetPort === undefined || input.targetPort === null ? null : intInRange(input.targetPort, 'targetPort', 1, 65535),
  }

  return Object.freeze({
    host,
    port,
    username,
    password,
    mdns,
    publicUrl,
    target: Object.freeze(target),
    rateLimit: Object.freeze(section(input.rateLimit, { windowMs: 60_000, max: 300 }, ['windowMs', 'max'])),
    authFailure: Object.freeze(section(input.authFailure, { windowMs: 300_000, max: 10, banMs: 300_000 }, ['windowMs', 'max', 'banMs'])),
    pairing: Object.freeze(pairing),
  })
}
