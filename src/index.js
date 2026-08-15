/**
 * dsh-remote-link — authenticated LAN gateway + pairing + fork_session for
 * DeepSeek Harness.
 *
 * What the plugin mounts:
 *   1. A reverse-proxy gateway on its own port (config.host:config.port)
 *      fronting the loopback DSH webserver: official web UI, /api RPC, and
 *      /api/events.* WebSocket upgrades.
 *   2. v1.5 pairing: one-time QR / 6-digit short code → HMAC challenge-
 *      response → HttpOnly cookie sessions, with a persistent device
 *      registry (list/revoke via the remote_devices tool). The v1
 *      ?token= query bypass is gone.
 *   3. mDNS advertisement on non-loopback binds (zero-dependency responder).
 *   4. The fork_session tool (model-callable session forking).
 *
 * Security baseline: binding beyond loopback requires a Basic password OR
 * the pairing flow (normalizeConfig enforces it at load).
 */

import { networkInterfaces, hostname } from 'node:os'
import { normalizeConfig } from './config.js'
import { createAuthenticator } from './auth.js'
import { createRateLimiter, createFailureBan } from './ratelimit.js'
import { createGateway } from './gateway.js'
import { createAdvertiser } from './mdns.js'
import { createPairingService } from './pairing.js'
import { PAIRING_PAGE_HTML } from './pairing-page.js'
import { defineForkSessionTool } from './fork-session.js'
import { defineRemoteQrTool, defineRemoteDevicesTool } from './tools.js'
import { encodeQr, renderAscii } from './qrcode.js'

export const name = 'dsh-remote-link'
export const inject = ['tools']

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1'])

/** First non-internal IPv4 address, or null when no LAN interface exists. */
export function pickLanAddress(interfaces = networkInterfaces()) {
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.internal === false && entry.family === 'IPv4' && entry.address !== '0.0.0.0') {
        return entry
      }
    }
  }
  return null
}

export function apply(ctx, config) {
  const cfg = normalizeConfig(config)
  const log = (...args) => console.log(`[${name}]`, ...args)

  // webServer arrives via lazy ctx.inject so the plugin also loads in profiles
  // without a web UI (headless): fork_session and the pairing tools still work,
  // the gateway itself simply has nothing to front and stays down.
  let webServer = null
  const target = () => ({
    host: cfg.target.host,
    port: cfg.target.port ?? webServer?.port ?? 3080,
  })

  const pairingService = cfg.pairing.enabled
    ? createPairingService({
      ttlMs: cfg.pairing.ttlMs,
      sessionMaxAgeMs: cfg.pairing.sessionMaxAgeDays * 86_400_000,
      deviceIdleExpiryMs: cfg.pairing.deviceIdleExpiryDays * 86_400_000,
      ...(cfg.pairing.devicesFile === null ? {} : { devicesFile: cfg.pairing.devicesFile }),
    })
    : null

  const gateway = createGateway({
    auth: createAuthenticator({
      username: cfg.username,
      password: cfg.password,
      cookieAuth: pairingService !== null,
      resolveSession: pairingService === null ? () => null : (token) => pairingService.resolveSession(token),
    }),
    limiter: createRateLimiter(cfg.rateLimit),
    failureBan: createFailureBan(cfg.authFailure),
    target,
    log,
    pairing: pairingService,
    pairingPage: PAIRING_PAGE_HTML,
    pairLimiter: createRateLimiter({ windowMs: 60_000, max: 10 }),
    cookieMaxAgeSeconds: cfg.pairing.sessionMaxAgeDays * 86_400,
  })

  ctx.tools.register(defineForkSessionTool(ctx))
  if (pairingService !== null) {
    ctx.tools.register(defineRemoteQrTool({
      createPairing: () => pairingService.createPairing(),
      baseUrl: () => `http://${lanAddress()}:${gateway.port}`,
    }))
    ctx.tools.register(defineRemoteDevicesTool({ service: pairingService }))
  }

  const lanAddress = () => {
    const lan = pickLanAddress()
    return lan === null ? '127.0.0.1' : lan.address
  }

  let advertiser = null
  const advertise = () => {
    if (!cfg.mdns || LOOPBACK.has(cfg.host)) return
    const lan = pickLanAddress()
    if (lan === null) return log('mdns: skipped, no LAN IPv4 interface found')
    const host = hostname().replace(/\.local$/, '')
    advertiser = createAdvertiser({
      instance: `DSH Remote Link on ${host}`,
      serviceName: 'dsh-remote-link',
      host,
      port: gateway.port,
      address: lan.address,
      txt: { path: '/', auth: cfg.password.length > 0 ? 'basic' : pairingService !== null ? 'pairing' : 'none' },
      log,
    })
    advertiser.start().catch((error) => log(`mdns: failed to start: ${String(error?.message ?? error)}`))
  }

  let gatewayStarted = false
  const startGateway = () => {
    if (gatewayStarted) return
    gatewayStarted = true
    gateway
      .listen({ host: cfg.host, port: cfg.port })
      .then(() => {
        try {
          ctx.provide('remoteLinkGateway', { port: gateway.port })
        } catch {
          // non-fatal: another instance may already provide the service
        }
        log(`gateway on ${cfg.host}:${gateway.port} → ${target().host}:${target().port}`)
        if (pairingService !== null) {
          const pairing = pairingService.createPairing()
          const url = `http://${lanAddress()}:${gateway.port}/#p=${pairing.sid}.${pairing.secret}`
          log(`pairing ready for 5min — scan or visit:\n${renderAscii(encodeQr(url, { border: 2 }))}\n${url}\nshort code: ${pairing.shortCode}`)
        } else if (cfg.password.length > 0) {
          log(`basic auth user "${cfg.username}" (password from config)`)
        }
        advertise()
      })
      .catch((error) => log(`gateway failed to listen on ${cfg.host}:${cfg.port}: ${String(error?.message ?? error)}`))
  }

  try {
    ctx.inject?.(['webServer'], (scoped) => {
      webServer = scoped.webServer
      startGateway()
    })
  } catch {
    // hosts without the lazy-inject API: fall through, gateway stays down
  }

  ctx.effect(() => () => {
    gateway.close()
    advertiser?.stop()
  })
}
