/**
 * dsh-remote-link — authenticated LAN gateway + fork_session for DeepSeek Harness.
 *
 * What the plugin mounts:
 *   1. A reverse-proxy gateway on its own port (config.host:config.port)
 *      fronting the loopback DSH webserver: official web UI, /api RPC, and
 *      /api/events.* WebSocket upgrades — Basic Auth with a ?token= bypass
 *      (browser WS/EventSource cannot set headers), per-IP rate limiting and
 *      auth-failure bans.
 *   2. mDNS advertisement on non-loopback binds (zero-dependency responder).
 *   3. The fork_session tool (model-callable session forking).
 *
 * Security baseline: binding beyond loopback without a password refuses to
 * load (normalizeConfig throws), so a misconfigured row fails loudly at boot.
 */

import { networkInterfaces, hostname } from 'node:os'
import { normalizeConfig } from './config.js'
import { createAuthenticator } from './auth.js'
import { createRateLimiter, createFailureBan } from './ratelimit.js'
import { createGateway } from './gateway.js'
import { createAdvertiser } from './mdns.js'
import { defineForkSessionTool } from './fork-session.js'

export const name = 'dsh-remote-link'
export const inject = ['tools', 'webServer']

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

  // The loopback webserver port is read lazily: ctx.webServer is optional and
  // only guaranteed once its service finished listening.
  const target = () => ({
    host: cfg.target.host,
    port: cfg.target.port ?? ctx.webServer?.port ?? 3080,
  })

  const gateway = createGateway({
    auth: createAuthenticator(cfg),
    limiter: createRateLimiter(cfg.rateLimit),
    failureBan: createFailureBan(cfg.authFailure),
    target,
    log,
  })

  ctx.tools.register(defineForkSessionTool(ctx))

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
      txt: { path: '/', auth: cfg.password.length > 0 ? 'basic' : 'none' },
      log,
    })
    advertiser.start().catch((error) => log(`mdns: failed to start: ${String(error?.message ?? error)}`))
  }

  gateway
    .listen({ host: cfg.host, port: cfg.port })
    .then(() => {
      try {
        ctx.provide('remoteLinkGateway', { port: gateway.port })
      } catch {
        // non-fatal: another instance may already provide the service
      }
      log(
        `gateway on ${cfg.host}:${gateway.port} → ${target().host}:${target().port}` +
          (cfg.password.length > 0 ? ' (basic auth)' : ' (no auth, loopback only)') +
          (cfg.password.length > 0 ? ` — open http://${cfg.username}:${cfg.password}@<lan-ip>:${gateway.port}` : ''),
      )
      advertise()
    })
    .catch((error) => log(`gateway failed to listen on ${cfg.host}:${cfg.port}: ${String(error?.message ?? error)}`))

  ctx.effect(() => () => {
    gateway.close()
    advertiser?.stop()
  })
}
