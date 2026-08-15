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
import { encodeQr, renderQr, renderPng } from './qrcode.js'

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

  // One live pairing at a time: the terminal log, the remote_qr tool, and the
  // desktop chat's /qr.png image must all show the SAME pairing, so repeated
  // tool calls within the TTL reuse it instead of invalidating the visible QR.
  let currentPairing = null
  const pairingUrl = (pairing) => {
    const base = cfg.publicUrl ?? `http://${lanAddress()}:${gateway.port}`
    // /pair is the page that reads the #p= fragment and runs the
    // challenge-response; the bare root would 401 before pairing.
    return `${base}/pair#p=${pairing.sid}.${pairing.secret}`
  }
  const currentOrMint = () => {
    const now = Date.now()
    if (currentPairing === null || currentPairing.expiresAt <= now + 2_000) {
      currentPairing = pairingService.createPairing()
    }
    return currentPairing
  }

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
    qrImage: pairingService === null
      ? null
      : () => {
          const pairing = currentOrMint()
          return renderPng(pairingUrl(pairing))
        },
    qrPage: pairingService === null
      ? null
      : () => {
          const pairing = currentOrMint()
          const seconds = Math.max(0, Math.round((pairing.expiresAt - Date.now()) / 1000))
          return QR_PAGE_HTML(pairingUrl(pairing), pairing.shortCode, seconds)
        },
  })

  ctx.tools.register(defineForkSessionTool(ctx))
  if (pairingService !== null) {
    ctx.tools.register(defineRemoteQrTool({
      createPairing: currentOrMint,
      baseUrl: () => cfg.publicUrl ?? `http://${lanAddress()}:${gateway.port}`,
      qrImageUrl: () => `http://127.0.0.1:${gateway.port}/qr.png?v=${Date.now()}`,
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
          const pairing = currentOrMint()
          const url = pairingUrl(pairing)
          log(`pairing ready for 5min — scan or visit:\n${renderQr(url)}\n${url}\nshort code: ${pairing.shortCode}`)
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


/** Loopback-only QR viewer page: `open http://127.0.0.1:<port>/qr` puts a
 *  scannable image on the desktop screen — the phone scans the monitor. */
function QR_PAGE_HTML(url, shortCode, secondsLeft) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH Remote Link 配对</title>
<meta http-equiv="refresh" content="60">
<style>body{margin:0;display:flex;flex-direction:column;align-items:center;background:#111;color:#eee;font-family:system-ui;padding:24px}
h1{font-size:18px;font-weight:600}img{width:min(70vmin,520px);image-rendering:pixelated}
.short{font-size:28px;letter-spacing:8px;margin:16px 0 4px}small{color:#888}</style></head>
<body><h1>DSH Remote Link — 手机扫码配对</h1>
<img src="/qr.png" alt="配对二维码">
<div class="short">${shortCode}</div>
<small>短码备用 · 本配对 ${secondsLeft}s 内有效 · 页面每 60s 自动刷新（同码续期，过期自动换新）</small>
</body></html>`
}
