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
import { defineRemoteQrTool, defineRemoteDevicesTool, defineRemoteRecoveryTool } from './tools.js'
import { encodeQr, renderQr, renderPng } from './qrcode.js'
import { createNotifier } from './notify.js'
import { createEventTap } from './event-tap.js'

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
      recoveryCode: cfg.pairing.recoveryCode,
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

  // Offline interaction push: when an approval/question arrives and no
  // browser leg is connected to see it, ring the user's own channels
  // (Bark/ntfy/webhook). Payload carries no secrets; per-id dedupe plus a
  // global cooldown keep it a doorbell, not a fire alarm.
  const notifier = createNotifier({ ...cfg.notify, log })
  let lastPushAt = null
  let lastPushCooldownUntil = 0
  const PUSH_COOLDOWN_MS = 60_000
  const pushedIds = new Set()
  const eventTap = notifier.enabled
    ? createEventTap({
      target,
      log,
      onRequested: ({ kind, id }) => {
        if (gateway.activeLegCount() > 0) return // a connected browser sees it live
        const key = `${kind}:${id}`
        if (pushedIds.has(key)) return
        const t = Date.now()
        if (t < lastPushCooldownUntil) return
        pushedIds.add(key)
        lastPushAt = t
        lastPushCooldownUntil = t + PUSH_COOLDOWN_MS
        notifier.notify({
          title: kind === 'approval' ? 'DSH 等待审批' : 'DSH 等待回答',
          body: `宿主机 agent 正在等你${kind === 'approval' ? '批准操作' : '回答问题'}——打开远程页面处理。`,
        }).catch(() => {})
      },
      onResolved: () => {
        // Frames do not reliably carry the same id on resolve; dropping the
        // whole set on any resolution keeps the dedupe bounded and simple.
        pushedIds.clear()
      },
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
    keepaliveIntervalMs: cfg.keepaliveIntervalMs,
    tunnelHeartbeatFile: cfg.tunnelHeartbeatFile,
    hostProbeIntervalMs: cfg.hostProbeIntervalMs,
    notifySnapshot: notifier.enabled
      ? () => ({ channels: notifier.channelNames(), lastPushAt, tap: eventTap.state() })
      : null,
    pairingSnapshot: pairingService === null
      ? null
      : () => (currentPairing === null ? null : { shortCode: currentPairing.shortCode, expiresAt: currentPairing.expiresAt }),
    resolveDevice: pairingService === null
      ? null
      : (deviceId) => pairingService.listDevices().find((d) => d.deviceId === deviceId)?.name ?? null,
  })

  ctx.tools.register(defineForkSessionTool(ctx))
  if (pairingService !== null) {
    ctx.tools.register(defineRemoteQrTool({
      createPairing: currentOrMint,
      baseUrl: () => cfg.publicUrl ?? `http://${lanAddress()}:${gateway.port}`,
      qrImageUrl: () => `http://127.0.0.1:${gateway.port}/qr.png?v=${Date.now()}`,
    }))
    ctx.tools.register(defineRemoteDevicesTool({ service: pairingService }))
    ctx.tools.register(defineRemoteRecoveryTool({
      service: pairingService,
      baseUrl: () => cfg.publicUrl ?? `http://${lanAddress()}:${gateway.port}`,
    }))
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
        log(`link keepalive ${cfg.keepaliveIntervalMs > 0 ? `every ${Math.round(cfg.keepaliveIntervalMs / 1000)}s when idle` : 'off'} · status: http://127.0.0.1:${gateway.port}/status`)
        if (pairingService !== null) {
          const recovery = pairingService.recoveryStatus()
          if (recovery.enabled) log(`recovery pairing enabled (source: ${recovery.source})`)
          else log('recovery code NOT set — say "设置恢复码" in chat (or configure pairing.recoveryCode) to enable emergency device recovery')
        }
        if (eventTap !== null) {
          eventTap.start()
          log(`interaction push on idle: ${notifier.channelNames().join(', ')}`)
        }
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
    eventTap?.close()
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
<small>短码备用 · 本配对 <span id="ttl">${secondsLeft}</span>s 内有效 · 到期自动换新码</small>
<script>
let s = ${secondsLeft}
setInterval(() => {
  s -= 1
  const el = document.getElementById('ttl')
  if (el) el.textContent = Math.max(0, s)
  if (s <= 0) location.reload()
}, 1000)
</script>
</body></html>`
}
