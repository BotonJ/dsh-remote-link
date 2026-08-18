// Standalone gateway runner: loads the plugin's apply() against a mock ctx
// whose webServer.port points at any local HTTP upstream — the DSH web UI or
// another harness's server (e.g. MiMo Code's `serve`). Usage:
//   node runner-gateway.mjs <publicUrl> [gatewayPort=3081] [targetPort=49152] [host=0.0.0.0]
//
// The bind default matches normalizeConfig (0.0.0.0): the pairing QR always
// advertises the LAN address, and a loopback bind makes every scanned QR
// connection-refused. Pass 127.0.0.1 explicitly for desktop-only testing —
// the runner then warns, because the QR stays unreachable from other devices.
import { apply } from './src/index.js'

const publicUrl = process.argv[2] ?? ''
const port = Number(process.argv[3] ?? 3081)
const targetPort = Number(process.argv[4] ?? 49152)
const host = process.argv[5] ?? '0.0.0.0'

const logs = []
const origLog = console.log
console.log = (...args) => logs.push(args.join(' '))

const tools = []
const ctx = {
  tools: { register: (t) => tools.push(t) },
  inject: (deps, cb) => { cb({ webServer: { port: targetPort } }) },
  effect: () => {},
  provide: () => {},
}

apply(ctx, {
  host,
  port,
  mdns: false,
  publicUrl: publicUrl || undefined,
  pairing: { enabled: true },
})

for (let i = 0; i < 200; i += 1) {
  if (logs.some((l) => l.includes('gateway on'))) break
  await new Promise((r) => setTimeout(r, 50))
}

console.log = origLog
const block = logs.find((l) => l.includes('#p=') && l.includes('short code'))
if (!block) { console.error('FAIL: no pairing block'); process.exit(1) }
console.log(block)
console.log(`[runner] publicUrl=${publicUrl || '(lan default)'} target=127.0.0.1:${targetPort} bind=${host}`)
if (host === '127.0.0.1' || host === 'localhost' || host === '::1') {
  console.warn('[runner] loopback bind: the QR above advertises the LAN address and is UNREACHABLE from phones — rerun with host 0.0.0.0')
}

// mint a FRESH pairing right now (5-min clock starts at handoff)
const qrTool = tools.find((t) => t.name === 'remote_qr')
const r = await qrTool.execute({}, {})
const rendered = qrTool.output.render(null, r)
console.log('[runner] fresh pairing:')
console.log(rendered[0].text)

setInterval(() => {}, 1 << 30)
