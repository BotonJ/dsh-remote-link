// Standalone runner for the real remote test: loads the plugin's apply()
// against a mock ctx whose webServer is the real DSH web port, so the
// gateway proxies the actual DSH UI/RPC. Usage:
//   node runner-gateway.mjs <publicUrl> [gatewayPort=3081] [targetPort=49152]
import { apply } from '~/dsh-remote-link/src/index.js'

const publicUrl = process.argv[2] ?? ''
const port = Number(process.argv[3] ?? 3081)
const targetPort = Number(process.argv[4] ?? 49152)

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
  host: '127.0.0.1',
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
console.log(`[runner] publicUrl=${publicUrl || '(lan default)'} target=127.0.0.1:${targetPort}`)

// mint a FRESH pairing right now (5-min clock starts at handoff)
const qrTool = tools.find((t) => t.name === 'remote_qr')
const r = await qrTool.execute({}, {})
const rendered = qrTool.output.render(null, r)
console.log('[runner] fresh pairing:')
console.log(rendered[0].text)

setInterval(() => {}, 1 << 30)
