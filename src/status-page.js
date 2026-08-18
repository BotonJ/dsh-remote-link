/**
 * Loopback-only link status page: gateway uptime, keepalive telemetry per
 * live WebSocket leg (ping RTT, injection counts), and the pairing countdown.
 * Same guard policy as /qr — desktop-side observability, never exposed
 * through the tunnel (loopback source AND no proxy chain).
 */

function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
}

export function STATUS_PAGE_HTML(payload) {
  const legs = payload.legs.map((leg) => `
    <tr>
      <td>#${esc(leg.id)}</td>
      <td>${esc(leg.path)}</td>
      <td>${esc(Math.round(leg.ageMs / 1000))}s</td>
      <td>${leg.keepalive.enabled ? `${esc(leg.keepalive.pingsSent)} / ${esc(leg.keepalive.pongsReceived)}` : 'off'}</td>
      <td>${leg.keepalive.lastRttMs === null ? '—' : `${esc(leg.keepalive.lastRttMs)}ms`}</td>
      <td>${leg.keepalive.enabled ? esc(Math.round(leg.keepalive.idleMs / 1000)) + 's' : '—'}</td>
    </tr>`).join('')

  const pairing = payload.pairing === null
    ? '<div class="muted">未启用或当前无活动配对</div>'
    : `<div>短码 <b class="short">${esc(payload.pairing.shortCode)}</b> · 剩余 <span id="ttl">${esc(payload.pairing.secondsLeft)}</span>s</div>`

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH Remote Link 状态</title>
<meta http-equiv="refresh" content="5">
<style>body{margin:0;background:#111;color:#eee;font-family:system-ui;padding:24px}
h1{font-size:18px;font-weight:600;margin:0 0 4px}.muted{color:#888}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:16px 0}
.card{background:#1b1b1b;border:1px solid #2a2a2a;border-radius:8px;padding:12px}
.card b{display:block;font-size:22px;margin-top:4px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:6px 10px;border-bottom:1px solid #2a2a2a;text-align:left}
th{color:#888;font-weight:500}.short{letter-spacing:4px}
#ttl{color:#4ec9b0}</style></head>
<body><h1>DSH Remote Link — 链路状态</h1>
<div class="muted">每 5s 自动刷新 · 仅本机可见</div>
<div class="grid">
  <div class="card">网关运行<b>${esc(Math.round(payload.uptimeMs / 1000))}s</b></div>
  <div class="card">keepalive 间隔<b>${payload.keepaliveIntervalMs > 0 ? esc((payload.keepaliveIntervalMs / 1000).toFixed(0)) + 's' : '关闭'}</b></div>
  <div class="card">WS 连接累计（代数）<b>${esc(payload.generation)}</b></div>
  <div class="card">当前活动连接<b>${esc(payload.legs.length)}</b></div>
</div>
<div class="card" style="margin-bottom:16px">${pairing}</div>
<table>
  <thead><tr><th>腿</th><th>路径</th><th>存活</th><th>ping 发/收</th><th>最近 RTT</th><th>空闲</th></tr></thead>
  <tbody>${legs || '<tr><td colspan="6" class="muted">无活动连接 — 手机未连接或未完成配对</td></tr>'}</tbody>
</table>
${payload.pairing === null ? '' : `<script>
let s = ${payload.pairing.secondsLeft}
setInterval(() => {
  s -= 1
  const el = document.getElementById('ttl')
  if (el) el.textContent = Math.max(0, s)
}, 1000)
</script>`}
</body></html>`
}
