/**
 * Host telemetry: full-stack health probe + live host event tap.
 *
 * The /status page used to prove only that the upstream HTTP server answers
 * (lastOkAt). A DSH webserver can still answer while its ApiProxy/host core
 * is dead — so this module talks the same seam the official client uses:
 *
 *   ① probe  — POST /api/host.describe with a client-request envelope. The
 *              call must traverse webserver → ApiProxy → host to return, so
 *              success proves the whole stack alive; the round-trip doubles
 *              as a latency measure and the value carries host facts
 *              (version, model, attachedSessions).
 *   ② events — GET /api/events.host (the SSE variant of the host downlink)
 *              kept open for live deltas: host/session-added/-status/
 *              -removed track the running bit per session.
 *
 * Non-DSH upstreams (e.g. MiMo Code fronted by the runner, whose catch-all
 * UI route answers every path with 200 HTML) fail the shape check: after a
 * few wrong-shape answers the probe marks the upstream unsupported and goes
 * quiet — telemetry degrades to "not a DSH host" instead of a scary failure
 * row, and no pointless traffic keeps flowing.
 *
 * Deliberately URL-shape-coupled only (same philosophy as the proxy): no
 * DSH internals are imported, so runner mode against any HTTP server works
 * and DSH releases can only break us by renaming paths.
 */

import { request } from 'node:http'
import { randomUUID } from 'node:crypto'

const UNSUPPORTED_AFTER_FAILURES = 3
const SSE_BACKOFF_MS = [1_000, 3_000, 10_000, 30_000]

function postJson(target, path, body, timeoutMs) {
  return new Promise((resolve) => {
    const payload = Buffer.from(JSON.stringify(body), 'utf8')
    const req = request({
      host: target.host,
      port: target.port,
      method: 'POST',
      path,
      headers: { 'content-type': 'application/json', 'content-length': payload.length },
      timeout: timeoutMs,
    }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      // A mid-body upstream death emits error on the RESPONSE (the request
      // only ever sees 'close'): settle the probe instead of hanging it.
      res.on('error', (e) => resolve({ status: 0, error: String(e?.message ?? e) }))
      res.on('end', () => {
        let parsed = null
        try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { /* non-JSON answer */ }
        resolve({ status: res.statusCode, body: parsed })
      })
    })
    req.on('timeout', () => req.destroy(new Error('probe timeout')))
    req.on('error', (error) => resolve({ status: 0, error: String(error?.message ?? error) }))
    req.end(payload)
  })
}

export function createHostProbe({ target, intervalMs = 30_000, probeTimeoutMs = 5_000, handshakeTimeoutMs = 10_000, log = () => {} }) {
  const enabled = intervalMs > 0
  const state = {
    enabled,
    supported: null, // null = unknown yet, false = upstream is not a DSH host
    probe: { ok: null, at: null, ms: null, error: null, describe: null },
    events: { connected: false, connectedAt: null, lastFrameAt: null, framesSeen: 0, sessionCount: 0, runningCount: 0 },
    sessions: new Map(), // sessionId → running (deltas since subscribe)
  }
  let timer = null
  let failures = 0
  let shapeWrong = 0
  let sseReq = null
  let sseAttempt = 0
  let sseTimer = null
  let closed = false

  async function probe() {
    const startedAt = Date.now()
    const res = await postJson(target(), '/api/host.describe', {
      type: 'client-request',
      rpcId: randomUUID(),
      method: 'host.describe',
      payload: {},
    }, probeTimeoutMs)
    const ms = Date.now() - startedAt
    if (res.body?.result && typeof res.body.result === 'object' && 'ok' in res.body.result) {
      // A server-response envelope came back: this IS the DSH /api surface
      // (an RPC-level failure still means the stack is alive).
      failures = 0
      shapeWrong = 0
      state.supported = true
      state.probe = res.body.result.ok === true
        ? { ok: true, at: Date.now(), ms, error: null, describe: res.body.result.value ?? null }
        : { ok: false, at: Date.now(), ms, error: 'rpc error', describe: null }
      return
    }
    failures += 1
    state.probe = { ok: false, at: Date.now(), ms, error: res.error ?? `HTTP ${res.status}`, describe: null }
    // "Wrong shape" = the upstream demonstrably is not a DSH host: explicit
    // 404/501, or a 200 whose body is not a server-response envelope (MiMo's
    // catch-all UI route answers everything with HTML). Transport-level
    // failures (refused/timeout) do NOT count — that may be a down DSH.
    if (res.status === 404 || res.status === 501 || res.status === 200) shapeWrong += 1
    if (shapeWrong >= UNSUPPORTED_AFTER_FAILURES && state.supported !== false) {
      state.supported = false
      stopSse()
      log('host-probe: upstream is not a DSH host (no /api RPC surface) — host telemetry off')
    }
  }

  function applyFrame(payload) {
    state.events.framesSeen += 1
    state.events.lastFrameAt = Date.now()
    if (payload.type === 'host/session-added') state.sessions.set(payload.sessionId, false)
    else if (payload.type === 'host/session-status') state.sessions.set(payload.sessionId, Boolean(payload.running))
    else if (payload.type === 'host/session-removed') state.sessions.delete(payload.sessionId)
    // host/agent-error and future frame types only refresh lastFrameAt.
    state.events.sessionCount = state.sessions.size
    state.events.runningCount = [...state.sessions.values()].filter(Boolean).length
  }

  function connectSse() {
    if (closed || state.supported === false) return
    // Handshake-only deadline: cleared once headers arrive — an established
    // host event stream may be legitimately quiet for minutes.
    const req = request({ host: target().host, port: target().port, method: 'GET', path: '/api/events.host', timeout: handshakeTimeoutMs }, (res) => {
      req.setTimeout(0)
      const isSse = String(res.headers['content-type'] ?? '').includes('text/event-stream')
      if (res.statusCode !== 200 || !isSse) {
        res.resume()
        // A catch-all UI route (e.g. MiMo's) answers every path with 200
        // HTML — that is definitive "not a DSH host", same as 404 here.
        if (res.statusCode === 404 || res.statusCode === 501 || res.statusCode === 200) {
          state.supported = false
          log('host-probe: upstream has no host event stream — telemetry off')
          return
        }
        scheduleSse()
        return
      }
      sseReq = req
      state.events.connected = true
      state.events.connectedAt = Date.now()
      sseAttempt = 0
      let buffer = ''
      res.on('data', (chunk) => {
        buffer += chunk.toString('utf8')
        let boundary
        while ((boundary = buffer.indexOf('\n\n')) !== -1) {
          const event = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          for (const line of event.split('\n')) {
            if (!line.startsWith('data:')) continue
            let parsed = null
            try { parsed = JSON.parse(line.slice(5).trim()) } catch { continue }
            applyFrame(parsed?.payload ?? parsed)
          }
        }
      })
      res.on('end', () => { state.events.connected = false; sseReq = null; scheduleSse() })
      res.on('error', () => { state.events.connected = false; sseReq = null; scheduleSse() })
    })
    req.on('timeout', () => req.destroy())
    req.on('error', () => scheduleSse())
    req.end()
  }

  function scheduleSse() {
    if (closed || state.supported === false) return
    const delay = SSE_BACKOFF_MS[Math.min(sseAttempt, SSE_BACKOFF_MS.length - 1)]
    sseAttempt += 1
    sseTimer = setTimeout(connectSse, delay)
  }

  function stopSse() {
    if (sseTimer !== null) { clearTimeout(sseTimer); sseTimer = null }
    sseReq?.destroy()
    sseReq = null
    state.events.connected = false
  }

  return {
    start() {
      if (!enabled || timer !== null) return
      probe()
      timer = setInterval(probe, intervalMs)
      connectSse()
    },
    /** Probe once on demand (the status page refresh also nudges freshness). */
    async refresh() {
      if (!enabled || state.supported === false) return
      await probe()
    },
    state() {
      return {
        enabled,
        supported: state.supported,
        probe: { ...state.probe, describe: state.probe.describe === null ? null : {
          version: state.probe.describe.version,
          model: state.probe.describe.model ?? null,
          attachedSessions: state.probe.describe.attachedSessions ?? null,
        } },
        events: { ...state.events },
      }
    },
    close() {
      closed = true
      if (timer !== null) clearInterval(timer)
      timer = null
      stopSse()
    },
  }
}
