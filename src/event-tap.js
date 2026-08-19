/**
 * Mux event tap: the gateway's own subscription to /api/events.mux (the SSE
 * variant of the browser's WebSocket downlink), watching for pending user
 * interactions (approval/question requested/resolved).
 *
 * Why the gateway subscribes itself: mux frames only flow to OPEN
 * subscriptions — when no browser is connected, sniffing the proxied stream
 * would see nothing (each browser connection owns its stream). Our own
 * subscription sees interactions exactly when nobody else can, which is the
 * only case worth pushing about.
 *
 * Non-DSH upstreams self-disable via the same shape detection as
 * host-probe.js (catch-all UI routes answer /api/* with 200 HTML).
 * Oversized frames (> 256 KiB, e.g. base64 attachments) are skipped:
 * interaction frames are always tiny.
 */

import { request } from 'node:http'

const MAX_INTERESTING_FRAME = 256 * 1024
const BACKOFF_MS = [1_000, 3_000, 10_000, 30_000]

export function createEventTap({ target, onRequested, onResolved, handshakeTimeoutMs = 10_000, log = () => {} }) {
  const state = { connected: false, supported: null, framesSeen: 0, interactionsSeen: 0, lastFrameAt: null }
  let req = null
  let attempt = 0
  let timer = null
  let closed = false

  function handlePayload(payload) {
    if (payload === null || typeof payload !== 'object') return
    state.framesSeen += 1
    state.lastFrameAt = Date.now()
    if (payload.type === 'approval/requested' || payload.type === 'question/requested') {
      state.interactionsSeen += 1
      onRequested?.({
        kind: payload.type === 'approval/requested' ? 'approval' : 'question',
        id: String(payload.approvalId ?? payload.questionRpcId ?? payload.rpcId ?? ''),
        summary: typeof payload.summary === 'string' ? payload.summary.slice(0, 120) : null,
      })
    } else if (payload.type === 'approval/resolved' || payload.type === 'question/resolved') {
      onResolved?.({
        kind: payload.type === 'approval/resolved' ? 'approval' : 'question',
        id: String(payload.approvalId ?? payload.questionRpcId ?? ''),
      })
    }
  }

  function connect() {
    if (closed || state.supported === false) return
    // Handshake-only deadline: cleared once headers arrive — an established
    // mux stream may be legitimately quiet until the next interaction.
    req = request({ host: target().host, port: target().port, method: 'GET', path: '/api/events.mux', timeout: handshakeTimeoutMs }, (res) => {
      req.setTimeout(0)
      const isSse = String(res.headers['content-type'] ?? '').includes('text/event-stream')
      if (res.statusCode !== 200 || !isSse) {
        res.resume()
        if (res.statusCode === 404 || res.statusCode === 501 || res.statusCode === 200) {
          state.supported = false
          log('event-tap: upstream has no mux event stream — interaction push off')
          return
        }
        schedule()
        return
      }
      state.connected = true
      state.supported = true
      attempt = 0
      let buffer = ''
      res.on('data', (chunk) => {
        buffer += chunk.toString('utf8')
        let boundary
        while ((boundary = buffer.indexOf('\n\n')) !== -1) {
          const event = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          if (event.length > MAX_INTERESTING_FRAME) continue
          for (const line of event.split('\n')) {
            if (!line.startsWith('data:')) continue
            let parsed = null
            try { parsed = JSON.parse(line.slice(5).trim()) } catch { continue }
            handlePayload(parsed?.payload ?? parsed)
          }
        }
      })
      res.on('end', () => { state.connected = false; req = null; schedule() })
      res.on('error', () => { state.connected = false; req = null; schedule() })
    })
    req.on('timeout', () => req.destroy())
    req.on('error', () => schedule())
    req.end()
  }

  function schedule() {
    if (closed || state.supported === false) return
    timer = setTimeout(connect, BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)])
    attempt += 1
  }

  return {
    start() {
      if (closed) return
      connect()
    },
    state() {
      return { ...state }
    },
    close() {
      closed = true
      if (timer !== null) clearTimeout(timer)
      req?.destroy()
      req = null
      state.connected = false
    },
  }
}
