/**
 * Link keepalive: boundary-aware WebSocket ping injection.
 *
 * The DSH event downlinks (/api/events.mux, /api/events.host) carry business
 * frames only — the server never pings (WebSocketDownlinks.pump is a bare
 * for-await), so an idle remote session (agent thinking, user away) presents
 * zero bytes to every intermediary between the phone and this gateway. Tunnel
 * edges and carrier NATs reap such idle streams, and every reap costs the
 * client a full resync (its recovery model wipes all session state and
 * refetches history on each reconnect generation).
 *
 * This module keeps the downstream leg (gateway ↔ browser, the only leg that
 * crosses intermediaries; the upstream leg is loopback) alive by injecting an
 * RFC 6455 ping toward the browser whenever that direction has been idle for
 * one interval. Injection happens only at frame boundaries, tracked by an
 * incremental parser that observes (never consumes) the byte stream: writing
 * into a partially-delivered frame would corrupt the stream. Browsers answer
 * pings in-kernel (invisible to page JS), which both feeds bytes to every
 * idle reaper on the path and gives the gateway a per-leg RTT measure.
 *
 * Failure posture: any parser anomaly (reserved opcode, oversized frame)
 * permanently stops injection for that leg and the proxy degrades to the
 * plain pipe — the keepalive must never be able to break a working link.
 */

const OP_CONTINUATION = 0x0
const OP_TEXT = 0x1
const OP_BINARY = 0x2
const OP_CLOSE = 0x8
const OP_PING = 0x9
const OP_PONG = 0xa

export const CONTROL_OPCODES = new Set([OP_CLOSE, OP_PING, OP_PONG])
export const DATA_OPCODES = new Set([OP_CONTINUATION, OP_TEXT, OP_BINARY])

/** Incremental WebSocket frame-boundary parser.
 *
 * Observes a byte stream (one parser per direction) and reports each
 * completed frame via onFrame({ fin, rsv, opcode, masked, length, peek }).
 * Payload bytes are counted, never buffered beyond `peek` — at most the
 * first 8 payload bytes, delivered already unmasked so consumers can read
 * control-frame counters directly. Reserved opcodes (3–7, 11–15) or a
 * length above maxFrameBytes set `desynced` — a desynced parser stops
 * reporting and the caller must stop injecting on that leg. */
export function createBoundaryParser(onFrame, { maxFrameBytes = 512 * 1024 * 1024 } = {}) {
  let phase = 'b0' // b0 → b1 → ext → mask → payload
  let fin = false
  let rsv = 0
  let opcode = -1
  let masked = false
  let maskKey = Buffer.alloc(4)
  let maskKeyLen = 0
  let extBuf = Buffer.alloc(8)
  let extLen = 0
  let extBytesNeeded = 0
  let length = 0
  let payloadRemaining = 0
  let peek = null
  let peekRemaining = 0
  let framesSeen = 0
  let desynced = false

  const reserved = (code) => (code >= 3 && code <= 7) || (code >= 0xb && code <= 0xf)

  function beginPayload() {
    phase = 'payload'
    payloadRemaining = length
    peek = length === 0 ? Buffer.alloc(0) : Buffer.alloc(Math.min(8, length))
    peekRemaining = peek.length
    if (payloadRemaining === 0) frameDone()
  }

  function frameDone() {
    framesSeen += 1
    if (masked && peek.length > 0) {
      for (let i = 0; i < peek.length; i += 1) peek[i] ^= maskKey[i % 4]
    }
    phase = 'b0'
    maskKeyLen = 0
    extLen = 0
    onFrame({ fin, rsv, opcode, masked, length, peek, framesSeen })
  }

  return {
    get desynced() { return desynced },
    get atBoundary() { return phase === 'b0' },
    get framesSeen() { return framesSeen },
    feed(chunk) {
      if (desynced) return
      for (let i = 0; i < chunk.length; i += 1) {
        const byte = chunk[i]
        if (phase === 'payload') {
          if (peekRemaining > 0) {
            peek[peek.length - peekRemaining] = byte
            peekRemaining -= 1
          }
          payloadRemaining -= 1
          if (payloadRemaining === 0) frameDone()
          continue
        }
        if (phase === 'b0') {
          fin = (byte & 0x80) !== 0
          rsv = (byte & 0x70) >> 4
          opcode = byte & 0x0f
          if (reserved(opcode)) { desynced = true; return }
          phase = 'b1'
          continue
        }
        if (phase === 'b1') {
          masked = (byte & 0x80) !== 0
          const len7 = byte & 0x7f
          if (len7 < 126) {
            length = len7
            if (masked) { phase = 'mask' } else beginPayload()
          } else if (len7 === 126) {
            extBytesNeeded = 2
            phase = 'ext'
          } else {
            extBytesNeeded = 8
            phase = 'ext'
          }
          continue
        }
        if (phase === 'ext') {
          extBuf[extLen] = byte
          extLen += 1
          if (extLen === extBytesNeeded) {
            length = extBytesNeeded === 2 ? extBuf.readUInt16BE(0) : Number(extBuf.readBigUInt64BE(0))
            if (length > maxFrameBytes) { desynced = true; return }
            extLen = 0
            if (masked) phase = 'mask'
            else beginPayload()
          }
          continue
        }
        // 'mask': capture the 4 key bytes; peek unmasking happens in frameDone.
        maskKey[maskKeyLen] = byte
        maskKeyLen += 1
        if (maskKeyLen === 4) {
          maskKeyLen = 0
          beginPayload()
        }
      }
    },
  }
}

/** Attach keepalive telemetry to one proxied WebSocket leg.
 *
 * `downSocket` faces the browser (through the tunnel), `upstreamSocket` faces
 * the loopback DSH webserver. seedDown/seedUp are the bytes each side had
 * already sent past the 101 handshake (proxyUpgrade's head/upstreamHead).
 * Returns { dispose, stats } — dispose removes every listener and timer this
 * attached. intervalMs <= 0 disables injection entirely (stats stays alive
 * so the status page can still show per-leg counters). */
export function attachLinkKeepalive(downSocket, upstreamSocket, {
  intervalMs = 25_000, seedDown = Buffer.alloc(0), seedUp = Buffer.alloc(0),
  maxFrameBytes, now = () => Date.now(), log = () => {},
} = {}) {
  const attachedAt = now()
  const state = {
    enabled: intervalMs > 0, attachedAt,
    pingsSent: 0, pongsReceived: 0, lastPongAt: null, lastRttMs: null, worstRttMs: null,
    desynced: false, evicted: false, idleMs: 0, framesDown: 0, framesUp: 0,
  }
  if (!(intervalMs > 0)) return { dispose() {}, stats: () => ({ ...state }) }

  const outstanding = new Map() // ping counter → sent-at ms
  let pingCounter = 0
  let disposed = false
  let timer = null

  // gateway→browser direction: injection-safety boundaries + idle accounting
  // (any byte from the upstream keeps the tunnel fed; frame boundaries decide
  // where an injected ping may legally land).
  let lastDownDataAt = attachedAt
  const upParser = createBoundaryParser(() => {}, maxFrameBytes === undefined ? {} : { maxFrameBytes })
  // browser→gateway direction: pong correlation via unmasked peek counters.
  const downParser = createBoundaryParser((meta) => {
    if (meta.opcode !== OP_PONG || meta.peek.length < 4) return
    const sentAt = outstanding.get(meta.peek.readUInt32BE(0))
    if (sentAt === undefined) return
    outstanding.delete(meta.peek.readUInt32BE(0))
    state.pongsReceived += 1
    state.lastPongAt = now()
    state.lastRttMs = state.lastPongAt - sentAt
    if (state.worstRttMs === null || state.lastRttMs > state.worstRttMs) state.worstRttMs = state.lastRttMs
  }, maxFrameBytes === undefined ? {} : { maxFrameBytes })

  const onDownData = (chunk) => {
    downParser.feed(chunk)
    state.framesDown = downParser.framesSeen
  }
  const onUpData = (chunk) => {
    lastDownDataAt = now()
    upParser.feed(chunk)
    state.framesUp = upParser.framesSeen
  }

  const tick = () => {
    if (disposed) return
    state.desynced = upParser.desynced || downParser.desynced
    if (state.desynced) {
      log('keepalive: frame parser desynced on this leg — injection permanently disabled')
      clearInterval(timer)
      timer = null
      return
    }
    if (!upParser.atBoundary) return // mid-frame: never inject into a partial frame
    if (outstanding.size >= 3) {
      // Three unanswered pings (≈3×interval of one-way silence): the leg is
      // dead but TCP may not know yet (half-open mobile links can hang for
      // minutes). Close it ourselves so the client's reconnect loop starts
      // immediately instead of waiting for a timeout that only one side sees.
      state.evicted = true
      log('keepalive: 3 pings unanswered — closing dead leg')
      clearInterval(timer)
      timer = null
      downSocket.destroy()
      return
    }
    state.idleMs = now() - lastDownDataAt
    if (state.idleMs < intervalMs) return // active traffic already feeds the path
    pingCounter += 1
    const payload = Buffer.alloc(4)
    payload.writeUInt32BE(pingCounter, 0)
    outstanding.set(pingCounter, now())
    state.pingsSent += 1
    downSocket.write(Buffer.concat([Buffer.from([0x89, 0x04]), payload]))
  }

  const cleanup = () => {
    if (disposed) return
    disposed = true
    if (timer !== null) clearInterval(timer)
    timer = null
    outstanding.clear()
    downSocket.removeListener('data', onDownData)
    upstreamSocket.removeListener('data', onUpData)
  }

  if (seedDown.length > 0) onDownData(seedDown)
  if (seedUp.length > 0) onUpData(seedUp)
  downSocket.on('data', onDownData)
  upstreamSocket.on('data', onUpData)
  downSocket.on('close', cleanup)
  upstreamSocket.on('close', cleanup)
  timer = setInterval(tick, intervalMs)

  return {
    dispose: cleanup,
    stats: () => {
      state.idleMs = now() - lastDownDataAt
      state.desynced = upParser.desynced || downParser.desynced
      return { ...state }
    },
  }
}
