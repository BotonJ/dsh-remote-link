/**
 * HTTP/WebSocket reverse proxy onto the loopback DSH webserver.
 *
 * The Host header is rewritten to the loopback origin so the connection
 * layer's trust fence (loopback-Host DNS-rebinding guard) accepts proxied
 * requests; hop-by-hop headers are dropped per RFC 7230 §6.1.
 */

import { request } from 'node:http'

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

function forwardedHeaders(req, target) {
  const headers = { ...req.headers }
  const connectionTokens = String(req.headers.connection ?? '')
    .split(',').map((token) => token.trim().toLowerCase())
  for (const header of [...HOP_BY_HOP, ...connectionTokens]) delete headers[header]
  headers.host = `${target.host}:${target.port}`
  // The backend enforces same-origin on RPC POSTs (CSRF fence): rewrite Host
  // alone is not enough — the browser's Origin/Referer still name the public
  // URL and the call 403s. Strip both so the upstream sees an own-origin call.
  delete headers.origin
  delete headers.referer
  return headers
}

export function proxyRequest(req, res, target, onError) {
  const upstream = request({
    host: target.host,
    port: target.port,
    method: req.method,
    path: req.url,
    headers: forwardedHeaders(req, target),
  })
  upstream.on('response', (upstreamRes) => {
    const headers = { ...upstreamRes.headers }
    const connectionTokens = String(upstreamRes.headers.connection ?? '')
      .split(',').map((token) => token.trim().toLowerCase())
    for (const header of [...HOP_BY_HOP, ...connectionTokens]) delete headers[header]
    res.writeHead(upstreamRes.statusCode, headers)
    upstreamRes.pipe(res)
  })
  upstream.on('error', (error) => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
    res.end(`upstream unavailable: ${String(error?.message ?? error)}`)
    onError?.(error)
  })
  req.on('aborted', () => upstream.destroy())
  req.pipe(upstream)
}

export function proxyUpgrade(req, socket, head, target, onError, { onEstablished } = {}) {
  const upstream = request({
    host: target.host,
    port: target.port,
    method: req.method,
    path: req.url,
    headers: { ...forwardedHeaders(req, target), connection: 'Upgrade', upgrade: req.headers.upgrade ?? 'websocket' },
  })
  upstream.on('upgrade', (_upstreamRes, upstreamSocket, upstreamHead) => {
    const headerBlock = Object.entries(_upstreamRes.headers)
      .map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value}\r\n`)
      .join('')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\n${headerBlock}\r\n`)
    if (upstreamHead.length > 0) socket.write(upstreamHead)
    if (head.length > 0) upstreamSocket.write(head)
    upstreamSocket.pipe(socket)
    socket.pipe(upstreamSocket)
    // Established before the pipes can deliver a chunk (same tick), so the
    // observer sees every byte of both directions; seeds replay the heads
    // already written. Returns a disposer for teardown.
    const detach = onEstablished?.(socket, upstreamSocket, upstreamHead) ?? null
    const teardown = () => { detach?.(); upstreamSocket.destroy(); socket.destroy() }
    upstreamSocket.on('close', teardown)
    socket.on('close', teardown)
    upstreamSocket.on('error', teardown)
    socket.on('error', teardown)
  })
  upstream.on('response', (upstreamRes) => {
    // The upstream refused the upgrade (e.g. unknown path): pass the verdict on.
    socket.end(`HTTP/1.1 ${upstreamRes.statusCode} ${upstreamRes.statusMessage ?? ''}\r\nConnection: close\r\n\r\n`)
    upstreamRes.resume()
  })
  upstream.on('error', (error) => {
    socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n')
    onError?.(error)
  })
  upstream.end()
}
