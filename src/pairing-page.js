/**
 * The /pair page served by the gateway: reads the QR fragment
 * (#p=<sid>.<secret>) or accepts the 6-digit short code, proves possession
 * of the secret via HMAC challenge-response, and stores the resulting
 * HttpOnly session cookie — after which the official web UI just works.
 *
 * HMAC-SHA256 is implemented in plain JS because the page loads over plain
 * HTTP on the LAN: `crypto.subtle` is undefined outside secure contexts.
 * HMAC_SHA256_JS is exported separately so tests can verify it against
 * node:crypto byte-for-byte.
 */

export const HMAC_SHA256_JS = String.raw`
function hmacSha256Hex(keyStr, msgStr) {
  var enc = new TextEncoder()
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)) }

  function sha256(bytes) {
    var h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    var bitLen = bytes.length * 8
    var padded = bytes.slice()
    padded.push(0x80)
    while (padded.length % 64 !== 56) padded.push(0)
    for (var i = 7; i >= 0; i--) padded.push((bitLen / Math.pow(2, i * 8)) & 0xff)

    for (var block = 0; block < padded.length; block += 64) {
      var w = new Array(64)
      for (var t = 0; t < 16; t++) {
        w[t] = (padded[block + t * 4] << 24) | (padded[block + t * 4 + 1] << 16) |
               (padded[block + t * 4 + 2] << 8) | padded[block + t * 4 + 3]
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        var ch = (e & f) ^ (~e & g)
        var temp1 = (hh + S1 + ch + K[t] + w[t]) | 0
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        var maj = (a & b) ^ (a & c) ^ (b & c)
        var temp2 = (S0 + maj) | 0
        hh = g; g = f; f = e; e = (d + temp1) | 0
        d = c; c = b; b = a; a = (temp1 + temp2) | 0
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0
    }
    var out = []
    for (i = 0; i < 8; i++) {
      out.push((h[i] >>> 24) & 0xff, (h[i] >>> 16) & 0xff, (h[i] >>> 8) & 0xff, h[i] & 0xff)
    }
    return out
  }

  function toHex(bytes) {
    var s = ''
    for (var i = 0; i < bytes.length; i++) s += (bytes[i] >>> 4).toString(16) + (bytes[i] & 15).toString(16)
    return s
  }

  var key = Array.from(enc.encode(keyStr))
  if (key.length > 64) key = sha256(key)
  while (key.length < 64) key.push(0)
  var oKey = key.map(function (b) { return b ^ 0x5c })
  var iKey = key.map(function (b) { return b ^ 0x36 })
  var inner = sha256(iKey.concat(Array.from(enc.encode(msgStr))))
  return toHex(sha256(oKey.concat(inner)))
}
`

export const PAIRING_PAGE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSH Remote Link 配对</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 420px; margin: 15vh auto; padding: 0 16px; color: #1a1a1a; }
  h1 { font-size: 20px; }
  #status { margin: 16px 0; padding: 12px; border-radius: 8px; background: #f2f2f7; word-break: break-all; }
  #status.err { background: #ffe5e5; }
  input { font-size: 22px; letter-spacing: 6px; width: 9ch; padding: 8px; text-align: center; border: 1px solid #c7c7cc; border-radius: 8px; }
  button { font-size: 17px; padding: 8px 18px; margin-left: 8px; border: none; border-radius: 8px; background: #0a84ff; color: #fff; }
</style>
</head>
<body>
<h1>DSH Remote Link 配对</h1>
<div id="status">正在配对…</div>
<div id="manual" style="display:none">
  <p>无法扫码？输入桌面端显示的 6 位短码：</p>
  <input id="code" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="off">
  <button onclick="pairWithCode()">配对</button>
</div>
<script>
${HMAC_SHA256_JS}
var statusEl = document.getElementById('status')
function fail(msg) { statusEl.textContent = msg; statusEl.className = 'err' }

async function pair(queryValue, isCode, secret) {
  try {
    var res = await fetch('/pair/challenge?' + (isCode ? 'code=' : 'sid=') + encodeURIComponent(queryValue))
    if (!res.ok) { fail('获取挑战失败（' + res.status + '）——短码或二维码可能已过期'); return }
    var ch = await res.json()
    var proof = hmacSha256Hex(secret, ch.sid + '|' + ch.nonce + '|' + ch.ts)
    // The short-code path must verify with the code as the shared secret
    // (the server keys the proof on the code, not on the pairing secret).
    var body = isCode
      ? { code: queryValue, ts: ch.ts, proof: proof, name: navigator.userAgent.slice(0, 64) }
      : { sid: ch.sid, ts: ch.ts, proof: proof, name: navigator.userAgent.slice(0, 64) }
    var verify = await fetch('/pair/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    })
    if (verify.ok) { statusEl.textContent = '配对成功，正在进入…'; location.href = '/' }
    else { fail('配对被拒绝（' + (await verify.text()) + '）') }
  } catch (e) { fail('网络错误：' + e) }
}

function pairWithCode() {
  var code = document.getElementById('code').value.trim()
  if (!/^\\d{6}$/.test(code)) { fail('请输入 6 位数字短码'); return }
  statusEl.className = ''; statusEl.textContent = '正在配对…'
  pair(code, true, code)
}

var fragment = location.hash.match(/^#p=([^.]+)\\.([A-Za-z0-9_-]+)$/)
if (fragment) {
  pair(fragment[1], false, fragment[2])
} else {
  statusEl.textContent = ''
  document.getElementById('manual').style.display = 'block'
}
</script>
</body>
</html>
`
