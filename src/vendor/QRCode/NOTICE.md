# Vendored: qrcode-terminal@0.12.0 — vendor/QRCode

The QR encoder core used by this plugin is the battle-tested
Kazuhiko Arase "QRCode for JavaScript" implementation, vendored verbatim
from `qrcode-terminal@0.12.0` (https://github.com/gtanner/qrcode-terminal,
Apache-2.0 wrapper; the encoder itself is MIT © 2009 Kazuhiko Arase,
http://www.d-project.com/). It is the same engine that powers the classic
`qrcode` npm ecosystem and has been verified against countless scanners.

Files: `index.js`, `QRUtil.js`, `QRPolynomial.js`, `QRRSBlock.js`,
`QRBitBuffer.js`, `QR8bitByte.js`, `QRMath.js`, `QRMode.js`,
`QRMaskPattern.js`, `QRErrorCorrectLevel.js` — each retains its original
MIT header.

## Local modifications

- `QR8bitByte.js` — the original wrote raw UTF-16 code units as 8-bit
  values, truncating every code point above U+00FF (Chinese, emoji, …).
  This copy adds the standard UTF-8 byte encoding (same fix the `qrcode`
  npm package applied), so non-ASCII payloads survive the round trip.
