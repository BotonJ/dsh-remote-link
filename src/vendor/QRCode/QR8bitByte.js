//---------------------------------------------------------------------
// QRCode for JavaScript
//
// Copyright (c) 2009 Kazuhiko Arase
//
// URL: http://www.d-project.com/
//
// Licensed under the MIT license:
//   http://www.opensource.org/licenses/mit-license.php
//
// The word "QR Code" is registered trademark of 
// DENSO WAVE INCORPORATED
//   http://www.denso-wave.com/qrcode/faqpatent-e.html
//
//---------------------------------------------------------------------
// LOCAL PATCH (dsh-remote-link): the original wrote raw UTF-16 code units
// as 8-bit values, truncating every code point above U+00FF (Chinese,
// emoji, ...). This copy UTF-8 encodes the string first — the same fix the
// `qrcode` npm package applied — so non-ASCII payloads survive the round
// trip. See src/vendor/QRCode/NOTICE.md.
//---------------------------------------------------------------------

var QRMode = require('./QRMode');

function QR8bitByte(data) {
	this.mode = QRMode.MODE_8BIT_BYTE;
	this.data = data;
	this.parsedData = [];

	// UTF-8 encode
	for (var i = 0; i < data.length; i++) {
		var c = data.charCodeAt(i);
		if (c < 0x80) {
			this.parsedData.push(c);
		} else if (c < 0x800) {
			this.parsedData.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
		} else if (c >= 0xd800 && c <= 0xdbff) {
			// high surrogate → 4-byte sequence
			var lo = data.charCodeAt(++i);
			var cp = 0x10000 + ((c - 0xd800) << 10) + (lo - 0xdc00);
			this.parsedData.push(
				0xf0 | (cp >> 18),
				0x80 | ((cp >> 12) & 0x3f),
				0x80 | ((cp >> 6) & 0x3f),
				0x80 | (cp & 0x3f));
		} else {
			this.parsedData.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
		}
	}
}

QR8bitByte.prototype = {

	getLength : function() {
		return this.parsedData.length;
	},

	write : function(buffer) {
		for (var i = 0; i < this.parsedData.length; i++) {
			buffer.put(this.parsedData[i], 8);
		}
	}
};

module.exports = QR8bitByte;
