'use strict';

const crypto = require('node:crypto');
const { HS_TYPE } = require('../constants.js');
const { hashLen } = require('../crypto/hkdf.js');

// DTLS handshake message header normalization.
// RFC 9147 §5.2 + RFC 8446 §4.4.1:
// Transcript hash DTLS 12-byte header üzerinden değil,
// 4-byte TLS 1.3 header (type + 24-bit length) + body üzerinden hesaplanır.
// DTLS-specific alanlar (message_seq, fragment_offset, fragment_length) hariç tutulur.
function normalizeDtlsHandshakeForTranscript(rawHandshake) {
  if (rawHandshake.length < 12) {
    throw new Error(`handshake too short: ${rawHandshake.length}`);
  }

  // TLS 1.3 header: [msg_type(1)] + [length(3)]
  // DTLS header:    [msg_type(1)] + [length(3)] + [message_seq(2)] + [fragment_offset(3)] + [fragment_length(3)]
  // Sadece ilk 4 byte (type + total length) tutulur, geri kalan 8 byte atılır.
  const tlsHeader = Buffer.alloc(4);
  tlsHeader[0] = rawHandshake[0]; // msg_type
  tlsHeader[1] = rawHandshake[1]; // length[0]  (big-endian u24)
  tlsHeader[2] = rawHandshake[2]; // length[1]
  tlsHeader[3] = rawHandshake[3]; // length[2]

  // byte 4..11 → DTLS-only alanlar → atla
  const body = rawHandshake.slice(12);
  return Buffer.concat([tlsHeader, body]);
}

class Transcript {
  constructor(hashName) {
    this.hashName = hashName;
    this.hashLen  = hashLen(hashName);
    this.h = crypto.createHash(hashName);
    this.log = []; // Debug için
  }

  // DTLS wire formatındaki handshake mesajını normalize edip hash'e ekle
  appendDtls(rawDtlsHandshake) {
    const normalized = normalizeDtlsHandshakeForTranscript(rawDtlsHandshake);
    this.h.update(normalized);
    this.log.push({ msgType: normalized[0], rawLen: rawDtlsHandshake.length, normalizedLen: normalized.length });
    return this;
  }

  // Zaten TLS 1.3 formatındaki ham buffer'ı direkt ekle (örn: MessageHash pseudo-message)
  appendRaw(msgBuf) {
    this.h.update(msgBuf);
    this.log.push({ msgType: msgBuf[0], rawLen: msgBuf.length, note: 'raw' });
    return this;
  }

  // RFC 8446 §4.4.1 — HelloRetryRequest sonrası transcript'i
  // "message_hash" sözde mesajı ile değiştir.
  //
  // Üretilen pseudo-message her zaman 4-byte TLS 1.3 header kullanır
  // (DTLS 12-byte header KULLANILMAZ — RFC 9147 §5.2'de açıkça belirtilmiş):
  //
  //   struct {
  //     HandshakeType msg_type = message_hash(254);
  //     uint24 length = Hash.length;
  //     opaque body[Hash.length] = Hash(CH1);
  //   }
  replaceWithMessageHash() {
    const ch1Digest = this.h.digest(); // Şimdiye kadar hash'lenenin özeti (CH1)

    const newH = crypto.createHash(this.hashName);

    // 4-byte TLS 1.3 pseudo-message header
    const hdr = Buffer.alloc(4);
    hdr.writeUInt8(HS_TYPE.MESSAGE_HASH, 0); // 254
    hdr.writeUInt8(0, 1);
    hdr.writeUInt8(0, 2);
    hdr.writeUInt8(this.hashLen, 3); // SHA-256 → 32, SHA-384 → 48

    newH.update(hdr);
    newH.update(ch1Digest);
    this.h = newH;

    this.log.push({
      msgType: HS_TYPE.MESSAGE_HASH,
      rawLen: 4 + this.hashLen,
      note: 'HRR message_hash transform',
      ch1Digest: ch1Digest.toString('hex'),
    });
    return this;
  }

  // Mevcut transcript hash'ini hesapla (hash state'ini BOZMAZ — copy kullanır)
  digest() {
    return this.h.copy().digest();
  }

  // Debug snapshot
  snapshot() {
    return {
      hash: this.hashName,
      messages: this.log.map(m => ({ ...m })),
      currentDigest: this.digest().toString('hex'),
    };
  }
}

module.exports = {
  Transcript,
  normalizeDtlsHandshakeForTranscript,
};