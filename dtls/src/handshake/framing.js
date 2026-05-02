'use strict';
// DTLS 1.3 Handshake Message Framing — RFC 9147 §5.
//
// DTLS handshake header TLS'tekinden farklı: 12 byte, fragment bilgisi içerir.
//
//   struct {
//       HandshakeType msg_type;         // uint8
//       uint24 length;                  // tüm mesajın boyu (yeniden birleştirilmiş)
//       uint16 message_seq;             // DTLS-specific; her mesaj için monoton artar
//       uint24 fragment_offset;         // bu parçanın full message içindeki offset'i
//       uint24 fragment_length;         // bu parçanın boyu
//       opaque body[fragment_length];
//   } Handshake;
//
// Tek datagrama sığmayan mesajlar için parçalama (örn. Certificate) kritik — Faz 3.
// Faz 1'de tek-parça mesajları kodlayıp/çözebiliyoruz; multi-fragment reassembly henüz yok.

const crypto = require('node:crypto');
const {
  HS_TYPE, CIPHER_SUITE, HRR_RANDOM, NAMES,
} = require('../constants.js');
const {
  encodeExtensions, decodeExtensions,
  ext_supportedVersionsClient, ext_supportedVersionsServer,
  ext_supportedGroups, ext_signatureAlgorithms,
  ext_keyShareClient, ext_keyShareServer,
  ext_serverName, ext_cookie, ext_pskKeyExchangeModes,
} = require('./extensions.js');

const HS_HEADER_LEN = 12;

function encodeHandshake({ msgType, messageSeq, body, fragmentOffset = 0, fragmentLength = null }) {
  const totalLen = body.length;
  const fragLen = fragmentLength ?? totalLen;
  const hdr = Buffer.alloc(HS_HEADER_LEN);
  hdr.writeUInt8(msgType, 0);
  writeUInt24BE(hdr, totalLen, 1);
  hdr.writeUInt16BE(messageSeq, 4);
  writeUInt24BE(hdr, fragmentOffset, 6);
  writeUInt24BE(hdr, fragLen, 9);
  return Buffer.concat([hdr, body]);
}

function decodeHandshake(buf, offset = 0) {
  if (buf.length - offset < HS_HEADER_LEN) throw new Error('handshake header too short');
  const msgType = buf.readUInt8(offset);
  const length = readUInt24BE(buf, offset + 1);
  const messageSeq = buf.readUInt16BE(offset + 4);
  const fragmentOffset = readUInt24BE(buf, offset + 6);
  const fragmentLength = readUInt24BE(buf, offset + 9);
  const bodyStart = offset + HS_HEADER_LEN;
  const bodyEnd = bodyStart + fragmentLength;
  if (bodyEnd > buf.length) {
    throw new Error(`handshake body truncated: need ${fragmentLength}, got ${buf.length - bodyStart}`);
  }
  return {
    msgType,
    msgTypeName: NAMES.HS_TYPE[msgType] || `UNKNOWN(${msgType})`,
    length, messageSeq, fragmentOffset, fragmentLength,
    body: buf.slice(bodyStart, bodyEnd),
    bytesConsumed: HS_HEADER_LEN + fragmentLength,
    isComplete: fragmentOffset === 0 && fragmentLength === length,
  };
}

// ============================================================================
// ClientHello — RFC 8446 §4.1.2 + DTLS-specific legacy_cookie field
//
//   ProtocolVersion legacy_version = 0x0303;       // TLS 1.2
//   Random random[32];
//   opaque legacy_session_id<0..32>;
//   opaque legacy_cookie<0..2^8-1>;                // DTLS only, MUST be empty in DTLS 1.3
//   CipherSuite cipher_suites<2..2^16-2>;
//   opaque legacy_compression_methods<1..2^8-1>;   // MUST be [0x00]
//   Extension extensions<8..2^16-1>;
// ============================================================================
function buildClientHello({
  random = crypto.randomBytes(32),
  sessionId = Buffer.alloc(0),
  cipherSuites = [
    CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
    CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
  ],
  extensions,
}) {
  if (sessionId.length > 32) throw new RangeError('session_id > 32');

  const parts = [];
  parts.push(Buffer.from([0xfe, 0xfd])); // legacy_version = DTLS 1.2 — RFC 9147 §5.3
  parts.push(random);
  parts.push(Buffer.from([sessionId.length]));
  if (sessionId.length) parts.push(sessionId);
  parts.push(Buffer.from([0x00])); // legacy_cookie empty — RFC 9147 §5.3

  const csBuf = Buffer.alloc(2 + cipherSuites.length * 2);
  csBuf.writeUInt16BE(cipherSuites.length * 2, 0);
  cipherSuites.forEach((cs, i) => csBuf.writeUInt16BE(cs, 2 + i * 2));
  parts.push(csBuf);

  parts.push(Buffer.from([0x01, 0x00])); // compression_methods: 1 byte, value 0
  parts.push(encodeExtensions(extensions));

  return Buffer.concat(parts);
}

function parseClientHello(body) {
  let o = 0;
  const legacyVersion = body.readUInt16BE(o); o += 2;
  const random = body.slice(o, o + 32); o += 32;

  const sidLen = body.readUInt8(o); o += 1;
  if (sidLen > 32) throw new Error(`invalid session_id length: ${sidLen}`);
  const sessionId = body.slice(o, o + sidLen); o += sidLen;

  const cookieLen = body.readUInt8(o); o += 1;
  const legacyCookie = body.slice(o, o + cookieLen); o += cookieLen;
  // DTLS 1.3 zorunluluk: cookie alanı empty olmalı. Boş değilse warning'e değer.

  const csLen = body.readUInt16BE(o); o += 2;
  if (csLen % 2 !== 0) throw new Error('odd cipher_suites length');
  const cipherSuites = [];
  for (let i = 0; i < csLen; i += 2) {
    cipherSuites.push(body.readUInt16BE(o));
    o += 2;
  }

  const compLen = body.readUInt8(o); o += 1;
  const compression = body.slice(o, o + compLen); o += compLen;

  const { extensions } = decodeExtensions(body, o);

  return {
    legacyVersion, random, sessionId, legacyCookie,
    cipherSuites: cipherSuites.map(v => ({
      value: v,
      name: NAMES.CIPHER_SUITE[v] || `UNKNOWN(0x${v.toString(16)})`,
    })),
    compression,
    extensions,
  };
}

// ============================================================================
// ServerHello — aynı format; HelloRetryRequest = ServerHello + sabit random.
// ============================================================================
function buildServerHello({
  random = crypto.randomBytes(32),
  sessionId = Buffer.alloc(0),
  cipherSuite,
  extensions,
  isHRR = false,
}) {
  const serverRandom = isHRR ? HRR_RANDOM : random;
  if (serverRandom.length !== 32) throw new Error('server random must be 32 bytes');

  const parts = [];
  parts.push(Buffer.from([0xfe, 0xfd])); // legacy_version = DTLS 1.2 — RFC 9147 §5.4
  parts.push(serverRandom);
  parts.push(Buffer.from([sessionId.length]));
  if (sessionId.length) parts.push(sessionId);

  const cs = Buffer.alloc(2);
  cs.writeUInt16BE(cipherSuite, 0);
  parts.push(cs);

  parts.push(Buffer.from([0x00])); // legacy_compression_method (tek byte, no length prefix)
  parts.push(encodeExtensions(extensions));

  return Buffer.concat(parts);
}

function parseServerHello(body) {
  let o = 0;
  const legacyVersion = body.readUInt16BE(o); o += 2;
  const random = body.slice(o, o + 32); o += 32;
  const isHRR = random.equals(HRR_RANDOM);

  const sidLen = body.readUInt8(o); o += 1;
  const sessionId = body.slice(o, o + sidLen); o += sidLen;

  const cipherSuite = body.readUInt16BE(o); o += 2;
  const compression = body.readUInt8(o); o += 1;

  const { extensions } = decodeExtensions(body, o);

  return {
    legacyVersion, random, isHRR, sessionId,
    cipherSuite: {
      value: cipherSuite,
      name: NAMES.CIPHER_SUITE[cipherSuite] || `UNKNOWN(0x${cipherSuite.toString(16)})`,
    },
    compression, extensions,
  };
}

// ============================================================================
// uint24 helpers (big-endian, 3 byte)
// ============================================================================
function readUInt24BE(buf, offset) {
  return (buf.readUInt8(offset) << 16) | buf.readUInt16BE(offset + 1);
}
function writeUInt24BE(buf, value, offset) {
  if (value < 0 || value > 0xffffff) throw new RangeError('uint24 out of range');
  buf.writeUInt8((value >> 16) & 0xff, offset);
  buf.writeUInt16BE(value & 0xffff, offset + 1);
}

module.exports = {
  HS_HEADER_LEN,
  encodeHandshake, decodeHandshake,
  buildClientHello, parseClientHello,
  buildServerHello, parseServerHello,
  readUInt24BE, writeUInt24BE,
  // extension helpers re-export for ergonomik import
  ext_supportedVersionsClient, ext_supportedVersionsServer,
  ext_supportedGroups, ext_signatureAlgorithms,
  ext_keyShareClient, ext_keyShareServer,
  ext_serverName, ext_cookie, ext_pskKeyExchangeModes,
};
