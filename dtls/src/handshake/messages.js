'use strict';
// Handshake messages — RFC 8446 §4.3.1, §4.4.2, §4.4.3, §4.4.4.

const crypto = require('node:crypto');
const { HS_TYPE, NAMES, SIG_SCHEME } = require('../constants.js');
const { encodeExtensions } = require('./extensions.js');
const { hkdfExpandLabel } = require('../crypto/hkdf.js');

const uint24 = (n) => { const b = Buffer.alloc(3); b[0]=(n>>16)&0xff; b[1]=(n>>8)&0xff; b[2]=n&0xff; return b; };
const readU24 = (b,o) => (b[o]<<16)|(b[o+1]<<8)|b[o+2];

// ===== EncryptedExtensions (§4.3.1) =====
function buildEncryptedExtensions(extList = []) { return encodeExtensions(extList); }
function parseEncryptedExtensions(body) {
  const { extensions } = require('./extensions.js').decodeExtensions(body, 0);
  return { extensions };
}

// ===== Certificate (§4.4.2) =====
//   opaque certificate_request_context<0..2^8-1>;  (server: empty)
//   CertificateEntry certificate_list<0..2^24-1>;
//     opaque cert_data<1..2^24-1>;
//     Extension extensions<0..2^16-1>;  (leaf'te boş olabilir)
function buildCertificate({ context = Buffer.alloc(0), certChainDER = [] }) {
  if (context.length > 255) throw new RangeError('ctx > 255');
  const entries = certChainDER.map((der) => Buffer.concat([
    uint24(der.length), der,
    Buffer.from([0x00, 0x00]), // empty extensions
  ]));
  const listBody = Buffer.concat(entries);
  return Buffer.concat([
    Buffer.from([context.length]), context,
    uint24(listBody.length), listBody,
  ]);
}
function parseCertificate(body) {
  let o = 0;
  const ctxLen = body.readUInt8(o); o += 1;
  const context = body.slice(o, o + ctxLen); o += ctxLen;
  const listLen = readU24(body, o); o += 3;
  const end = o + listLen;
  const entries = [];
  while (o < end) {
    const cLen = readU24(body, o); o += 3;
    const cert = body.slice(o, o + cLen); o += cLen;
    const eLen = body.readUInt16BE(o); o += 2;
    const extData = body.slice(o, o + eLen); o += eLen;
    entries.push({ cert, extData });
  }
  return { context, entries };
}

// ===== CertificateVerify (§4.4.3) =====
// Imza girdisi:
//   64 * 0x20  ||  "TLS 1.3, server CertificateVerify"  ||  0x00  ||  transcript_hash
// veya "client CertificateVerify" (mutual auth).
const CV_SERVER_CONTEXT = Buffer.concat([
  Buffer.alloc(64, 0x20),
  Buffer.from('TLS 1.3, server CertificateVerify', 'ascii'),
  Buffer.from([0x00]),
]);
const CV_CLIENT_CONTEXT = Buffer.concat([
  Buffer.alloc(64, 0x20),
  Buffer.from('TLS 1.3, client CertificateVerify', 'ascii'),
  Buffer.from([0x00]),
]);

function certVerifyInput(role, transcriptHash) {
  const prefix = role === 'server' ? CV_SERVER_CONTEXT : CV_CLIENT_CONTEXT;
  return Buffer.concat([prefix, transcriptHash]);
}

function signCertVerify({ role, privateKey, sigScheme, transcriptHash }) {
  const input = certVerifyInput(role, transcriptHash);
  let sig;
  if (sigScheme === SIG_SCHEME.ECDSA_SECP256R1_SHA256) {
    sig = crypto.sign('sha256', input, { key: privateKey, dsaEncoding: 'der' });
  } else if (sigScheme === SIG_SCHEME.RSA_PSS_RSAE_SHA256) {
    sig = crypto.sign('sha256', input, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
  } else if (sigScheme === SIG_SCHEME.ED25519) {
    sig = crypto.sign(null, input, privateKey);
  } else {
    throw new Error(`unsupported sig scheme: 0x${sigScheme.toString(16)}`);
  }
  const out = Buffer.alloc(4 + sig.length);
  out.writeUInt16BE(sigScheme, 0);
  out.writeUInt16BE(sig.length, 2);
  sig.copy(out, 4);
  return out;
}
function parseCertVerify(body) {
  const sigScheme = body.readUInt16BE(0);
  const sigLen = body.readUInt16BE(2);
  const signature = body.slice(4, 4 + sigLen);
  return { sigScheme, signature };
}
function verifyCertVerify({ role, publicKey, sigScheme, signature, transcriptHash }) {
  const input = certVerifyInput(role, transcriptHash);
  if (sigScheme === SIG_SCHEME.ECDSA_SECP256R1_SHA256) {
    return crypto.verify('sha256', input, { key: publicKey, dsaEncoding: 'der' }, signature);
  } else if (sigScheme === SIG_SCHEME.RSA_PSS_RSAE_SHA256) {
    return crypto.verify('sha256', input, { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
  } else if (sigScheme === SIG_SCHEME.ED25519) {
    return crypto.verify(null, input, publicKey, signature);
  }
  throw new Error(`unsupported sig scheme: 0x${sigScheme.toString(16)}`);
}

// ===== Finished (§4.4.4) =====
// verify_data = HMAC(finished_key, Transcript-Hash up to but NOT including Finished)
function buildFinished({ hash, finishedKey, transcriptHash }) {
  return crypto.createHmac(hash, finishedKey).update(transcriptHash).digest();
}
function verifyFinished({ hash, finishedKey, transcriptHash, received }) {
  const expected = buildFinished({ hash, finishedKey, transcriptHash });
  if (expected.length !== received.length) return false;
  return crypto.timingSafeEqual(expected, received);
}

module.exports = {
  buildEncryptedExtensions, parseEncryptedExtensions,
  buildCertificate, parseCertificate,
  signCertVerify, parseCertVerify, verifyCertVerify, certVerifyInput,
  buildFinished, verifyFinished,
};
