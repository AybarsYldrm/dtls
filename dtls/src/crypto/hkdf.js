'use strict';
// HKDF (RFC 5869) + TLS 1.3 Key Derivation (RFC 8446 §7.1).
//
// DTLS 1.3 TLS 1.3'ün key schedule'ını aynen miras alır (RFC 9147 §5.9);
// "tls13 " prefix'i DEĞİŞMEZ — DTLS için ayrı bir prefix yok.
//
// Şema:
//   HKDF-Extract(salt, IKM)              = HMAC(salt, IKM)
//   HKDF-Expand(PRK, info, L)            = T(1) || T(2) ... ilk L byte
//   HKDF-Expand-Label(Secret, Label, Ctx, L) =
//     HKDF-Expand(Secret, HkdfLabel, L)
//   HkdfLabel = { uint16 length=L,
//                 opaque label<7..255>   = "tls13 " + Label,
//                 opaque context<0..255> = Ctx }
//   Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)

const crypto = require('node:crypto');

// --------------------------------------------------------------------------
// HKDF-Extract — HMAC(salt, IKM). Salt yoksa Hash.length sıfır byte kullanılır.
// --------------------------------------------------------------------------
function hkdfExtract(hash, salt, ikm) {
  const saltBuf = (salt && salt.length > 0) ? salt : Buffer.alloc(hashLen(hash), 0);
  return crypto.createHmac(hash, saltBuf).update(ikm).digest();
}

// --------------------------------------------------------------------------
// HKDF-Expand — iteratif HMAC, çıktı uzunluğu 255*HashLen ile sınırlı.
// --------------------------------------------------------------------------
function hkdfExpand(hash, prk, info, length) {
  const hLen = hashLen(hash);
  if (length > 255 * hLen) throw new RangeError(`HKDF-Expand length too large (${length} > ${255 * hLen})`);

  const out = Buffer.alloc(length);
  let T = Buffer.alloc(0);
  let written = 0;
  let counter = 1;
  while (written < length) {
    const h = crypto.createHmac(hash, prk);
    h.update(T);
    h.update(info);
    h.update(Buffer.from([counter]));
    T = h.digest();
    const take = Math.min(hLen, length - written);
    T.copy(out, written, 0, take);
    written += take;
    counter += 1;
  }
  return out;
}

// --------------------------------------------------------------------------
// HKDF-Expand-Label — TLS 1.3 özgü yapılandırılmış info üretir.
//
//   struct {
//     uint16 length = L;
//     opaque label<7..255>   = "tls13 " + Label;
//     opaque context<0..255> = Context;
//   } HkdfLabel;
//
// label_full byte uzunluğu 7..255 arasında olmalı — TLS stack'larının tipik hatası:
// uzun label kullanırken taşırma. Burada runtime kontrol var.
// --------------------------------------------------------------------------
const LABEL_PREFIX = Buffer.from('tls13 ', 'ascii');

function buildHkdfLabel(length, label, context) {
  const labelBuf = typeof label === 'string' ? Buffer.from(label, 'ascii') : label;
  const ctxBuf   = context ? (Buffer.isBuffer(context) ? context : Buffer.from(context)) : Buffer.alloc(0);

  const fullLabel = Buffer.concat([LABEL_PREFIX, labelBuf]);
  if (fullLabel.length < 7 || fullLabel.length > 255) {
    throw new RangeError(`HkdfLabel.label length out of range: ${fullLabel.length}`);
  }
  if (ctxBuf.length > 255) {
    throw new RangeError(`HkdfLabel.context length > 255: ${ctxBuf.length}`);
  }

  const out = Buffer.alloc(2 + 1 + fullLabel.length + 1 + ctxBuf.length);
  let o = 0;
  out.writeUInt16BE(length, o); o += 2;
  out.writeUInt8(fullLabel.length, o); o += 1;
  fullLabel.copy(out, o); o += fullLabel.length;
  out.writeUInt8(ctxBuf.length, o); o += 1;
  ctxBuf.copy(out, o);
  return out;
}

function hkdfExpandLabel(hash, secret, label, context, length) {
  const info = buildHkdfLabel(length, label, context);
  return hkdfExpand(hash, secret, info, length);
}

// --------------------------------------------------------------------------
// Derive-Secret(Secret, Label, Messages):
//   HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
//
// `messagesHash` YA transcript sonucu (Buffer) YA boş hash olabilir.
// Boş hash için hashEmpty(hash) yardımcısı kullanılır.
// --------------------------------------------------------------------------
function deriveSecret(hash, secret, label, messagesHash) {
  const hLen = hashLen(hash);
  const ctx = messagesHash ?? hashEmpty(hash);
  if (ctx.length !== hLen) {
    throw new Error(`Derive-Secret: context length ${ctx.length} != Hash.length ${hLen}`);
  }
  return hkdfExpandLabel(hash, secret, label, ctx, hLen);
}

// --------------------------------------------------------------------------
// Yardımcılar
// --------------------------------------------------------------------------
function hashLen(name) {
  switch (name.toLowerCase()) {
    case 'sha256': return 32;
    case 'sha384': return 48;
    case 'sha512': return 64;
    default: throw new Error(`unknown hash: ${name}`);
  }
}

function hashEmpty(name) {
  return crypto.createHash(name).digest();
}

function transcriptHash(name, ...chunks) {
  const h = crypto.createHash(name);
  for (const c of chunks) h.update(c);
  return h.digest();
}

module.exports = {
  hkdfExtract,
  hkdfExpand,
  hkdfExpandLabel,
  deriveSecret,
  buildHkdfLabel,
  hashLen,
  hashEmpty,
  transcriptHash,
};
