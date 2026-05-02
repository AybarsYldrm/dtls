'use strict';
const crypto = require('node:crypto');

function buildAeadNonce(writeIv, recordSeq) {
  const nonce = Buffer.from(writeIv); // IV'yi güvenlice kopyala
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(BigInt(recordSeq), 0);
  const off = nonce.length - 8;
  for (let i = 0; i < 8; i++) nonce[off + i] ^= seqBuf[i];
  return nonce;
}

function buildInnerPlaintext(contentType, content, paddingLen = 0) {
  const pad = paddingLen > 0 ? Buffer.alloc(paddingLen, 0) : Buffer.alloc(0);
  return Buffer.concat([content, Buffer.from([contentType]), pad]);
}

function parseInnerPlaintext(inner) {
  let i = inner.length - 1;
  while (i >= 0 && inner[i] === 0) i--;
  if (i < 0) throw new Error('inner plaintext all zeros — invalid');
  const contentType = inner[i];
  return { contentType, content: inner.slice(0, i) };
}

function aeadSeal({ aead, key, nonce, aad, plaintext, tagLen = 16 }) {
  const cipher = crypto.createCipheriv(aead, key, nonce, { authTagLength: tagLen });
  if (aad && aad.length > 0) {
    cipher.setAAD(aad); // Node.js'te plaintextLength parametresini kaldırdık, bazen GCM'yi bozar
  }
  const ct = cipher.update(plaintext);
  const final = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([ct, final, tag]);
}

function aeadOpen({ aead, key, nonce, aad, ciphertextWithTag, tagLen = 16 }) {
  if (ciphertextWithTag.length < tagLen) throw new Error('ciphertext shorter than tag');
  
  const splitAt = ciphertextWithTag.length - tagLen;
  
  // FORCE DEEP COPIES for Node.js native crypto bindings
  const ct = Buffer.from(ciphertextWithTag.slice(0, splitAt));
  const tag = Buffer.from(ciphertextWithTag.slice(splitAt));
  const safeAad = (aad && aad.length > 0) ? Buffer.from(aad) : Buffer.alloc(0);
  const safeNonce = Buffer.from(nonce);
  const safeKey = Buffer.from(key);

  const decipher = crypto.createDecipheriv(aead, safeKey, safeNonce, { authTagLength: tagLen });
  
  if (safeAad.length > 0) {
    decipher.setAAD(safeAad);
  }
  
  decipher.setAuthTag(tag);
  
  try {
    const pt = decipher.update(ct);
    const final = decipher.final();
    return Buffer.concat([pt, final]);
  } catch (e) {
    throw new Error(`AEAD auth failed: ${e.message}`);
  }
}

function snMask(snCipher, snKey, ciphertext) {
  if (snCipher === 'aes-128-ecb' || snCipher === 'aes-256-ecb') {
    // Node.js'te ECB modu için IV olarak 'null' değil, boş string ('') kullanmalıyız!
    const c = crypto.createCipheriv(snCipher, snKey, '');
    c.setAutoPadding(false); 
    
    // Şifreli metinden (ciphertext) kesinlikle ilk 16 byte'ı almalıyız. 
    // Eğer 16 byte'tan kısaysa, sonunu sıfırlarla doldurmalıyız.
    let block = ciphertext.slice(0, 16);
    if (block.length < 16) {
      const padded = Buffer.alloc(16, 0);
      block.copy(padded);
      block = padded;
    }
    
    return c.update(block);
  }
  if (snCipher === 'chacha20') {
    const counter = ciphertext.slice(0, 4);
    const nonce12 = ciphertext.slice(4, 16);
    const iv = Buffer.concat([counter, nonce12]);
    const c = crypto.createCipheriv('chacha20', snKey, iv);
    return c.update(Buffer.alloc(16, 0));
  }
  throw new Error(`unknown sn cipher: ${snCipher}`);
}

function reconstructSeq(lastKnownFullSeq, truncated, snBits) {
  const mask = (1 << snBits) - 1;
  const low = truncated & mask;
  const lastLow = lastKnownFullSeq & mask;
  const lastHigh = lastKnownFullSeq - lastLow;
  const window = 1 << snBits;

  const candidates = [
    lastHigh - window + low,
    lastHigh + low,
    lastHigh + window + low,
  ];
  let best = candidates.filter(x => x >= 0)[0];
  let bestDist = Math.abs(best - lastKnownFullSeq);
  for (const c of candidates) {
    if (c < 0) continue;
    const d = Math.abs(c - lastKnownFullSeq);
    if (d < bestDist) { best = c; bestDist = d; }
  }
  return best;
}

module.exports = {
  buildAeadNonce, buildInnerPlaintext, parseInnerPlaintext,
  aeadSeal, aeadOpen, snMask, reconstructSeq,
};