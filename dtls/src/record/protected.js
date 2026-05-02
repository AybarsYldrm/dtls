'use strict';

const {
  buildAeadNonce,
  buildInnerPlaintext,
  parseInnerPlaintext,
  aeadSeal,
  aeadOpen,
  snMask,
  reconstructSeq,
} = require('../crypto/aead.js');

// ============================================================================
// protectRecord — DTLS 1.3 unified header ile kayıt şifreleme (RFC 9147 §4.3.2)
//
// Header formatı:
//   0b001CSLXX  (C=CID var mı, S=16-bit seq, L=length var mı, XX=epoch-low 2 bit)
// ============================================================================
function protectRecordV2({
  contentType, content, recordSeq, epoch,
  writeKey, writeIv, snKey, aeadAlg, snCipher,
  paddingLen = 0, connectionId = null,
}) {
  const epochLow = epoch & 0b11;
  const cidBuf = connectionId ? Buffer.from(connectionId) : null;
  const cBit = cidBuf ? 1 : 0;
  const sBit = 1; // 16-bit sequence
  const lBit = 1; // Length included
  const firstByte = 0b00100000 | (cBit << 4) | (sBit << 3) | (lBit << 2) | epochLow;

  // Düz (maskelenmemiş) sequence number — AAD için kullanılır
  const seqPlain = Buffer.alloc(2);
  seqPlain.writeUInt16BE(recordSeq & 0xffff, 0);

  const inner = buildInnerPlaintext(contentType, content, paddingLen);

  // RFC 9147 §4.2.3: per-record AEAD nonce uses the 48-bit record sequence
  // number ONLY (left-padded to iv_length, XORed with static IV). Unlike
  // DTLS 1.2, the epoch is NOT part of the nonce — epoch is implicit in the
  // keys (each epoch derives its own key/iv from a different traffic_secret).
  const nonce = buildAeadNonce(writeIv, recordSeq);

  const ctLen = inner.length + 16; // plaintext + AEAD tag
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(ctLen, 0);

  // AAD = firstByte || [CID] || plaintext_seq || length
  const aad = Buffer.concat([
    Buffer.from([firstByte]),
    cidBuf || Buffer.alloc(0),
    seqPlain,
    lenBuf,
  ]);

  const ct = aeadSeal({
    aead: aeadAlg, key: writeKey, nonce, aad, plaintext: inner, tagLen: 16,
  });

  // Sequence Number Encryption (RFC 9147 §4.3.3):
  // mask = SN-Cipher(snKey, ciphertext[0..15])
  // encrypted_seq = plaintext_seq XOR mask[0..snLen-1]
  const mask = snMask(snCipher, snKey, ct);
  const seqEnc = Buffer.from(seqPlain);
  seqEnc[0] ^= mask[0];
  seqEnc[1] ^= mask[1];

  return Buffer.concat([
    Buffer.from([firstByte]),
    cidBuf || Buffer.alloc(0),
    seqEnc,   // maskelenmiş seq
    lenBuf,
    ct,
  ]);
}

// ============================================================================
// unprotectRecord — DTLS 1.3 unified header ile kayıt şifre çözme
//
// Akış (RFC 9147 §4.3.3):
//   1. Header'ı parse et, şifreli seq'i oku
//   2. mask = SN-Cipher(snKey, ciphertext[0..15])
//   3. plaintext_seq = encrypted_seq XOR mask
//   4. full_seq = reconstructSeq(lastSeq, plaintext_seq, snBits)
//   5. AAD = firstByte || [CID] || plaintext_seq || [length]
//   6. nonce = IV XOR (epoch << 48 | full_seq)
//   7. inner = AEAD-Open(key, nonce, AAD, ciphertext)
//   8. {contentType, content} = parseInnerPlaintext(inner)
// ============================================================================
function unprotectRecord({
  record, offset = 0,
  readKey, readIv, snKey, aeadAlg, snCipher,
  lastSeq = 0, epoch = 0, cidLength = 0,
}) {
  const firstByte = record.readUInt8(offset);

  // Unified header magic: top 3 bits = 0b001
  if ((firstByte & 0b11100000) !== 0b00100000) return null;

  const cBit  = (firstByte >> 4) & 1;
  const sBit  = (firstByte >> 3) & 1;
  const lBit  = (firstByte >> 2) & 1;
  const snLen = sBit ? 2 : 1;
  const snBits = sBit ? 16 : 8;

  let o = offset + 1;

  // CID (opsiyonel)
  let cid = null;
  if (cBit) {
    cid = Buffer.from(record.slice(o, o + cidLength));
    o += cidLength;
  }

  // Şifreli (maskelenmiş) sequence number
  const seqEnc = Buffer.from(record.slice(o, o + snLen));
  o += snLen;

  // Uzunluk alanı
  let ctLen;
  if (lBit) {
    ctLen = record.readUInt16BE(o);
    o += 2;
  } else {
    ctLen = record.length - o;
  }

  const ct = Buffer.from(record.slice(o, o + ctLen));
  const totalConsumed = (o - offset) + ctLen;

  // --- Adım 2: SN maskesini ciphertext'in ilk bloğundan üret ---
  const mask = snMask(snCipher, snKey, ct);

  // --- Adım 3: Seq'i unmask et ---
  const seqDec = Buffer.from(seqEnc);
  seqDec[0] ^= mask[0];
  if (sBit) seqDec[1] ^= mask[1];

  // --- Adım 4: 48-bit tam sequence numarasını yeniden oluştur ---
  const truncated = sBit ? seqDec.readUInt16BE(0) : seqDec.readUInt8(0);
  const fullSeq = reconstructSeq(lastSeq, truncated, snBits);

  // --- Adım 5: AAD = firstByte || [CID] || plaintext_seq || [length] ---
  const aadParts = [Buffer.from([firstByte])];
  if (cid) aadParts.push(cid);
  aadParts.push(seqDec); // düz seq (unmask edilmiş)
  if (lBit) {
    const lb = Buffer.alloc(2);
    lb.writeUInt16BE(ctLen, 0);
    aadParts.push(lb);
  }
  const aad = Buffer.concat(aadParts);

  // --- Adım 6: Nonce = IV XOR pad12(fullSeq) ---
  // RFC 9147 §4.2.3: only the 48-bit record sequence number goes into the
  // AEAD nonce — the epoch is NOT included (it is implicit in the key/iv,
  // selected per epoch). This is THE difference from DTLS 1.2.
  const nonce = buildAeadNonce(readIv, fullSeq);

  // --- Adım 7-8: AEAD aç, inner plaintext'i parse et ---
  let inner;
  try {
    inner = aeadOpen({
      aead: aeadAlg,
      key: readKey,
      nonce,
      aad,
      ciphertextWithTag: ct,
      tagLen: 16,
    });
  } catch (e) {
    throw new Error(`unprotectRecord AEAD failed (epoch=${epoch} seq=${fullSeq}): ${e.message}`);
  }

  const { contentType, content } = parseInnerPlaintext(inner);

  return {
    contentType,
    content,
    epochLow: firstByte & 0b11,
    fullSeq,
    seqTruncated: truncated,
    bytesConsumed: totalConsumed,
    cid,
  };
}

module.exports = { protectRecord: protectRecordV2, unprotectRecord };