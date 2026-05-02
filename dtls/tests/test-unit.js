'use strict';
// Unit tests — ECDHE, Transcript (HRR dönüşümü), AEAD seal/open, SN encryption.
//
// Bu testler "iç mantığın bütünlüğü" kategorisindedir — external RFC vektörleri değil,
// implementation roundtrip + invariant'ları doğrular.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { NAMED_GROUP, HS_TYPE } = require('../src/constants.js');
const ecdhe = require('../src/crypto/ecdhe.js');
const { Transcript } = require('../src/handshake/transcript.js');
const {
  buildAeadNonce, buildInnerPlaintext, parseInnerPlaintext,
  aeadSeal, aeadOpen,
  encryptSeqNum, decryptSeqNum, reconstructSeq,
} = require('../src/crypto/aead.js');
const { getSuite } = require('../src/crypto/cipher-suite.js');
const { CIPHER_SUITE } = require('../src/constants.js');
const { CookieMinter } = require('../src/handshake/cookie.js');

let failed = 0;
function t(name, fn) {
  try { fn(); console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.error(`  ✗ ${name}\n    ${e.message}\n    ${e.stack}`); }
}

// ============================================================================
console.log('\n[ECDHE]');
// ============================================================================

t('X25519 roundtrip — shared secret eşit', () => {
  const a = ecdhe.generateKeyPair(NAMED_GROUP.X25519);
  const b = ecdhe.generateKeyPair(NAMED_GROUP.X25519);
  assert.equal(a.publicRaw.length, 32);
  assert.equal(b.publicRaw.length, 32);

  const aPeer = ecdhe.importPeerPublic(NAMED_GROUP.X25519, b.publicRaw);
  const bPeer = ecdhe.importPeerPublic(NAMED_GROUP.X25519, a.publicRaw);

  const s1 = ecdhe.computeSharedSecret(a.privateKey, aPeer);
  const s2 = ecdhe.computeSharedSecret(b.privateKey, bPeer);

  assert.deepEqual(s1, s2);
  assert.equal(s1.length, 32);
});

t('X25519 rastgele keypairlerde shared secret eşsiz', () => {
  const a = ecdhe.generateKeyPair(NAMED_GROUP.X25519);
  const b = ecdhe.generateKeyPair(NAMED_GROUP.X25519);
  const c = ecdhe.generateKeyPair(NAMED_GROUP.X25519);

  const ab = ecdhe.computeSharedSecret(a.privateKey, ecdhe.importPeerPublic(NAMED_GROUP.X25519, b.publicRaw));
  const ac = ecdhe.computeSharedSecret(a.privateKey, ecdhe.importPeerPublic(NAMED_GROUP.X25519, c.publicRaw));
  assert.notDeepEqual(ab, ac);
});

t('P-256 roundtrip — uncompressed (0x04) prefix korunuyor', () => {
  const a = ecdhe.generateKeyPair(NAMED_GROUP.SECP256R1);
  const b = ecdhe.generateKeyPair(NAMED_GROUP.SECP256R1);
  assert.equal(a.publicRaw.length, 65);
  assert.equal(a.publicRaw[0], 0x04);
  assert.equal(b.publicRaw.length, 65);

  const aPeer = ecdhe.importPeerPublic(NAMED_GROUP.SECP256R1, b.publicRaw);
  const bPeer = ecdhe.importPeerPublic(NAMED_GROUP.SECP256R1, a.publicRaw);

  const s1 = ecdhe.computeSharedSecret(a.privateKey, aPeer);
  const s2 = ecdhe.computeSharedSecret(b.privateKey, bPeer);
  assert.deepEqual(s1, s2);
  assert.equal(s1.length, 32); // P-256 shared X-coord 32 byte
});

t('P-256 invalid prefix reddediyor', () => {
  const a = ecdhe.generateKeyPair(NAMED_GROUP.SECP256R1);
  const bad = Buffer.concat([Buffer.from([0x03]), a.publicRaw.slice(1)]); // compressed
  assert.throws(() => ecdhe.importPeerPublic(NAMED_GROUP.SECP256R1, bad));
});

// ============================================================================
console.log('\n[Transcript]');
// ============================================================================

t('transcript: DTLS handshake → TLS 4-byte form (RFC 9147 §5.2)', () => {
  const body = Buffer.from('cafebabe', 'hex');
  // Wire'da DTLS 12-byte header, msg_seq/frag_off non-zero
  const m = Buffer.concat([
    Buffer.from([1, 0x00, 0x00, 0x04]),  // type=1, length=4
    Buffer.from([0x00, 0x07]),            // message_seq=7
    Buffer.from([0x00, 0x00, 0x02]),      // frag_off=2
    Buffer.from([0x00, 0x00, 0x02]),      // frag_len=2  (parçalı bile olsa transcript için hepsi at)
    body,
  ]);
  const tx = new Transcript('sha256');
  tx.appendDtls(m);

  // Beklenen: SHA256(type||length||body) — 4-byte TLS handshake header
  const expected = crypto.createHash('sha256')
    .update(Buffer.from('01000004', 'hex'))   // 4-byte TLS header
    .update(body)
    .digest();
  assert.deepEqual(tx.digest(), expected);
});

t('DTLS handshake header message_seq transcript\'te sıfırlanıyor', () => {
  // İki handshake: biri message_seq=0, diğeri =5, ama aynı içerikli.
  const body = Buffer.from('cafebabe', 'hex');
  const hdr0 = Buffer.concat([
    Buffer.from([1]), Buffer.from([0x00, 0x00, 0x04]), // type=1, len=4
    Buffer.from([0x00, 0x00]),                          // message_seq=0
    Buffer.from([0x00, 0x00, 0x00]),                    // frag_off=0
    Buffer.from([0x00, 0x00, 0x04]),                    // frag_len=4
  ]);
  const hdr5 = Buffer.concat([
    Buffer.from([1]), Buffer.from([0x00, 0x00, 0x04]),
    Buffer.from([0x00, 0x05]),                          // message_seq=5
    Buffer.from([0x00, 0x00, 0x02]),                    // frag_off=2 (transcript'te sıfırlanır)
    Buffer.from([0x00, 0x00, 0x02]),                    // frag_len=2 (transcript'te len'e zorlanır)
  ]);
  const m0 = Buffer.concat([hdr0, body]);
  const m5 = Buffer.concat([hdr5, body]);

  const t0 = new Transcript('sha256'); t0.appendDtls(m0);
  const t5 = new Transcript('sha256'); t5.appendDtls(m5);
  assert.deepEqual(t0.digest(), t5.digest());
});

t('HRR transform: message_hash sargısı beklenen formatı üretiyor', () => {
  // Oluştur: transcript(CH1) ham
  const ch1 = buildFakeHandshake(HS_TYPE.CLIENT_HELLO, Buffer.from('deadbeef', 'hex'));
  const tA = new Transcript('sha256');
  tA.appendDtls(ch1);
  const digestCH1 = tA.digest(); // = SHA-256(normalized(ch1))

  // HRR transform
  tA.replaceWithMessageHash();

  // Ayrı bir instance üzerinden: message_hash pseudo mesajını manuel kurup karşılaştır
  const tB = new Transcript('sha256');
  // prefix = [254, 00, 00, 32] || digestCH1
  const prefix = Buffer.concat([
    Buffer.from([HS_TYPE.MESSAGE_HASH, 0, 0, 32]),
    digestCH1,
  ]);
  // appendRaw ile manuel ekleriz
  tB.appendRaw(prefix);

  assert.deepEqual(tA.digest(), tB.digest());
});

t('HRR transform: CH1||HRR||CH2 akışı deterministik', () => {
  const ch1 = buildFakeHandshake(HS_TYPE.CLIENT_HELLO, Buffer.from('aa', 'hex'));
  const hrr = buildFakeHandshake(HS_TYPE.SERVER_HELLO, Buffer.from('bb', 'hex'));
  const ch2 = buildFakeHandshake(HS_TYPE.CLIENT_HELLO, Buffer.from('cc', 'hex'));

  const tA = new Transcript('sha256');
  tA.appendDtls(ch1);
  tA.replaceWithMessageHash();
  tA.appendDtls(hrr);
  tA.appendDtls(ch2);

  const tB = new Transcript('sha256');
  tB.appendDtls(ch1);
  tB.replaceWithMessageHash();
  tB.appendDtls(hrr);
  tB.appendDtls(ch2);

  assert.deepEqual(tA.digest(), tB.digest());
});

function buildFakeHandshake(msgType, body) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt8(msgType, 0);
  hdr.writeUInt8(0, 1); hdr.writeUInt16BE(body.length, 2);  // length u24
  hdr.writeUInt16BE(0, 4);                                  // message_seq
  hdr.writeUInt8(0, 6); hdr.writeUInt16BE(0, 7);             // frag_off u24
  hdr.writeUInt8(0, 9); hdr.writeUInt16BE(body.length, 10);  // frag_len u24
  return Buffer.concat([hdr, body]);
}

// ============================================================================
console.log('\n[AEAD]');
// ============================================================================

t('AES-128-GCM seal/open roundtrip', () => {
  const suite = getSuite(CIPHER_SUITE.TLS_AES_128_GCM_SHA256);
  const key = crypto.randomBytes(suite.keyLen);
  const iv  = crypto.randomBytes(suite.ivLen);
  const nonce = buildAeadNonce(iv, 42n === 42n ? 42 : 0); // seq 42
  const aad = Buffer.from('2f000008', 'hex'); // varsayımsal DTLS hdr
  const pt  = Buffer.from('hello world!');

  const ct = aeadSeal({ aead: suite.aead, key, nonce, aad, plaintext: pt, tagLen: suite.tagLen });
  const openNonce = buildAeadNonce(iv, 42);
  const out = aeadOpen({ aead: suite.aead, key, nonce: openNonce, aad, ciphertextWithTag: ct, tagLen: suite.tagLen });
  assert.deepEqual(out, pt);
  assert.equal(ct.length, pt.length + suite.tagLen);
});

t('AEAD tampered ciphertext fail', () => {
  const suite = getSuite(CIPHER_SUITE.TLS_AES_128_GCM_SHA256);
  const key = crypto.randomBytes(suite.keyLen);
  const iv  = crypto.randomBytes(suite.ivLen);
  const nonce = buildAeadNonce(iv, 1);
  const aad = Buffer.alloc(0);
  const pt  = Buffer.from('secret');
  const ct = aeadSeal({ aead: suite.aead, key, nonce, aad, plaintext: pt });
  ct[0] ^= 0x01; // flip a bit
  assert.throws(() =>
    aeadOpen({ aead: suite.aead, key, nonce, aad, ciphertextWithTag: ct }),
    /AEAD auth failed/
  );
});

t('AEAD AAD mismatch fail', () => {
  const suite = getSuite(CIPHER_SUITE.TLS_AES_128_GCM_SHA256);
  const key = crypto.randomBytes(suite.keyLen);
  const iv  = crypto.randomBytes(suite.ivLen);
  const nonce = buildAeadNonce(iv, 0);
  const pt = Buffer.from('x');
  const ct = aeadSeal({ aead: suite.aead, key, nonce, aad: Buffer.from('AAA'), plaintext: pt });
  assert.throws(() =>
    aeadOpen({ aead: suite.aead, key, nonce, aad: Buffer.from('BBB'), ciphertextWithTag: ct })
  );
});

t('ChaCha20-Poly1305 seal/open roundtrip', () => {
  const suite = getSuite(CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256);
  const key = crypto.randomBytes(suite.keyLen);
  const iv  = crypto.randomBytes(suite.ivLen);
  const nonce = buildAeadNonce(iv, 7);
  const aad = Buffer.from('aabbcc', 'hex');
  const pt  = Buffer.from('chacha is fast in software');

  const ct = aeadSeal({ aead: suite.aead, key, nonce, aad, plaintext: pt });
  const out = aeadOpen({ aead: suite.aead, key, nonce, aad, ciphertextWithTag: ct });
  assert.deepEqual(out, pt);
});

t('buildInnerPlaintext + parseInnerPlaintext roundtrip (padding ile)', () => {
  const inner = buildInnerPlaintext(22 /* HANDSHAKE */, Buffer.from('abcd', 'hex'), 5);
  // inner = [ab cd 16 00 00 00 00 00]
  assert.equal(inner.length, 2 + 1 + 5);
  const parsed = parseInnerPlaintext(inner);
  assert.equal(parsed.contentType, 22);
  assert.deepEqual(parsed.content, Buffer.from('abcd', 'hex'));
});



t('Nonce construction — seq XOR right-aligned', () => {
  const iv = Buffer.from('000102030405060708090a0b', 'hex');
  const n0 = buildAeadNonce(iv, 0);
  assert.deepEqual(n0, iv); // seq=0 XOR hiçbir şey değiştirmez
  const n1 = buildAeadNonce(iv, 1);
  // Son byte XOR 1
  const expected = Buffer.from(iv); expected[11] ^= 1;
  assert.deepEqual(n1, expected);
});

// ============================================================================
console.log('\n[SN encryption]');
// ============================================================================

t('AES-ECB SN encrypt/decrypt simetrik', () => {
  const snKey = crypto.randomBytes(16);
  const ciphertext = crypto.randomBytes(32);
  const sn = Buffer.from([0x12, 0x34]);
  const enc = encryptSeqNum('aes-128-ecb', snKey, ciphertext, sn);
  const dec = decryptSeqNum('aes-128-ecb', snKey, ciphertext, enc);
  assert.deepEqual(dec, sn);
  assert.notDeepEqual(enc, sn);
});

t('ChaCha20 SN encrypt/decrypt simetrik', () => {
  const snKey = crypto.randomBytes(32);
  const ciphertext = crypto.randomBytes(32);
  const sn = Buffer.from([0xab]);
  const enc = encryptSeqNum('chacha20', snKey, ciphertext, sn);
  const dec = decryptSeqNum('chacha20', snKey, ciphertext, enc);
  assert.deepEqual(dec, sn);
});

t('SN ciphertext 16 byte altı reddediyor', () => {
  const snKey = crypto.randomBytes(16);
  const short = crypto.randomBytes(15);
  assert.throws(() => encryptSeqNum('aes-128-ecb', snKey, short, Buffer.from([0])));
});

t('reconstructSeq — basit monotonic', () => {
  assert.equal(reconstructSeq(5, 6, 8), 6);
  assert.equal(reconstructSeq(100, 255, 8), 255);
  // 8-bit wrap: son bilinen 250, gelen truncated=3 → 259 beklenir
  assert.equal(reconstructSeq(250, 3, 8), 259);
});

// ============================================================================
console.log('\n[Cookie]');
// ============================================================================

t('Cookie mint+verify OK', () => {
  const m = new CookieMinter();
  const peer = { address: '203.0.113.1', port: 55555 };
  const chHash = crypto.randomBytes(32);
  const c = m.mint(peer, chHash);
  const r = m.verify(c, peer, chHash);
  assert.equal(r.ok, true);
});

t('Cookie peer değişirse fail', () => {
  const m = new CookieMinter();
  const chHash = crypto.randomBytes(32);
  const c = m.mint({ address: '10.0.0.1', port: 1000 }, chHash);
  const r = m.verify(c, { address: '10.0.0.2', port: 1000 }, chHash);
  assert.equal(r.ok, false);
});

t('Cookie CH hash değişirse fail', () => {
  const m = new CookieMinter();
  const peer = { address: '10.0.0.1', port: 1000 };
  const c = m.mint(peer, crypto.randomBytes(32));
  const r = m.verify(c, peer, crypto.randomBytes(32));
  assert.equal(r.ok, false);
});

t('Cookie tahrip MAC fail', () => {
  const m = new CookieMinter();
  const peer = { address: '10.0.0.1', port: 1000 };
  const h = crypto.randomBytes(32);
  const c = m.mint(peer, h);
  c[c.length - 1] ^= 1;
  const r = m.verify(c, peer, h);
  assert.equal(r.ok, false);
});

// ============================================================================
console.log(`\nResult: ${failed === 0 ? 'ALL PASS' : `${failed} FAILED`}`);
process.exit(failed === 0 ? 0 : 1);
