'use strict';
// Cipher Suite Metadata — RFC 8446 §B.4 + RFC 9147 §4.2.3.
//
// TLS 1.3 suite formatı: TLS_<AEAD>_<HASH>, tek bir PRF hash'ı (HKDF), tek AEAD.
// Her suite için runtime'da ihtiyaç duyulan tüm ölçüler burada tek yerde.
//
// DTLS 1.3 record protection aynı AEAD/IV türetmesini kullanır. Ek olarak
// "sequence number encryption" (§4.2.3) için AES-ECB veya ChaCha20 mask üreticisi
// gerekir — bu tabloda `sn_cipher` alanı bunu belirtir.

const { CIPHER_SUITE } = require('../constants.js');

// Ortak AEAD boyları: TLS 1.3'te iv uzunluğu daima 12 (RFC 8446 §5.3),
// tag uzunluğu AES-GCM için 16, CCM_8 için 8, ChaCha20-Poly1305 için 16.

const SUITES = Object.freeze({
  [CIPHER_SUITE.TLS_AES_128_GCM_SHA256]: Object.freeze({
    id:       CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
    name:     'TLS_AES_128_GCM_SHA256',
    hash:     'sha256',
    hashLen:  32,
    aead:     'aes-128-gcm',
    keyLen:   16,
    ivLen:    12,
    tagLen:   16,
    sn_cipher: 'aes-128-ecb',   // RFC 9147 §4.2.3 — sn_key ile ilk 16 byte CT'den mask
    sn_keyLen: 16,
  }),
  [CIPHER_SUITE.TLS_AES_256_GCM_SHA384]: Object.freeze({
    id:       CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
    name:     'TLS_AES_256_GCM_SHA384',
    hash:     'sha384',
    hashLen:  48,
    aead:     'aes-256-gcm',
    keyLen:   32,
    ivLen:    12,
    tagLen:   16,
    sn_cipher: 'aes-256-ecb',
    sn_keyLen: 32,
  }),
  [CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256]: Object.freeze({
    id:       CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
    name:     'TLS_CHACHA20_POLY1305_SHA256',
    hash:     'sha256',
    hashLen:  32,
    aead:     'chacha20-poly1305',
    keyLen:   32,
    ivLen:    12,
    tagLen:   16,
    sn_cipher: 'chacha20',      // tek blok 4-byte counter + 12-byte nonce
    sn_keyLen: 32,
  }),
});

// Öncelik sırası: AES-GCM donanımsal hızlandırma varsa neredeyse her zaman daha hızlı,
// yazılımsal ortamlarda ise ChaCha20 çoğu kez galip. Default öncelik donanım varsayımıyla.
const DEFAULT_SERVER_PRIORITY = [
  CIPHER_SUITE.TLS_AES_128_GCM_SHA256,
  CIPHER_SUITE.TLS_AES_256_GCM_SHA384,
  CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256,
];

function getSuite(id) {
  const s = SUITES[id];
  if (!s) throw new Error(`unsupported cipher suite: 0x${id.toString(16)}`);
  return s;
}

function selectSuite(clientList, serverPriority = DEFAULT_SERVER_PRIORITY) {
  const clientSet = new Set(clientList);
  for (const id of serverPriority) {
    if (clientSet.has(id) && SUITES[id]) return SUITES[id];
  }
  return null;
}

module.exports = {
  SUITES,
  DEFAULT_SERVER_PRIORITY,
  getSuite,
  selectSuite,
};
