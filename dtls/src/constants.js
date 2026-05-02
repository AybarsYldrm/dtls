'use strict';
// DTLS 1.3 Protocol Constants — RFC 9147 + RFC 8446.
// Her sabit RFC bölümüyle ilişkilendirildi; değiştirmek ≈ wire-format kırılması demektir.

// ===== Protocol Versions =====
// DTLS sürüm encoding'i TLS'in 1's-complement olmayan, historical bir mapping:
const VERSION = Object.freeze({
  DTLS_1_0: 0xfeff,
  DTLS_1_2: 0xfefd,
  DTLS_1_3: 0xfefc, // RFC 9147 §5.3
  TLS_1_2:  0x0303, // legacy_version field'larında görülür
  TLS_1_3:  0x0304, // TLS 1.3 (DTLS'de supported_versions değil, TLS'de)
});

// ===== Record Content Type (RFC 9147 §4 + RFC 8446 §5.1) =====
const CONTENT_TYPE = Object.freeze({
  INVALID:             0,
  CHANGE_CIPHER_SPEC: 20, // DTLS 1.3'te middlebox-compat amacıyla izinli, yoksayılır
  ALERT:              21,
  HANDSHAKE:          22,
  APPLICATION_DATA:   23,
  HEARTBEAT:          24, // RFC 6520
  TLS12_CID:          25, // RFC 9146 (legacy)
  ACK:                26, // RFC 9147 §7
});

// ===== Handshake Message Types (RFC 8446 §4) =====
const HS_TYPE = Object.freeze({
  CLIENT_HELLO:         1,
  SERVER_HELLO:         2,
  NEW_SESSION_TICKET:   4,
  END_OF_EARLY_DATA:    5,
  ENCRYPTED_EXTENSIONS: 8,
  REQUEST_CONNECTION_ID: 9,  // RFC 9146
  NEW_CONNECTION_ID:    10,  // RFC 9146
  CERTIFICATE:          11,
  CERTIFICATE_REQUEST:  13,
  CERTIFICATE_VERIFY:   15,
  FINISHED:             20,
  KEY_UPDATE:           24,
  MESSAGE_HASH:        254,
});

// HelloRetryRequest: ServerHello formatında fakat sabit "magic" random ile.
// RFC 8446 §4.1.3 — SHA-256("HelloRetryRequest") değil, sabit vektör:
const HRR_RANDOM = Buffer.from(
  'CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C',
  'hex',
);

// ===== Cipher Suites (TLS 1.3, RFC 8446 §B.4) =====
const CIPHER_SUITE = Object.freeze({
  TLS_AES_128_GCM_SHA256:       0x1301,
  TLS_AES_256_GCM_SHA384:       0x1302,
  TLS_CHACHA20_POLY1305_SHA256: 0x1303,
  TLS_AES_128_CCM_SHA256:       0x1304,
  TLS_AES_128_CCM_8_SHA256:     0x1305,
});

// ===== Extension Types (RFC 8446 §4.2 + çeşitli ek RFC'ler) =====
const EXT_TYPE = Object.freeze({
  SERVER_NAME:                     0, // RFC 6066
  MAX_FRAGMENT_LENGTH:             1,
  STATUS_REQUEST:                  5,
  SUPPORTED_GROUPS:               10, // RFC 8422, 7919
  SIGNATURE_ALGORITHMS:           13,
  USE_SRTP:                       14, // RFC 5764
  HEARTBEAT:                      15, // RFC 6520
  ALPN:                           16, // RFC 7301
  SIGNED_CERTIFICATE_TIMESTAMP:   18,
  PADDING:                        21,
  PRE_SHARED_KEY:                 41,
  EARLY_DATA:                     42,
  SUPPORTED_VERSIONS:             43,
  COOKIE:                         44,
  PSK_KEY_EXCHANGE_MODES:         45,
  CERTIFICATE_AUTHORITIES:        47,
  OID_FILTERS:                    48,
  POST_HANDSHAKE_AUTH:            49,
  SIGNATURE_ALGORITHMS_CERT:      50,
  KEY_SHARE:                      51,
  CONNECTION_ID:                  54, // RFC 9146
});

// ===== Named Groups (RFC 8446 §4.2.7) =====
const NAMED_GROUP = Object.freeze({
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  SECP521R1: 0x0019,
  X25519:    0x001d,
  X448:      0x001e,
  FFDHE2048: 0x0100,
  FFDHE3072: 0x0101,
});

// ===== Signature Schemes (RFC 8446 §4.2.3) =====
const SIG_SCHEME = Object.freeze({
  RSA_PKCS1_SHA256:       0x0401, // cert-only
  RSA_PKCS1_SHA384:       0x0501,
  RSA_PKCS1_SHA512:       0x0601,
  ECDSA_SECP256R1_SHA256: 0x0403,
  ECDSA_SECP384R1_SHA384: 0x0503,
  ECDSA_SECP521R1_SHA512: 0x0603,
  RSA_PSS_RSAE_SHA256:    0x0804,
  RSA_PSS_RSAE_SHA384:    0x0805,
  RSA_PSS_RSAE_SHA512:    0x0806,
  ED25519:                0x0807,
  ED448:                  0x0808,
  RSA_PSS_PSS_SHA256:     0x0809,
  RSA_PSS_PSS_SHA384:     0x080a,
  RSA_PSS_PSS_SHA512:     0x080b,
});

// ===== Alerts (RFC 8446 §6) =====
const ALERT_LEVEL = Object.freeze({ WARNING: 1, FATAL: 2 });
const ALERT_DESC  = Object.freeze({
  CLOSE_NOTIFY:             0,
  UNEXPECTED_MESSAGE:      10,
  BAD_RECORD_MAC:          20,
  RECORD_OVERFLOW:         22,
  HANDSHAKE_FAILURE:       40,
  BAD_CERTIFICATE:         42,
  UNSUPPORTED_CERTIFICATE: 43,
  CERTIFICATE_REVOKED:     44,
  CERTIFICATE_EXPIRED:     45,
  CERTIFICATE_UNKNOWN:     46,
  ILLEGAL_PARAMETER:       47,
  UNKNOWN_CA:              48,
  ACCESS_DENIED:           49,
  DECODE_ERROR:            50,
  DECRYPT_ERROR:           51,
  PROTOCOL_VERSION:        70,
  INSUFFICIENT_SECURITY:   71,
  INTERNAL_ERROR:          80,
  INAPPROPRIATE_FALLBACK:  86,
  USER_CANCELED:           90,
  MISSING_EXTENSION:      109,
  UNSUPPORTED_EXTENSION:  110,
  UNRECOGNIZED_NAME:      112,
  BAD_CERTIFICATE_STATUS: 113,
  UNKNOWN_PSK_IDENTITY:   115,
  CERTIFICATE_REQUIRED:   116,
  NO_APPLICATION_PROTOCOL: 120,
});

// ===== Epoch Semantics (RFC 9147 §6.1) =====
// Epoch her key-change'te 1 artar. Başlangıç 0 (plaintext), 1=early_data, 2=handshake,
// 3=app, 3+N=KeyUpdate. Record'un unified header'ında yalnızca low 2-bit taşınır.
const EPOCH = Object.freeze({
  INITIAL:     0,
  EARLY_DATA:  1,
  HANDSHAKE:   2,
  APPLICATION: 3,
});

// Log için ters eşleştirme — her düşük-seviye parse çıktısında "HANDSHAKE(22)" görmek için.
function reverseLookup(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[v] = k;
  return out;
}
const NAMES = Object.freeze({
  CONTENT_TYPE: reverseLookup(CONTENT_TYPE),
  HS_TYPE:      reverseLookup(HS_TYPE),
  CIPHER_SUITE: reverseLookup(CIPHER_SUITE),
  EXT_TYPE:     reverseLookup(EXT_TYPE),
  NAMED_GROUP:  reverseLookup(NAMED_GROUP),
  SIG_SCHEME:   reverseLookup(SIG_SCHEME),
  ALERT_LEVEL:  reverseLookup(ALERT_LEVEL),
  ALERT_DESC:   reverseLookup(ALERT_DESC),
  VERSION:      reverseLookup(VERSION),
});

module.exports = {
  VERSION, CONTENT_TYPE, HS_TYPE, HRR_RANDOM,
  CIPHER_SUITE, EXT_TYPE, NAMED_GROUP, SIG_SCHEME,
  ALERT_LEVEL, ALERT_DESC, EPOCH, NAMES,
};
