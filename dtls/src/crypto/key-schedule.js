'use strict';
// TLS 1.3 Key Schedule — RFC 8446 §7.1 (DTLS 1.3 aynı şemayı kullanır, RFC 9147 §5.9).
//
// Ağaç:
//
//             0  (salt)
//             |
//             v
//   PSK ->  HKDF-Extract = Early Secret
//             |
//             +---> Derive-Secret(., "ext binder" | "res binder", "") = binder_key
//             +---> Derive-Secret(., "c e traffic", ClientHello)      = client_early_traffic_secret
//             +---> Derive-Secret(., "e exp master", ClientHello)     = early_exporter_master_secret
//             v
//        Derive-Secret(., "derived", "")
//             |
//             v
//   (EC)DHE -> HKDF-Extract = Handshake Secret
//             |
//             +---> Derive-Secret(., "c hs traffic", CH..SH) = client_handshake_traffic_secret
//             +---> Derive-Secret(., "s hs traffic", CH..SH) = server_handshake_traffic_secret
//             v
//        Derive-Secret(., "derived", "")
//             |
//             v
//   0      -> HKDF-Extract = Master Secret
//             |
//             +---> Derive-Secret(., "c ap traffic", CH..SF)  = client_application_traffic_secret_0
//             +---> Derive-Secret(., "s ap traffic", CH..SF)  = server_application_traffic_secret_0
//             +---> Derive-Secret(., "exp master", CH..SF)    = exporter_master_secret
//             +---> Derive-Secret(., "res master", CH..CF)    = resumption_master_secret
//
// Traffic secret -> traffic key/iv/sn_key:
//   key    = HKDF-Expand-Label(traffic_secret, "key", "", key_length)
//   iv     = HKDF-Expand-Label(traffic_secret, "iv",  "", iv_length)
//   sn_key = HKDF-Expand-Label(traffic_secret, "sn",  "", sn_key_length) [RFC 9147 §4.2.3]
//
// Finished MAC için:
//   finished_key = HKDF-Expand-Label(Base-Key, "finished", "", Hash.length)
//
// KeyUpdate:
//   application_traffic_secret_N+1 =
//     HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)

const {
  hkdfExtract, hkdfExpandLabel, deriveSecret, hashEmpty,
  TLS13_LABEL_PREFIX, DTLS13_LABEL_PREFIX,
} = require('./hkdf.js');

// RFC 9147 §5.9 / interop reality: in DTLS 1.3, the AEAD key material
// (key, iv, sn, finished, traffic upd) is derived with the "dtls13" HKDF
// prefix in both wolfSSL and OpenSSL. Traffic secrets via Derive-Secret
// keep "tls13 " in those implementations as well.
const KM_PREFIX = DTLS13_LABEL_PREFIX;

// --------------------------------------------------------------------------
// Early Secret
// --------------------------------------------------------------------------
function earlySecret(hash, psk = null) {
  const ikm = psk || Buffer.alloc(require('./hkdf.js').hashLen(hash), 0);
  const salt = Buffer.alloc(0); // HKDF-Extract(0, PSK) — salt 0, HMAC'da zero-filled olur
  return hkdfExtract(hash, salt, ikm);
}

// Derive-Secret(Early Secret, "derived", "") — Handshake Secret için salt
function derivedFromEarly(hash, earlyS) {
  return deriveSecret(hash, earlyS, 'derived', hashEmpty(hash));
}

// --------------------------------------------------------------------------
// Handshake Secret
// --------------------------------------------------------------------------
function handshakeSecret(hash, earlyS, ecdheSharedSecret) {
  const salt = derivedFromEarly(hash, earlyS);
  return hkdfExtract(hash, salt, ecdheSharedSecret);
}

function clientHandshakeTrafficSecret(hash, hsS, transcriptCH_SH) {
  return deriveSecret(hash, hsS, 'c hs traffic', transcriptCH_SH);
}
function serverHandshakeTrafficSecret(hash, hsS, transcriptCH_SH) {
  return deriveSecret(hash, hsS, 's hs traffic', transcriptCH_SH);
}

function derivedFromHandshake(hash, hsS) {
  return deriveSecret(hash, hsS, 'derived', hashEmpty(hash));
}

// --------------------------------------------------------------------------
// Master Secret
// --------------------------------------------------------------------------
function masterSecret(hash, hsS) {
  const salt = derivedFromHandshake(hash, hsS);
  const ikm = Buffer.alloc(require('./hkdf.js').hashLen(hash), 0);
  return hkdfExtract(hash, salt, ikm);
}

function clientApplicationTrafficSecret(hash, masterS, transcriptCH_SF) {
  return deriveSecret(hash, masterS, 'c ap traffic', transcriptCH_SF);
}
function serverApplicationTrafficSecret(hash, masterS, transcriptCH_SF) {
  return deriveSecret(hash, masterS, 's ap traffic', transcriptCH_SF);
}
function exporterMasterSecret(hash, masterS, transcriptCH_SF) {
  return deriveSecret(hash, masterS, 'exp master', transcriptCH_SF);
}
function resumptionMasterSecret(hash, masterS, transcriptCH_CF) {
  return deriveSecret(hash, masterS, 'res master', transcriptCH_CF);
}

// --------------------------------------------------------------------------
// Traffic secret -> key/iv/sn
// --------------------------------------------------------------------------
// trafficKeyIv / snKey / finishedKey / updateTrafficSecret all take an
// optional `prefix` arg so RFC 8448 (TLS 1.3) KAT tests can still call them
// directly with the "tls13 " default. The high-level deriveHandshakeStage /
// deriveApplicationStage helpers pass DTLS13_LABEL_PREFIX so the live DTLS
// 1.3 protocol uses the "dtls13" prefix that wolfSSL/OpenSSL expect.
function trafficKeyIv(hash, trafficSecret, { keyLen, ivLen }, prefix = TLS13_LABEL_PREFIX) {
  return {
    key: hkdfExpandLabel(hash, trafficSecret, 'key', Buffer.alloc(0), keyLen, prefix),
    iv:  hkdfExpandLabel(hash, trafficSecret, 'iv',  Buffer.alloc(0), ivLen, prefix),
  };
}

// RFC 9147 §4.2.3 — sequence number mask anahtarı sadece DTLS 1.3 özgüdür.
function snKey(hash, trafficSecret, snKeyLen, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExpandLabel(hash, trafficSecret, 'sn', Buffer.alloc(0), snKeyLen, prefix);
}

// Finished key
function finishedKey(hash, baseKey, hashLen, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExpandLabel(hash, baseKey, 'finished', Buffer.alloc(0), hashLen, prefix);
}

// KeyUpdate — yeni application traffic secret
function updateTrafficSecret(hash, prevSecret, hashLen, prefix = TLS13_LABEL_PREFIX) {
  return hkdfExpandLabel(hash, prevSecret, 'traffic upd', Buffer.alloc(0), hashLen, prefix);
}

// --------------------------------------------------------------------------
// Yüksek seviyeli yardımcı — server/client ortak: ClientHello..ServerHello transcript
// ile handshake tarafındaki tüm türetmeleri tek seferde yap.
// --------------------------------------------------------------------------
function deriveHandshakeStage({
  suite,          // cipher-suite.js metadata
  sharedSecret,   // ECDHE çıktısı
  transcriptCH_SH, // Transcript-Hash(ClientHello || ServerHello)  (veya HRR dönüşümlü)
  psk = null,
}) {
  const { hash, keyLen, ivLen, sn_keyLen, hashLen: hLen } = suite;

  const early = earlySecret(hash, psk);
  const hs    = handshakeSecret(hash, early, sharedSecret);
  const cHS   = clientHandshakeTrafficSecret(hash, hs, transcriptCH_SH);
  const sHS   = serverHandshakeTrafficSecret(hash, hs, transcriptCH_SH);

  return {
    earlySecret:          early,
    handshakeSecret:      hs,
    clientHandshakeSecret: cHS,
    serverHandshakeSecret: sHS,
    clientHandshake: {
      ...trafficKeyIv(hash, cHS, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, cHS, sn_keyLen, KM_PREFIX),
      finishedKey:  finishedKey(hash, cHS, hLen, KM_PREFIX),
      trafficSecret: cHS,
    },
    serverHandshake: {
      ...trafficKeyIv(hash, sHS, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, sHS, sn_keyLen, KM_PREFIX),
      finishedKey:  finishedKey(hash, sHS, hLen, KM_PREFIX),
      trafficSecret: sHS,
    },
  };
}

function deriveApplicationStage({ suite, handshakeSecret, transcriptCH_SF }) {
  const { hash, keyLen, ivLen, sn_keyLen, hashLen: hLen } = suite;

  const master = masterSecret(hash, handshakeSecret);
  const cAP    = clientApplicationTrafficSecret(hash, master, transcriptCH_SF);
  const sAP    = serverApplicationTrafficSecret(hash, master, transcriptCH_SF);
  const exp    = exporterMasterSecret(hash, master, transcriptCH_SF);

  return {
    masterSecret: master,
    exporterSecret: exp,
    clientApplication: {
      ...trafficKeyIv(hash, cAP, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, cAP, sn_keyLen, KM_PREFIX),
      trafficSecret: cAP,
    },
    serverApplication: {
      ...trafficKeyIv(hash, sAP, { keyLen, ivLen }, KM_PREFIX),
      sn:           snKey(hash, sAP, sn_keyLen, KM_PREFIX),
      trafficSecret: sAP,
    },
  };
}

module.exports = {
  // primitives
  earlySecret, derivedFromEarly,
  handshakeSecret, derivedFromHandshake,
  masterSecret,
  clientHandshakeTrafficSecret, serverHandshakeTrafficSecret,
  clientApplicationTrafficSecret, serverApplicationTrafficSecret,
  exporterMasterSecret, resumptionMasterSecret,
  trafficKeyIv, snKey, finishedKey, updateTrafficSecret,
  // high-level
  deriveHandshakeStage, deriveApplicationStage,
};
