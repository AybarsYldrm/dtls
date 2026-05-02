# dtls13-node

Pure Node.js DTLS 1.3 (RFC 9147) implementasyonu. **Zero external dependencies** — sadece
Node built-in modülleri (`node:crypto`, `node:dgram`, `node:net`, `node:events`).

> Node.js'in yerleşik `tls` modülü DTLS desteklemez — yalnızca TCP/TLS. Bu proje
> DTLS 1.3'ü record layer + handshake + AEAD + key schedule seviyesinde sıfırdan
> inşa eder.

## Durum

| Faz | Kapsam | Durum |
|---|---|---|
| 1 | Record layer + handshake framing + ClientHello/ServerHello encode/parse | ✅ tamam |
| 2 | HKDF + key schedule + ECDHE + HRR/cookie + handshake key türetme | ✅ tamam |
| 3 | AEAD record protection + EE/Cert/CertVerify/Finished + fragment reassembly + ACK | ⏳ sıradaki |
| 4 | Replay window + KeyUpdate + CID (RFC 9146) + rate limiting + OpenSSL interop | 🔜 planlandı |

Bu durum itibarıyla **handshake'in gizlilik olmayan kısmı tam çalışıyor**: client
ve server bir HelloRetryRequest + cookie + ECDHE akışı üzerinden aynı handshake
traffic secret'lerini türetiyor. Bu sırada hiçbir UDP paketi hâlâ AEAD ile
şifrelenmiyor — o Phase 3'te.

## Doğrulama

```bash
npm run smoke        # 13 modül yüklenir
npm run selftest     # Phase 1 record/handshake roundtrip
npm test             # KAT + unit + e2e (toplam 54 test)
```

- **`test:kat`** — RFC 5869 (HKDF) + RFC 8448 §3 (TLS 1.3 key schedule) bilinen-cevap
  vektörleri. 22/22 geçer. Key schedule'un TLS 1.3 resmi referans çıktısıyla bire-bir
  uyumlu olduğunu kanıtlar.
- **`test:unit`** — ECDHE (X25519 + P-256), transcript (HRR message_hash dönüşümü
  dahil), AEAD seal/open (AES-GCM + ChaCha20-Poly1305), sequence number encryption
  (AES-ECB + ChaCha20), cookie mint/verify. 21/21 geçer.
- **`test:e2e`** — Aynı process'te gerçek UDP loopback üzerinden client↔server
  Phase 2 handshake. Her iki tarafın aynı shared secret, aynı transcript hash ve
  aynı tüm türetilmiş handshake key/iv/sn değerlerini ürettiğini 11 kriterde
  karşılaştırır.

## Dizin yapısı

```
dtls13-node/
├── server.js                   # Phase 2 server (HRR + cookie + SH + key derivation)
├── client.js                   # Phase 2 client (HRR handle + CH2 + ECDHE + key derivation)
├── selftest.js                 # Phase 1 encode/parse roundtrip
├── src/
│   ├── constants.js            # Tüm wire-format sabitleri + reverse-lookup
│   ├── logger.js               # Structured logger (renkli, component-etiketli)
│   ├── transport.js            # UDP endpoint sarmalayıcısı (node:dgram)
│   ├── record.js               # DTLSPlaintext + DTLSCiphertext unified header
│   ├── handshake.js            # 12-byte DTLS handshake header + CH/SH builder/parser
│   ├── extensions.js           # TLS 1.3 extension encode/decode + builders/parsers
│   ├── hkdf.js                 # RFC 5869 + RFC 8446 §7.1 HKDF-Expand-Label, Derive-Secret
│   ├── cipher-suite.js         # Suite metadata (hash, AEAD, key/iv/nonce/sn boyları)
│   ├── transcript.js           # Rolling transcript hash + HRR message_hash transform
│   ├── ecdhe.js                # X25519 + P-256 keypair/import/computeSharedSecret
│   ├── key-schedule.js         # Early/Handshake/Master secret ağacı + traffic keys
│   ├── aead.js                 # AEAD seal/open + sequence number encryption (§4.2.3)
│   └── cookie.js               # Stateless HMAC cookie (DoS koruması)
├── tests/
│   ├── test-kat.js             # RFC 5869 + RFC 8448 KAT
│   ├── test-unit.js            # Unit: ECDHE, transcript, AEAD, SN, cookie
│   └── test-e2e.js             # In-process end-to-end handshake
├── scripts/
│   ├── gen-certs.sh            # ECDSA P-256 self-signed (Phase 3'te kullanılacak)
│   ├── openssl-server.sh       # openssl s_server -dtls1_3 (Phase 3+4 interop için)
│   └── openssl-client.sh       # openssl s_client -dtls1_3
└── certs/                      # gen-certs.sh çıktısı (gitignore)
```

## Çalıştırma

```bash
# İki terminal:
npm run server              # 127.0.0.1:4444, cookie + HRR aktif
npm run client              # SNI=localhost, X25519 öncelikli

# Cookie/HRR'yi kapat (Phase 3 testleri için daha sade akış):
npm run server:nocookie

# Tüm key hex'leri gör:
DTLS_LOG_LEVEL=TRACE npm run server
DTLS_LOG_LEVEL=TRACE npm run client
```

## Phase 2 mimari notlar

### Key schedule kimlik doğrulaması

Key schedule semantiği TLS 1.3 ile **birebir aynı** (RFC 9147 §5.9 — DTLS 1.3 kendi
prefix'ini tanımlamaz, `"tls13 "` aynen kullanılır). `tests/test-kat.js` içindeki
RFC 8448 §3 vektörleri bu eşleşmenin resmi kanıtı:

- Early Secret = `33ad0a1c607ec03b…`
- Handshake Secret = `1dc826e93606aa6f…`
- client_handshake_traffic_secret = `b3eddb126e067f35…`
- client handshake key = `dbfaa693d1762c5b666af5d950258d01`
- master secret, c/s_application_traffic_secret_0 — hepsi match

### HRR transcript dönüşümü

`transcript.replaceWithMessageHash()` RFC 8446 §4.4.1'deki `message_hash(254)`
sarmalamasını uygular:

```
H := message_hash ||  00 00 HashLen  ||  Hash(ClientHello1)
H := H || HelloRetryRequest || ClientHello2 || ServerHello
```

`tests/test-e2e.js` bu transformun her iki tarafta aynı `transcriptCHSH` ürettiğini
kanıtlıyor.

### DTLS handshake header normalization

Transcript'e eklerken `message_seq`, `fragment_offset`, `fragment_length` alanları
**sıfırlanıp** `fragment_length = length` olarak yazılır (RFC 9147 §5.1). Bu, DTLS
özgü retransmit semantiğinin transcript'i bozmamasını sağlar. `test-unit.js`'te
`message_seq=0 vs message_seq=5` aynı içerikle aynı digest üretiyor.

### Stateless cookie

`CookieMinter` şu bind-data üzerine HMAC-SHA256 hesaplar:

```
address || port || timestamp || Hash(ClientHello1)
```

Wire formatı: `timestamp(8 BE) || mac(32)` = 40 byte. TTL 60 sn; spoofed IP
adreslerinden gelen CH'ler HRR alır ama CH2 gönderemez (HMAC fail).

Not: bu uygulamada cookie verify sırasında CH1'in hash'ine sunucu state'inden
erişiyoruz (connection tablosu). Tam stateless operasyon için Phase 4'te "cookie
payload içine CH1 bileşenlerini de yerleştir" alternatifi eklenecek.

## Phase 3 yol haritası

Sıradaki iş — handshake'in şifreli kısmını aç/kapa:

1. **`src/protected-record.js`** — AEAD seal/open + SN encryption'ı tek API'de
   birleştir. `protect(contentType, plaintext, epoch, seq, keys)` →
   DTLSCiphertext bytes. `unprotect(cipherBytes, expectedEpoch, lastSeq, keys)` →
   `{ contentType, content, seq }`.
2. **Fragment reassembly** (`src/hs-reassembler.js`) — handshake message_seq bazlı
   buffer; Certificate tek datagrama sığmaz, multi-fragment birleştirme zorunlu.
3. **Server FLIGHT 4** — `EncryptedExtensions` (muhtemelen boş), `Certificate`
   (ECDSA P-256 chain), `CertificateVerify` (imza = SHA-256 of context string +
   transcript hash), `Finished` (HMAC of transcript with finished_key).
4. **Client FLIGHT 5** — decrypt EE/Cert/CertVerify/Finished, server imzasını
   verify et, Finished MAC'i doğrula, kendi Finished'ını gönder, application
   traffic secret'ı türet.
5. **ACK mesajları** (RFC 9147 §7) — epoch değişimlerinde explicit ACK.
6. **Retransmit timer** — RFC 9147 §5.10, exponential backoff.

Bu Phase 3'ün sonunda `openssl s_client -dtls1_3 -connect` ile gerçek interop
testinin yapılabilir olması hedefi.
