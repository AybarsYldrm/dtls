'use strict';
// DTLS 1.3 Session — tam handshake state machine, record protection, ACK, replay.

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const {
  CONTENT_TYPE, VERSION, HS_TYPE, EXT_TYPE, NAMED_GROUP, SIG_SCHEME,
  EPOCH, NAMES, CIPHER_SUITE, ALERT_LEVEL, ALERT_DESC,
} = require('../constants.js');
const { encodePlaintext, decodePlaintext, parseDatagram } = require('../record/plaintext.js');
const {
  encodeHandshake, decodeHandshake,
  buildClientHello, parseClientHello,
  buildServerHello, parseServerHello,
} = require('../handshake/framing.js');
const {
  ext_serverName, ext_supportedVersionsClient, ext_supportedVersionsServer,
  ext_supportedGroups, ext_signatureAlgorithms,
  ext_keyShareClient, ext_keyShareServer, ext_keyShareHRR,
  ext_cookie, ext_pskKeyExchangeModes,
  parse_supportedVersionsClient, parse_supportedGroups,
  parse_keyShareClient, parse_keyShareServer,
  parse_cookie, parse_serverName,
  parse_signatureAlgorithms,
} = require('../handshake/extensions.js');
const { selectSuite, getSuite } = require('../crypto/cipher-suite.js');
const ecdhe = require('../crypto/ecdhe.js');
const { Transcript } = require('../handshake/transcript.js');
const {
  deriveHandshakeStage, deriveApplicationStage,
} = require('../crypto/key-schedule.js');
const { CookieMinter } = require('../handshake/cookie.js');
const { protectRecord, unprotectRecord } = require('../record/protected.js');
const { HsReassembler } = require('../handshake/reassembler.js');
const {
  buildEncryptedExtensions, parseEncryptedExtensions,
  buildCertificate, parseCertificate,
  signCertVerify, parseCertVerify, verifyCertVerify,
  buildFinished, verifyFinished,
} = require('../handshake/messages.js');
const { buildAck, parseAck } = require('../record/ack.js');
const { ReplayWindow } = require('../record/replay-window.js');
const { buildKeyUpdate, parseKeyUpdate, advanceTrafficSecret } = require('../crypto/key-update.js');

const MAX_MTU = 1200; // İnternet üstü DTLS için muhafazakar UDP payload (QUIC benzeri güvenli değer)
const HS_FRAG_BUDGET = MAX_MTU - 64;  // unified hdr + AEAD tag + olası CID/padding payı

// ============================================================================
// Session — client VE server için ortak. role="client" veya "server".
// ============================================================================
class Session extends EventEmitter {
  constructor({ role, transport, peer = null, sni = 'localhost',
                certDER = null, privateKey = null, cookieRequired = true, cid = null }) {
    super();
    this.role = role;
    this.transport = transport;
    this.peer = peer;           // { address, port } (client: server'ın; server: client'ın rinfo)
    this.sni = sni;
    this.certDER = certDER;     // server için
    this.privateKey = privateKey;
    this.cookieRequired = cookieRequired;
    this.ourCID = cid;          // kendi verdiğimiz CID (karşı taraftan bu CID ile gelmesini istiyoruz)
    this.theirCID = null;       // karşı tarafın istediği CID (biz onlara bu CID ile gönderirken)

    // State
    this.state = (role === 'client') ? 'START' : 'WAIT_CH1';
    this.suite = null;
    this.chosenGroup = NAMED_GROUP.X25519;
    this.keyPair = null;
    this.sharedSecret = null;
    this.transcript = null;
    this.handshakeKeys = null;
    this.appKeys = null;

    // Outgoing bookkeeping
    this.messageSeq = 0;      // next outgoing HS message_seq
    this.sendEpoch = EPOCH.INITIAL;
    this.sendSeq = new Map(); // epoch → u48 seq
    this.sendSeq.set(0, 0);

    // Incoming
    this.recvEpoch = EPOCH.INITIAL;
    this.recvLastSeq = new Map(); // epoch → highest accepted full seq (for sn reconstruction)
    this.recvLastSeq.set(0, -1);
    this.recvReplay = new Map();  // epoch → ReplayWindow
    this.recvReplay.set(0, new ReplayWindow(64));

    // HRR bookkeeping (server)
    this.ch1Wire = null;
    this.ch1Hash = null;
    this.hrrWire = null;
    this.ch2Wire = null;
    this.cookieMinter = new CookieMinter();

    // Reassemblers
    this.rxReassembler = new HsReassembler();
    this.createdAt = Date.now();

    // Pending record ACK'leri (bu record'ları peer'a işlenmiş olarak bildireceğiz)
    this.pendingAcks = [];

    // Retransmit flight buffer: son gönderilen handshake flight'ı
    this.lastFlight = null; // { records: [Buffer], timer: Timeout, attempts: number }
  }

  // ========================================================================
  // Dispatcher — transport'tan gelen her datagram buraya düşer.
  // ========================================================================
  handleDatagram(datagram, rinfo) {
    if (this.role === 'server' && !this.peer) this.peer = { address: rinfo.address, port: rinfo.port };
    try {
      let offset = 0;
      while (offset < datagram.length) {
        const firstByte = datagram.readUInt8(offset);
        const top3 = firstByte & 0b11100000;
        if (top3 === 0b00100000) {
          // Protected
          const rec = this.unprotectAt(datagram, offset);
          if (!rec) { offset = datagram.length; break; }
          offset += rec.bytesConsumed;
          this.onProtected(rec);
        } else {
          const rec = decodePlaintext(datagram, offset);
          offset += rec.bytesConsumed;
          this.onPlaintext(rec);
        }
      }
    } catch (e) {
      this.emit('error', e);
    }
  }

unprotectAt(datagram, offset) {
    const epochLow = datagram.readUInt8(offset) & 0b11;
    const keys = this.currentReadKeys(epochLow); 
    if (!keys) { return null; }
    const lastSeq = this.recvLastSeq.get(this.recvEpoch) ?? -1;
    const rec = unprotectRecord({
      record: datagram, offset,
      readKey: keys.key, readIv: keys.iv, snKey: keys.sn,
      aeadAlg: this.suite.aead, snCipher: this.suite.sn_cipher,
      lastSeq: Math.max(0, lastSeq),
      epoch: this.recvEpoch, // <--- EKSİK OLAN VE CRASH'E YOL AÇAN SATIR BUYDU!
      cidLength: this.ourCID ? this.ourCID.length : 0,
    });
    // Replay check
    const win = this.recvReplay.get(this.recvEpoch);
    if (win && !win.accept(rec.fullSeq)) {
      this.emit('log', 'warn', 'replay rejected', { epoch: this.recvEpoch, seq: rec.fullSeq });
      return { bytesConsumed: rec.bytesConsumed, replayed: true };
    }
    if (rec.fullSeq > (this.recvLastSeq.get(this.recvEpoch) ?? -1)) {
      this.recvLastSeq.set(this.recvEpoch, rec.fullSeq);
    }
    // ACK kaydı
    this.pendingAcks.push({ epoch: this.recvEpoch, seq: rec.fullSeq });
    return rec;
  }

  onPlaintext(rec) {
    if (rec.type === CONTENT_TYPE.HANDSHAKE) this.onHandshakeBytes(rec.fragment, rec);
    else if (rec.type === CONTENT_TYPE.ALERT) this.onAlert(rec.fragment);
    else this.emit('log', 'warn', 'unexpected plaintext', { type: rec.typeName });
  }

  onProtected(rec) {
    if (rec.replayed) return;
    if (rec.contentType === CONTENT_TYPE.HANDSHAKE) this.onHandshakeBytes(rec.content, rec);
    else if (rec.contentType === CONTENT_TYPE.APPLICATION_DATA) this.emit('data', rec.content);
    else if (rec.contentType === CONTENT_TYPE.ALERT) this.onAlert(rec.content);
    else if (rec.contentType === CONTENT_TYPE.ACK) this.onAck(rec.content);
    else this.emit('log', 'warn', 'unknown protected ct', { ct: rec.contentType });
  }

  onHandshakeBytes(buf, _rec) {
    let o = 0;
    while (o < buf.length) {
      const hs = decodeHandshake(buf.slice(o));
      o += 12 + hs.fragmentLength;
      const r = this.rxReassembler.add({
        msgType: hs.msgType,
        length: hs.length,
        messageSeq: hs.messageSeq,
        fragmentOffset: hs.fragmentOffset,
        fragmentLength: hs.fragmentLength,
        body: hs.body,
      });
      if (r.complete) {
        // Transcript için normalize edilmiş DTLS wire-form rebuild et (tek parça gibi)
        const rebuilt = rebuildSingleFragmentWire(r.msgType, r.messageSeq, r.body);
        this.onHandshakeMessage({ msgType: r.msgType, body: r.body, messageSeq: r.messageSeq, wire: rebuilt });
      }
    }
  }

  onHandshakeMessage(m) {
    const T = NAMES.HS_TYPE[m.msgType] || `UNKNOWN(${m.msgType})`;
    this.emit('log', 'info', `<< ${T}`, { messageSeq: m.messageSeq, length: m.body.length });
    try {
      if (this.role === 'server') this.serverHandle(m);
      else this.clientHandle(m);
    } catch (e) {
      this.emit('error', e);
    }
  }

  onAlert(body) {
    const level = body[0], desc = body[1];
    this.emit('log', 'warn', 'ALERT', { level: NAMES.ALERT_LEVEL[level], desc: NAMES.ALERT_DESC[desc] });
    this.emit('alert', { level, desc });
  }

  onAck(body) {
    const acks = parseAck(body);
    this.emit('log', 'debug', 'ACK rx', { count: acks.length });
    // Flight ACK'landı → timer'ı iptal et, buffer'ı temizle
    this.cancelRetransmit();
  }

  // ========================================================================
  // RETRANSMIT — RFC 9147 §5.10
  //
  // Bir handshake flight'ı gönderildiğinde, ACK veya bir sonraki peer flight'ı
  // gelene kadar exponential backoff ile yeniden göndeririz:
  //   baseMs=1000, attempt n: baseMs * 2^n, max 6 deneme (≈63s toplam)
  // Başarısızsa session'ı fatal kapatırız.
  // ========================================================================
  startFlight() {
    this.cancelRetransmit();
    this.lastFlight = { records: [], attempts: 0, timer: null };
  }

  recordFlightDatagram(buf) {
    // UDP wire'a gitmiş bir datagram buffer'ı — retransmit'te aynen yeniden gönderilecek
    if (this.lastFlight) this.lastFlight.records.push(buf);
  }

  armRetransmit(baseMs = 1000) {
    if (!this.lastFlight || this.lastFlight.records.length === 0) return;
    const delay = baseMs * Math.pow(2, this.lastFlight.attempts);
    const cap = 60_000; // 60sn üst sınır — RFC 9147 §5.10.1 önerdiği aralıkta
    this.lastFlight.timer = setTimeout(() => this.doRetransmit(), Math.min(delay, cap));
    if (this.lastFlight.timer.unref) this.lastFlight.timer.unref();
  }

  async doRetransmit() {
    if (!this.lastFlight) return;
    const MAX_ATTEMPTS = 6;
    if (this.lastFlight.attempts >= MAX_ATTEMPTS) {
      this.emit('log', 'error', 'retransmit limit aşıldı, session fatal',
                { attempts: this.lastFlight.attempts });
      return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.INTERNAL_ERROR, 'retransmit exhausted');
    }
    this.lastFlight.attempts += 1;
    this.emit('log', 'warn', 'retransmit flight', {
      attempt: this.lastFlight.attempts,
      records: this.lastFlight.records.length,
    });
    for (const rec of this.lastFlight.records) {
      try { await this.transport.send(rec, this.peer); }
      catch (e) { this.emit('log', 'warn', 'retransmit send failed', { err: e.message }); }
    }
    this.armRetransmit();
  }

  cancelRetransmit() {
    if (this.lastFlight && this.lastFlight.timer) {
      clearTimeout(this.lastFlight.timer);
    }
    this.lastFlight = null;
  }

  // ========================================================================
  // CURRENT READ/WRITE KEY CONTEXTS
  // ========================================================================
  // session.js
  currentReadKeys(epochLow) {
    const other = this.role === 'client' ? 'server' : 'client';
    
    // Eğer gelen paket Handshake epoch'una (0b10 = 2) aitse
    if (epochLow === 2 && this.handshakeKeys) {
      return this.handshakeKeys[other + 'Handshake'];
    }
    // Eğer paket Application epoch'una aitse (Örn: 0b11 = 3)
    if (this.appKeys && this.recvEpoch >= 3 && epochLow === (this.recvEpoch & 0b11)) {
      return this.appKeys[other + 'Application'];
    }
    return null;
  }
  currentWriteKeys() {
    const role = this.role;
    if (this.sendEpoch === 2 && this.handshakeKeys) return this.handshakeKeys[role + 'Handshake'];
    if (this.sendEpoch >= 3 && this.appKeys) return this.appKeys[role + 'Application'];
    return null;
  }

  // ========================================================================
  // SEND helpers
  // ========================================================================
  sendPlaintextRecord(contentType, fragment) {
    const seq = this.sendSeq.get(0) ?? 0;
    const rec = encodePlaintext({ type: contentType, epoch: 0, sequenceNumber: seq, fragment });
    this.sendSeq.set(0, seq + 1);
    this.recordFlightDatagram(rec);
    return this.transport.send(rec, this.peer);
  }

  sendProtectedRecord(contentType, content) {
    const keys = this.currentWriteKeys();
    if (!keys) throw new Error('sendProtectedRecord: no write keys');
    const seq = this.sendSeq.get(this.sendEpoch) ?? 0;
    const rec = protectRecord({
      contentType, content,
      recordSeq: seq,
      epoch: this.sendEpoch,
      writeKey: keys.key, writeIv: keys.iv, snKey: keys.sn,
      aeadAlg: this.suite.aead, snCipher: this.suite.sn_cipher,
      connectionId: this.theirCID,
    });
    this.sendSeq.set(this.sendEpoch, seq + 1);
    // Application data kendi başına retransmit'e dahil değil — sadece handshake/ACK/alert
    if (contentType === CONTENT_TYPE.HANDSHAKE || contentType === CONTENT_TYPE.ACK) {
      this.recordFlightDatagram(rec);
    }
    return this.transport.send(rec, this.peer);
  }

  // Handshake mesajını (ihtiyaçsa parçalayarak) gönder.
  async sendHandshakeMessage(msgType, body, { encrypted }) {
    const messageSeq = this.messageSeq++;
    const totalLen = body.length;
    // Transcript için normalize edilmiş wire (tek parça, fragment_off=0, fragment_len=totalLen)
    const fullWire = rebuildSingleFragmentWire(msgType, messageSeq, body);
    this.transcript?.appendDtls(fullWire);

    // Fragmentation
    const fragBudget = Math.max(256, HS_FRAG_BUDGET); // sertifika flight'ını küçük parçalara böl
    if (totalLen <= fragBudget) {
      // tek parça
      if (encrypted) await this.sendProtectedRecord(CONTENT_TYPE.HANDSHAKE, fullWire);
      else           await this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, fullWire);
    } else {
      let off = 0;
      while (off < totalLen) {
        const take = Math.min(fragBudget, totalLen - off);
        const fragWire = encodeHandshake({
          msgType, messageSeq, body: body.slice(off, off + take),
          fragmentOffset: off, fragmentLength: take,
          // encodeHandshake total length'i body.length'ten alıyor; fragment'te "length" alanı
          // tüm mesajın uzunluğu olmalı. Burada body.slice'ın uzunluğu != total. Fix:
        });
        // encodeHandshake'in doğru davranışı için total length'i body (full) length olarak
        // geçmek gerek — handshake.js signature'ına göre body aslında fragment body.
        // ama "length" alanı body.length olarak yazıyor. Yani fragmentation için
        // kendi elde encode edelim.
        const hdr = Buffer.alloc(12);
        hdr.writeUInt8(msgType, 0);
        hdr.writeUInt8((totalLen >> 16) & 0xff, 1);
        hdr.writeUInt16BE(totalLen & 0xffff, 2);
        hdr.writeUInt16BE(messageSeq, 4);
        hdr.writeUInt8((off >> 16) & 0xff, 6);
        hdr.writeUInt16BE(off & 0xffff, 7);
        hdr.writeUInt8((take >> 16) & 0xff, 9);
        hdr.writeUInt16BE(take & 0xffff, 10);
        const wire = Buffer.concat([hdr, body.slice(off, off + take)]);
        if (encrypted) await this.sendProtectedRecord(CONTENT_TYPE.HANDSHAKE, wire);
        else           await this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, wire);
        off += take;
      }
    }
  }

  async flushAcks() {
    if (!this.pendingAcks.length) return;
    if (this.sendEpoch < 2) return; // ACK ancak korumalı katmanda gönderilir
    const body = buildAck(this.pendingAcks);
    this.pendingAcks = [];
    await this.sendProtectedRecord(CONTENT_TYPE.ACK, body);
  }

  async sendApplicationData(data) {
    if (!this.appKeys) throw new Error('handshake tamamlanmadı');
    await this.sendProtectedRecord(CONTENT_TYPE.APPLICATION_DATA, data);
  }

  // ========================================================================
  // KEY UPDATE
  // ========================================================================
  async requestKeyUpdate(requestPeer = false) {
    if (!this.appKeys) throw new Error('KeyUpdate: app keys henüz yok');
    const body = buildKeyUpdate(requestPeer ? 1 : 0);
    // Önce mesajı mevcut epoch'ta gönder
    await this.sendHandshakeMessage(HS_TYPE.KEY_UPDATE, body, { encrypted: true });
    // Sonra kendi send tarafımızı yeni epoch'a çevir
    this.advanceWriteEpoch();
  }

  advanceWriteEpoch() {
    const role = this.role;
    const cur = this.appKeys[role + 'Application'];
    const adv = advanceTrafficSecret({ suite: this.suite, currentSecret: cur.trafficSecret });
    this.appKeys[role + 'Application'] = adv;
    this.sendEpoch += 1;
    this.sendSeq.set(this.sendEpoch, 0);
    this.emit('log', 'info', 'send epoch advanced (KeyUpdate)', { epoch: this.sendEpoch });
  }

  advanceReadEpoch() {
    const other = this.role === 'client' ? 'server' : 'client';
    const cur = this.appKeys[other + 'Application'];
    const adv = advanceTrafficSecret({ suite: this.suite, currentSecret: cur.trafficSecret });
    this.appKeys[other + 'Application'] = adv;
    this.recvEpoch += 1;
    this.recvLastSeq.set(this.recvEpoch, -1);
    this.recvReplay.set(this.recvEpoch, new ReplayWindow(64));
    this.emit('log', 'info', 'recv epoch advanced (KeyUpdate)', { epoch: this.recvEpoch });
  }

  // ========================================================================
  // CLIENT handler
  // ========================================================================
  clientStart() {
    this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);
    return this.sendClientHello({ cookie: null, messageSeq: 0 });
  }

  async sendClientHello({ cookie, messageSeq }) {
    const extsList = [
      ext_serverName(this.sni),
      ext_supportedVersionsClient([VERSION.DTLS_1_3]),
      ext_supportedGroups([NAMED_GROUP.X25519, NAMED_GROUP.SECP256R1]),
      ext_signatureAlgorithms([
        SIG_SCHEME.ECDSA_SECP256R1_SHA256,
        SIG_SCHEME.RSA_PSS_RSAE_SHA256,
        SIG_SCHEME.ED25519,
      ]),
      ext_keyShareClient([{ group: this.chosenGroup, keyExchange: this.keyPair.publicRaw }]),
      ext_pskKeyExchangeModes([0x01]),
    ];
    if (cookie) extsList.push(ext_cookie(cookie));

    const clientRandom = (messageSeq === 0) ? crypto.randomBytes(32) : this.clientRandom;
    this.clientRandom = clientRandom;
    const body = buildClientHello({
      random: clientRandom,
      cipherSuites: [CIPHER_SUITE.TLS_AES_128_GCM_SHA256, CIPHER_SUITE.TLS_AES_256_GCM_SHA384, CIPHER_SUITE.TLS_CHACHA20_POLY1305_SHA256],
      extensions: extsList,
    });
    // Transcript — burada directly buildClientHello body ile; önce transcript'i kur/yoksa
    // suite kesinleştikten sonra kuruluyor. Ama CH'yi en az bir kez yollamamız gerekli.
    // CH gönderirken transcript'i henüz kurmuyoruz — suite SH ile seçilecek.
    const wire = rebuildSingleFragmentWire(HS_TYPE.CLIENT_HELLO, messageSeq, body);
    if (messageSeq === 0) this.ch1Wire = wire; else this.ch2Wire = wire;
    this.messageSeq = messageSeq + 1;
    this.startFlight();
    await this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, wire);
    this.armRetransmit();
    this.state = messageSeq === 0 ? 'WAIT_SH' : 'WAIT_SH2';
  }

  async clientHandle(m) {
    if (m.msgType === HS_TYPE.SERVER_HELLO) return this.clientOnSH(m);
    if (!this.state.startsWith('WAIT_EE') && !this.state.startsWith('WAIT_CERT') &&
        !this.state.startsWith('WAIT_CV') && !this.state.startsWith('WAIT_SF')) {
      // Pre-encrypted aşamada beklenmedik mesaj
    }
    if (m.msgType === HS_TYPE.ENCRYPTED_EXTENSIONS) return this.clientOnEE(m);
    if (m.msgType === HS_TYPE.CERTIFICATE) return this.clientOnCert(m);
    if (m.msgType === HS_TYPE.CERTIFICATE_VERIFY) return this.clientOnCV(m);
    if (m.msgType === HS_TYPE.FINISHED) return this.clientOnSF(m);
    if (m.msgType === HS_TYPE.KEY_UPDATE) return this.onKeyUpdate(m);
  }

  async clientOnSH(m) {
    // CH/CH2 flight'ı başarıyla cevap aldı
    this.cancelRetransmit();
    const sh = parseServerHello(m.body);
    const suite = getSuite(sh.cipherSuite.value);
    this.suite = suite;

    if (sh.isHRR) {
      this.hrrWire = m.wire;
      const cookieExt = sh.extensions.find(e => e.type === EXT_TYPE.COOKIE);
      const ksExt = sh.extensions.find(e => e.type === EXT_TYPE.KEY_SHARE);
      const cookie = cookieExt ? parse_cookie(cookieExt.data) : null;
      const ks = ksExt ? parse_keyShareServer(ksExt.data) : null;
      if (ks && ks.selectedGroup && ks.selectedGroup !== this.chosenGroup) {
        this.chosenGroup = ks.selectedGroup;
        this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);
      }
      return this.sendClientHello({ cookie, messageSeq: this.messageSeq });
    }

    // Build transcript
    this.transcript = new Transcript(suite.hash);
    if (this.hrrWire) {
      this.transcript.appendDtls(this.ch1Wire);
      this.transcript.replaceWithMessageHash();
      this.transcript.appendDtls(this.hrrWire);
      this.transcript.appendDtls(this.ch2Wire);
    } else {
      this.transcript.appendDtls(this.ch1Wire);
    }
    this.transcript.appendDtls(m.wire);

    // ECDHE complete
    const ksExt = sh.extensions.find(e => e.type === EXT_TYPE.KEY_SHARE);
    const ks = parse_keyShareServer(ksExt.data);
    const peerPub = ecdhe.importPeerPublic(ks.group, ks.keyExchange);
    this.sharedSecret = ecdhe.computeSharedSecret(this.keyPair.privateKey, peerPub);

    this.handshakeKeys = deriveHandshakeStage({
      suite, sharedSecret: this.sharedSecret, transcriptCH_SH: this.transcript.digest(),
    });
    this.emit('secrets', { stage: 'handshake', keys: this.handshakeKeys, clientRandom: this.clientRandom });

    // Shift into handshake epoch for BOTH send and recv — epoch 2
    this.sendEpoch = 2; this.sendSeq.set(2, 0);
    this.recvEpoch = 2; this.recvLastSeq.set(2, -1); this.recvReplay.set(2, new ReplayWindow(64));

    this.state = 'WAIT_EE';
  }

  async clientOnEE(m) {
    // Transcript append
    this.transcript.appendDtls(m.wire);
    this.state = 'WAIT_CERT';
  }

  async clientOnCert(m) {
    const { entries } = parseCertificate(m.body);
    this.peerCertDER = entries[0]?.cert;
    this.peerCertChain = entries.map(e => new crypto.X509Certificate(e.cert));
    this.peerCert = this.peerCertChain[0];
    // Tüketicilere zincirin kendisini ve leaf'in özetini yay
    this.emit('peer-cert', {
      leaf: this.peerCert,
      chain: this.peerCertChain,
      subject: this.peerCert.subject,
      issuer: this.peerCert.issuer,
      validFrom: this.peerCert.validFrom,
      validTo: this.peerCert.validTo,
      fingerprint256: this.peerCert.fingerprint256,
      subjectAltName: this.peerCert.subjectAltName,
      keyType: this.peerCert.publicKey.asymmetricKeyType,
    });
    this.transcript.appendDtls(m.wire);
    this.state = 'WAIT_CV';
  }

  async clientOnCV(m) {
    // Transcript'e EKLEMEDEN önce verify ediyoruz — imza, önceki transcript'i kapsar
    const th = this.transcript.digest();
    const { sigScheme, signature } = parseCertVerify(m.body);
    const ok = verifyCertVerify({
      role: 'server', publicKey: this.peerCert.publicKey,
      sigScheme, signature, transcriptHash: th,
    });
    if (!ok) { this.emit('error', new Error('CertificateVerify failed')); return; }
    this.emit('log', 'info', 'CertificateVerify OK');
    this.transcript.appendDtls(m.wire);
    this.state = 'WAIT_SF';
  }

  async clientOnSF(m) {
    // Server Finished verify
    const thBeforeSF = this.transcript.digest();
    const fk = this.handshakeKeys.serverHandshake.finishedKey;
    const ok = verifyFinished({
      hash: this.suite.hash, finishedKey: fk,
      transcriptHash: thBeforeSF, received: m.body,
    });
    if (!ok) { this.emit('error', new Error('Server Finished MAC fail')); return; }
    this.emit('log', 'info', 'Server Finished OK');

    this.transcript.appendDtls(m.wire);

    // Send Client Finished
    const thBeforeCF = this.transcript.digest();
    const cfBody = buildFinished({
      hash: this.suite.hash,
      finishedKey: this.handshakeKeys.clientHandshake.finishedKey,
      transcriptHash: thBeforeCF,
    });
    this.startFlight();
    await this.sendHandshakeMessage(HS_TYPE.FINISHED, cfBody, { encrypted: true });
    this.armRetransmit();
    // Transcript: CF dahil transcript (CH..CF) uygulamak üzere saklanmış olsun — sendHandshakeMessage
    // zaten append ediyor. Ama onun appendini yaptığımızda yeniden normalize edilmiş olarak
    // eklenmiş olur; OK.

    // Derive application keys (transcriptCH_SF = CH..SF, yani CF değil; bizde "thBeforeCF" = CH..SF)
    this.appKeys = deriveApplicationStage({
      suite: this.suite,
      handshakeSecret: this.handshakeKeys.handshakeSecret,
      transcriptCH_SF: thBeforeCF,
    });
    this.emit('secrets', { stage: 'application', keys: this.appKeys, clientRandom: this.clientRandom });
    this.sendEpoch = 3; this.sendSeq.set(3, 0);
    this.recvEpoch = 3; this.recvLastSeq.set(3, -1); this.recvReplay.set(3, new ReplayWindow(64));
    this.state = 'ESTABLISHED';
    this.emit('handshake');
  }

  async onKeyUpdate(m) {
    const { requestUpdate } = parseKeyUpdate(m.body);
    this.advanceReadEpoch();
    if (requestUpdate === 1) {
      // Karşı taraf bizden de update istiyor
      await this.requestKeyUpdate(false);
    }
  }

  // ========================================================================
  // SERVER handler
  // ========================================================================
  async serverHandle(m) {
    if (m.msgType === HS_TYPE.CLIENT_HELLO) return this.serverOnCH(m);
    if (m.msgType === HS_TYPE.FINISHED) return this.serverOnCF(m);
    if (m.msgType === HS_TYPE.KEY_UPDATE) return this.onKeyUpdate(m);
  }

  async serverOnCH(m) {
    const ch = parseClientHello(m.body);
    this.clientRandom = ch.random;

    
    // Her CH için kısa özet — debugging için kritik. "Neden reddedildi" sorusunun
    // cevabı log'da bulunsun, peer'ın bize ne teklif ettiği görülebilsin.
    this.emit('log', 'info', 'ClientHello decoded', {
      legacyVersion: '0x' + ch.legacyVersion.toString(16),
      cipherSuites: ch.cipherSuites.map(c => c.name).slice(0, 6),
      cipherSuiteCount: ch.cipherSuites.length,
      extensions: ch.extensions.map(e => `${e.typeName}(${e.type})`),
      bodyLen: m.body.length,
    });

    // Opsiyonel: tüm CH'nin hex dump'ı — DTLS_DEBUG_CH=1 ile açılır.
    // wolfSSL / OpenSSL interop debug'ında kritik.
    if (process.env.DTLS_DEBUG_CH === '1') {
      this.emit('log', 'info', 'ClientHello raw body', {
        hex: m.body.toString('hex'),
        wireHex: m.wire.toString('hex'),
      });
    }

    // CH1 wire'ını erkenden sakla — HRR/group-HRR path'lerinin hepsi buna ihtiyaç duyar
    if (this.state === 'WAIT_CH1') this.ch1Wire = Buffer.from(m.wire);

    // legacy_version'ı logla — DTLS 1.0/1.2-only client ise supported_versions yoktur
    const sv = ch.extensions.find(e => e.type === EXT_TYPE.SUPPORTED_VERSIONS);
    if (!sv) {
      this.emit('log', 'warn', 'ClientHello supported_versions yok — legacy DTLS (1.0/1.2) istemcisi, reddediliyor', {
        legacyVersion: '0x' + ch.legacyVersion.toString(16),
      });
      return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.PROTOCOL_VERSION, 'legacy DTLS peer');
    }
    const versions = parse_supportedVersionsClient(sv.data);
    if (!versions.includes(VERSION.DTLS_1_3)) {
      // Teşhis detayı — hangi versiyonlar listelenmiş?
      const vStr = versions.map(v => {
        const name = NAMES.VERSION[v];
        return name ? `${name}(0x${v.toString(16)})` : `0x${v.toString(16)}`;
      }).join(', ');
      this.emit('log', 'warn', 'DTLS 1.3 teklif edilmedi — supported_versions içeriği:', {
        versions: vStr,
        rawHex: sv.data.toString('hex'),
        expected: `DTLS_1_3(0x${VERSION.DTLS_1_3.toString(16)})`,
      });
      return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.PROTOCOL_VERSION,
                            `DTLS 1.3 teklif edilmedi: ${vStr}`);
    }
    const suite = selectSuite(ch.cipherSuites.map(c => c.value));
    if (!suite) return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.HANDSHAKE_FAILURE);
    this.suite = suite;

    const cookieExt = ch.extensions.find(e => e.type === EXT_TYPE.COOKIE);
    const cookieBytes = cookieExt ? parse_cookie(cookieExt.data) : null;

    if (this.state === 'WAIT_CH1' && this.cookieRequired && !cookieBytes) {
      // HRR yolu
      this.ch1Wire = Buffer.from(m.wire);
      const ch1HashT = new Transcript(suite.hash); ch1HashT.appendDtls(m.wire);
      this.ch1Hash = ch1HashT.digest();

      this.chosenGroup = this.pickGroupFromCH(ch);
      if (this.chosenGroup == null) {
        return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.HANDSHAKE_FAILURE, 'ortak named_group yok');
      }

      const cookie = this.cookieMinter.mint(this.peer, this.ch1Hash);
      const hasChosenShare = (() => {
        const ksExt = ch.extensions.find(e => e.type === EXT_TYPE.KEY_SHARE);
        if (!ksExt) return false;
        const entries = parse_keyShareClient(ksExt.data);
        return entries.some(e => e.group === this.chosenGroup);
      })();

      // OpenSSL DTLS 1.3, "cookie-only" HRR bekler: eğer client zaten seçilen grup için
      // key_share gönderdiyse HRR içindeki key_share(selected_group) ile ikinci kez
      // aynı grubu istemek ILLEGAL_PARAMETER ile düşebiliyor.
      const hrrExtensions = [
        ext_supportedVersionsServer(VERSION.DTLS_1_3),
        ext_cookie(cookie),
      ];
      if (!hasChosenShare) hrrExtensions.push(ext_keyShareHRR(this.chosenGroup));

      const hrrBody = buildServerHello({
        cipherSuite: suite.id,
        extensions: hrrExtensions,
        isHRR: true,
      });
      const hrrWire = rebuildSingleFragmentWire(HS_TYPE.SERVER_HELLO, 0, hrrBody);
      this.hrrWire = hrrWire;
      this.messageSeq = 1;
      this.startFlight();
      await this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, hrrWire);
      this.armRetransmit();
      this.state = 'WAIT_CH2';
      return;
    }

    // CH2 (veya cookie kapalı direkt CH) — cookie doğrula
    if (this.cookieRequired) {
      const { ok, reason } = this.cookieMinter.verify(cookieBytes, this.peer, this.ch1Hash);
      if (!ok) return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.ILLEGAL_PARAMETER, reason);
    } else if (this.state === 'WAIT_CH1') {
      // Direct path (cookie off) — grup seçimini client'ın key_share'i üzerinden yap,
      // yoksa supported_groups intersection'ına düş. İkisi de yoksa HRR iste.
      this.chosenGroup = this.pickGroupFromCH(ch);
      if (this.chosenGroup == null) {
        return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.HANDSHAKE_FAILURE, 'ortak named_group yok');
      }
    }
    if (this.state === 'WAIT_CH2') this.ch2Wire = Buffer.from(m.wire);

    // ECDHE — client bizim seçtiğimiz grup için key_share göndermiş mi?
    const ksExt = ch.extensions.find(e => e.type === EXT_TYPE.KEY_SHARE);
    if (!ksExt) return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.MISSING_EXTENSION, 'key_share yok');
    const entries = parse_keyShareClient(ksExt.data);
    const entry = entries.find(e => e.group === this.chosenGroup);

    if (!entry) {
      // RFC 8446 §4.1.4: group uyumsuz → HRR göndermek ZORUNLUDUR.
      // Bu path zaten CH1 ise (HRR'den dönmediysek) HRR gönderelim; CH2 ise bu bir fatal
      // çünkü client daha önce yönlendirilmişti ama yine yanlış key_share gönderdi.
      if (this.state === 'WAIT_CH1' || !this.cookieRequired) {
        return this.sendGroupHRR(ch, suite);
      }
      return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.ILLEGAL_PARAMETER,
                            'HRR sonrası CH2 hâlâ yanlış key_share');
    }
    this.keyPair = ecdhe.generateKeyPair(this.chosenGroup);
    const peerPub = ecdhe.importPeerPublic(this.chosenGroup, entry.keyExchange);
    this.sharedSecret = ecdhe.computeSharedSecret(this.keyPair.privateKey, peerPub);

    this.emit('log', 'info', 'ECDHE_DEBUG', {
      group: this.chosenGroup,
      peer_pub_hex: entry.keyExchange.toString('hex'),
      peer_pub_len: entry.keyExchange.length,
      our_pub_hex: this.keyPair.publicRaw.toString('hex'),
      shared_hex: this.sharedSecret.toString('hex'),
    });

    // SH
    const shBody = buildServerHello({
      random: crypto.randomBytes(32),
      cipherSuite: suite.id,
      extensions: [
        ext_supportedVersionsServer(VERSION.DTLS_1_3),
        ext_keyShareServer({ group: this.chosenGroup, keyExchange: this.keyPair.publicRaw }),
      ],
      isHRR: false,
    });
    const shWire = rebuildSingleFragmentWire(HS_TYPE.SERVER_HELLO, this.messageSeq, shBody);
    this.messageSeq += 1;
    // CH2 kabul edildi → eski HRR flight'ını iptal et, SH+EE+Cert+CV+SF yeni flight'ı başlat
    this.cancelRetransmit();
    this.startFlight();
    await this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, shWire);

    // Transcript
    this.transcript = new Transcript(suite.hash);
    if (this.cookieRequired) {
      this.transcript.appendDtls(this.ch1Wire);
      this.transcript.replaceWithMessageHash();
      this.transcript.appendDtls(this.hrrWire);
      this.transcript.appendDtls(this.ch2Wire);
    } else {
      this.transcript.appendDtls(this.ch1Wire);
    }
    this.transcript.appendDtls(shWire);
this.emit('log', 'info', 'KEY_INPUTS', {
  client_random: this.clientRandom.toString('hex'),
  shared_secret: this.sharedSecret.toString('hex'),
  transcript_CH_SH: this.transcript.digest().toString('hex'),
});
this.emit('log', 'info', 'TRANSCRIPT_DEBUG', {
  th_CH_SH: this.transcript.digest().toString('hex'),
  ch1_wire_first16: this.ch1Wire.slice(0, 16).toString('hex'),
  ch1_wire_len: this.ch1Wire.length,
  sh_wire_hex: shWire.toString('hex'),
});

this.emit('log', 'info', 'TRANSCRIPT_FULL', {
  ch1_wire_full_hex: this.ch1Wire.toString('hex'),
  sh_wire_full_hex: shWire.toString('hex'),
  th_CH_SH: this.transcript.digest().toString('hex'),
});

// ↓↓↓ DEBUG ↓↓↓
this.emit('log', 'info', 'ECDHE_DEBUG', {
  group: this.chosenGroup,
  peer_pub_hex: entry.keyExchange.toString('hex'),
  peer_pub_len: entry.keyExchange.length,
  our_pub_hex: this.keyPair.publicRaw.toString('hex'),
  shared_hex: this.sharedSecret.toString('hex'),
});

    this.handshakeKeys = deriveHandshakeStage({
      suite, sharedSecret: this.sharedSecret, transcriptCH_SH: this.transcript.digest(),
    });

    // --- BRUTE-FORCE CRYPTO DETECTIVE ---
    // OpenSSL'in Transcript Hash'i nasıl yorumladığını kesin olarak bulmak için:
    try {
      const crypto = require('node:crypto');
      const { deriveHandshakeStage } = require('../crypto/key-schedule.js');
      
      const tests = {};
      
      // Senaryo 1: RFC 9147 Standart (4-byte header)
      const h1 = crypto.createHash(suite.hash);
      const ch1_4b = Buffer.concat([this.ch1Wire.slice(0,4), this.ch1Wire.slice(12)]);
      const sh_4b = Buffer.concat([shWire.slice(0,4), shWire.slice(12)]);
      h1.update(ch1_4b); h1.update(sh_4b);
      tests['RFC_Standard_4Byte'] = deriveHandshakeStage({ suite, sharedSecret: this.sharedSecret, transcriptCH_SH: h1.digest() }).clientHandshakeSecret.toString('hex');

      // Senaryo 2: Raw DTLS (12-byte header, dokunulmamış)
      const h2 = crypto.createHash(suite.hash);
      h2.update(this.ch1Wire); h2.update(shWire);
      tests['Raw_12Byte_Header'] = deriveHandshakeStage({ suite, sharedSecret: this.sharedSecret, transcriptCH_SH: h2.digest() }).clientHandshakeSecret.toString('hex');

      // Senaryo 3: Zeroed DTLS Header (Orijinal kodundaki gibi ama frag_len bozulmamış)
      const zeroHeader = (buf) => {
        const out = Buffer.from(buf);
        out.writeUInt16BE(0, 4); // seq = 0
        out.writeUInt8(0, 6); out.writeUInt16BE(0, 7); // frag_off = 0
        // frag_len'e DOKUNMUYORUZ, orijinal uzunluk kalıyor!
        return out;
      };
      const h3 = crypto.createHash(suite.hash);
      h3.update(zeroHeader(this.ch1Wire)); h3.update(zeroHeader(shWire));
      tests['Zeroed_SeqOff_12Byte'] = deriveHandshakeStage({ suite, sharedSecret: this.sharedSecret, transcriptCH_SH: h3.digest() }).clientHandshakeSecret.toString('hex');

      // Senaryo 4: Zeroed DTLS Header (Tamamen frag_len dahil sıfırlanmış)
      const zeroAllHeader = (buf) => {
        const out = Buffer.from(buf);
        out.writeUInt16BE(0, 4); out.writeUInt8(0, 6); out.writeUInt16BE(0, 7);
        out.writeUInt8(0, 9); out.writeUInt16BE(0, 10);
        return out;
      };
      const h4 = crypto.createHash(suite.hash);
      h4.update(zeroAllHeader(this.ch1Wire)); h4.update(zeroAllHeader(shWire));
      tests['Zeroed_All_12Byte'] = deriveHandshakeStage({ suite, sharedSecret: this.sharedSecret, transcriptCH_SH: h4.digest() }).clientHandshakeSecret.toString('hex');

      this.emit('log', 'info', 'CRITICAL_CRYPTO_DEBUG', tests);
    } catch (err) {
      this.emit('log', 'error', 'Detective failed', { err: err.message });
    }
    // --- DEDEKTIF SONU ---

    this.emit('secrets', { stage: 'handshake', keys: this.handshakeKeys, clientRandom: this.clientRandom });
    this.emit('log', 'info', 'DERIVED_KEYS', {
      c_hs_traffic: this.handshakeKeys.clientHandshakeSecret.toString('hex'),
      s_hs_traffic: this.handshakeKeys.serverHandshakeSecret.toString('hex'),
    });

    // Shift send epoch to handshake, start sending encrypted records
    this.sendEpoch = 2; this.sendSeq.set(2, 0);
    this.recvEpoch = 2; this.recvLastSeq.set(2, -1); this.recvReplay.set(2, new ReplayWindow(64));

    // FLIGHT: EE, Cert, CertVerify, Finished (hepsi epoch 2, encrypted)
    const ee = buildEncryptedExtensions([]);
    await this.sendHandshakeMessage(HS_TYPE.ENCRYPTED_EXTENSIONS, ee, { encrypted: true });

    const cert = buildCertificate({ certChainDER: [this.certDER] });
    await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE, cert, { encrypted: true });

    // CertVerify — imza girdisi = transcript(CH..Certificate)
    const thForCV = this.transcript.digest();
    // Algoritma seçimi: client'ın signature_algorithms ile certin anahtar türünü uyum
    const sigSchemeForCert = chooseSigSchemeForKey(this.privateKey);
    const cv = signCertVerify({
      role: 'server', privateKey: this.privateKey,
      sigScheme: sigSchemeForCert, transcriptHash: thForCV,
    });
    await this.sendHandshakeMessage(HS_TYPE.CERTIFICATE_VERIFY, cv, { encrypted: true });

    const thForSF = this.transcript.digest();
    const sfBody = buildFinished({
      hash: suite.hash,
      finishedKey: this.handshakeKeys.serverHandshake.finishedKey,
      transcriptHash: thForSF,
    });
    await this.sendHandshakeMessage(HS_TYPE.FINISHED, sfBody, { encrypted: true });
    // Tüm FLIGHT 4 (SH + EE + Cert + CV + SF) gönderildi, CF'ye kadar retransmit için arm
    this.armRetransmit();

    // Application keys (CH..SF)
    const thAfterSF = this.transcript.digest();
    this.appKeys = deriveApplicationStage({
      suite, handshakeSecret: this.handshakeKeys.handshakeSecret,
      transcriptCH_SF: thAfterSF,
    });
    this.emit('secrets', { stage: 'application', keys: this.appKeys, clientRandom: this.clientRandom });
    // Server'ın send tarafı Client Finished geldikten SONRA app epoch'a geçer.
    this.state = 'WAIT_CF';
  }

  async serverOnCF(m) {
    // CF geldi, server flight 4'ün retransmit'i artık gereksiz
    this.cancelRetransmit();
    // Client Finished verify — transcript m.wire'dan ÖNCE
    const th = this.transcript.digest();
    const fk = this.handshakeKeys.clientHandshake.finishedKey;
    const ok = verifyFinished({ hash: this.suite.hash, finishedKey: fk, transcriptHash: th, received: m.body });
    if (!ok) { this.emit('error', new Error('Client Finished MAC fail')); return; }
    this.transcript.appendDtls(m.wire);

    // Shift server send to application epoch
    this.sendEpoch = 3; this.sendSeq.set(3, 0);
    this.recvEpoch = 3; this.recvLastSeq.set(3, -1); this.recvReplay.set(3, new ReplayWindow(64));
    this.state = 'ESTABLISHED';
    this.emit('handshake');

    // Opsiyonel: server'dan ACK gönder
    this.flushAcks().catch(() => {});
  }

  // ========================================================================
  // Alerts
  // ========================================================================
  sendAlert(level, desc, reason) {
    this.emit('log', 'error', 'sending alert', { level, desc, reason });
    const b = Buffer.from([level, desc]);
    const prom = (this.sendEpoch >= 2 && this.handshakeKeys)
      ? this.sendProtectedRecord(CONTENT_TYPE.ALERT, b)
      : this.sendPlaintextRecord(CONTENT_TYPE.ALERT, b);
    // Fatal alert sonrası session'ı ölü ilan et — server üstten temizler
    if (level === ALERT_LEVEL.FATAL) {
      this.state = 'CLOSED';
      queueMicrotask(() => this.emit('closed', { reason: reason || `alert ${desc}` }));
    }
    return prom;
  }

  // Sunucunun desteklediği gruplardan hangisi hem client supported_groups'ta VAR
  // hem de client'ın key_share entry'si olarak gönderilmiş? (En hızlı yol — HRR'siz)
  // Eğer intersection'da bir şey varsa ama key_share'de yoksa, supported_groups
  // kesişiminden ilkini seç — HRR göndermeye hazır olarak.
  pickGroupFromCH(ch) {
    const sgExt = ch.extensions.find(e => e.type === EXT_TYPE.SUPPORTED_GROUPS);
    if (!sgExt) return null;
    const clientGroups = parse_supportedGroups(sgExt.data);
    const ksExt = ch.extensions.find(e => e.type === EXT_TYPE.KEY_SHARE);
    const ksGroups = ksExt ? parse_keyShareClient(ksExt.data).map(e => e.group) : [];
    const serverPref = [NAMED_GROUP.X25519, NAMED_GROUP.SECP256R1];

    // 1. tercih: key_share'de zaten var + bizim destek listemizde var
    for (const g of serverPref) if (ksGroups.includes(g) && clientGroups.includes(g)) return g;
    // 2. tercih: supported_groups'ta var ama key_share yok → HRR'de isteyeceğiz
    for (const g of serverPref) if (clientGroups.includes(g)) return g;
    return null;
  }

  // Group mismatch için HRR — cookie'siz path. Client'a "şu grubu kullan ve tekrar CH gönder" der.
  async sendGroupHRR(ch, suite) {
    const group = this.chosenGroup ?? this.pickGroupFromCH(ch);
    if (group == null) return this.sendAlert(ALERT_LEVEL.FATAL, ALERT_DESC.HANDSHAKE_FAILURE, 'ortak grup yok');
    this.chosenGroup = group;
    this.ch1Wire = this.ch1Wire || Buffer.from(ch._originalWire || Buffer.alloc(0));

    // Transcript hash of CH1 (message_hash transform için)
    const th = new Transcript(suite.hash); th.appendDtls(this.ch1Wire);
    this.ch1Hash = th.digest();

    // Cookie eklemeden sadece key_share ile HRR gönder (cookie=off)
    const hrrBody = buildServerHello({
      cipherSuite: suite.id,
      extensions: [
        ext_supportedVersionsServer(VERSION.DTLS_1_3),
        ext_keyShareHRR(group),
      ],
      isHRR: true,
    });
    const hrrWire = rebuildSingleFragmentWire(HS_TYPE.SERVER_HELLO, 0, hrrBody);
    this.hrrWire = hrrWire;
    this.messageSeq = 1;
    await this.sendPlaintextRecord(CONTENT_TYPE.HANDSHAKE, hrrWire);
    this.state = 'WAIT_CH2';
    this.emit('log', 'info', '>> HRR (group-only, no cookie)', {
      group: NAMES.NAMED_GROUP[group],
    });
  }
}

// ===== helpers =====
function rebuildSingleFragmentWire(msgType, messageSeq, body) {
  const hdr = Buffer.alloc(12);
  hdr.writeUInt8(msgType, 0);
  hdr.writeUInt8((body.length >> 16) & 0xff, 1);
  hdr.writeUInt16BE(body.length & 0xffff, 2);
  hdr.writeUInt16BE(messageSeq, 4);
  hdr.writeUInt8(0, 6); hdr.writeUInt16BE(0, 7);                  // fragment_offset
  hdr.writeUInt8((body.length >> 16) & 0xff, 9);
  hdr.writeUInt16BE(body.length & 0xffff, 10);                    // fragment_length = length
  return Buffer.concat([hdr, body]);
}

function chooseSigSchemeForKey(privKey) {
  const ko = typeof privKey === 'object' && privKey.asymmetricKeyType ? privKey :
             crypto.createPrivateKey(privKey);
  const type = ko.asymmetricKeyType;
  if (type === 'ec') return SIG_SCHEME.ECDSA_SECP256R1_SHA256;
  if (type === 'ed25519') return SIG_SCHEME.ED25519;
  if (type === 'rsa') return SIG_SCHEME.RSA_PSS_RSAE_SHA256;
  throw new Error(`unsupported key type: ${type}`);
}

module.exports = { Session };
