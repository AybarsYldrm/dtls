#!/usr/bin/env node
'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { UdpEndpoint } = require('./src/transport');
const { Session } = require('./src/session/session.js');
const { mk } = require('./src/logger.js');
const log = mk('server');

const HOST = process.env.DTLS_HOST || '94.138.209.225';
const PORT = Number(process.env.DTLS_PORT || 4444);
const COOKIE_REQUIRED = process.env.DTLS_COOKIE !== '0';
const CERT_PATH = process.env.DTLS_CERT || path.join(__dirname, 'certs/server.pem');
const KEY_PATH  = process.env.DTLS_KEY  || path.join(__dirname, 'certs/server.key');
const { RateLimiter } = require('./src/session/rate-limit.js');
const { attachKeyLog } = require('./src/session/keylog.js');
const KEYLOG = process.env.SSLKEYLOGFILE || null;

async function loadOrGenCert() {
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    const pemCert = fs.readFileSync(CERT_PATH, 'utf8');
    const keyPem  = fs.readFileSync(KEY_PATH,  'utf8');
    const certDER = pemToDer(pemCert);
    const privateKey = crypto.createPrivateKey({ key: keyPem, format: 'pem' });
    return { certDER, privateKey };
  }
  // Fallback: self-signed P-256 ephemeral
  log.warn('sertifika yok, ephemeral self-signed ECDSA P-256 üretiyorum');
  const { certDER, privateKey } = makeEphemeralCert();
  return { certDER, privateKey };
}

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

function makeEphemeralCert() {
  // Basit yaklaşım: node:crypto X509 oluşturucu yerleşik değil. Minimal DER kendi elde.
  // Burada openssl yokken test için: generateKeyPairSync + node-forge olmadan
  // self-signed cert üretmek complex. Çözüm: node 20+ 'de crypto.X509Certificate parse
  // edebiliyor ama üretemiyor. Fallback: pre-generated ephemeral via openssl script.
  throw new Error('Lütfen `npm run certs` ile sertifika üret (openssl gerekli).');
}

async function main() {
  const { certDER, privateKey } = await loadOrGenCert();
  const ep = new UdpEndpoint({ logComponent: 'udp' });
  await ep.bind(PORT, HOST);
  log.info('listening', { host: HOST, port: PORT, cookie: COOKIE_REQUIRED });

  const sessions = new Map();
  const limiter = new RateLimiter({ capacity: 20, refillPerSec: 10 });

  ep.on('datagram', (dg, rinfo) => {
    const key = `${rinfo.address}:${rinfo.port}`;
    if (!limiter.allow(key)) { log.warn('rate-limited', { peer: key }); return; }
    let s = sessions.get(key);
    if (!s) {
      s = new Session({
        role: 'server', transport: ep,
        peer: { address: rinfo.address, port: rinfo.port },
        certDER, privateKey,
        cookieRequired: COOKIE_REQUIRED,
      });
      wireLogs(s, 'srv');
      if (KEYLOG) attachKeyLog(s, KEYLOG);
      s.on('handshake', () => log.info('handshake ESTABLISHED', { peer: key }));
      s.on('data', (buf) => {
        log.info('app data rx', { peer: key, bytes: buf.length, text: buf.toString('utf8').slice(0, 80) });
        s.sendApplicationData(Buffer.from(`echo:${buf.toString('utf8')}`))
          .catch(e => log.error('echo send failed', { peer: key, err: e.message }));
      });
      // Session error'ı SADECE bu session'ı etkiler — server ayakta kalır
      s.on('error', (e) => {
        log.error('session error', { peer: key, err: e.message });
        cleanupSession(key);
      });
      s.on('closed', ({ reason }) => {
        log.info('session closed', { peer: key, reason });
        cleanupSession(key);
      });
      sessions.set(key, s);
    }
    // Defensive: handleDatagram içinde throw olursa session'ı temizle, server'ı yaşat
    try { s.handleDatagram(dg, rinfo); }
    catch (e) {
      log.error('datagram handler threw', { peer: key, err: e.message, stack: e.stack });
      cleanupSession(key);
    }
  });

  function cleanupSession(key) {
    const s = sessions.get(key);
    if (!s) return;
    sessions.delete(key);
    // state'i CLOSED yap, pending timer'ları iptal et
    try { s.removeAllListeners(); } catch {}
  }

  // Son emniyet ağı — bir session içinde async throw olursa tüm process'i düşürmemek için
  process.on('uncaughtException', (e) => {
    log.error('uncaughtException (yakalandı, server ayakta)', { err: e.message, stack: e.stack });
  });
  process.on('unhandledRejection', (e) => {
    log.error('unhandledRejection (yakalandı)', { err: e && e.message, stack: e && e.stack });
  });

  process.on('SIGINT', () => { log.warn('SIGINT'); ep.close().then(() => process.exit(0)); });
  setInterval(() => limiter.sweep(), 30_000).unref();

  // Idle session cleanup — 5 dk boyunca datagram gelmeyen session'ları at
  setInterval(() => {
    const now = Date.now();
    for (const [k, s] of sessions) {
      if (s.state === 'CLOSED' || now - (s.createdAt || now) > 300_000) cleanupSession(k);
    }
  }, 60_000).unref();
}

function wireLogs(s, tag) {
  s.on('log', (lvl, msg, meta) => (log[lvl] || log.info)(`[${tag}] ${msg}`, meta));
}

main().catch((e) => { log.error('fatal', { err: e.message, stack: e.stack }); process.exit(1); });
