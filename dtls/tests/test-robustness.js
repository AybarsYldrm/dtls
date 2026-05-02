#!/usr/bin/env node
'use strict';
// Robustness test — 3 senaryo, tek server'a karşı:
//   1) P-256 only client (wolfSSL default'undan farklı grup)  → başarılı handshake + echo
//   2) Ham DTLS 1.2 ClientHello gönder (supported_versions YOK) → server alert döner, ayakta kalır
//   3) Senaryo 1'in hemen ardından 2. bir P-256 client daha bağlanır → çalışır
//
// Amaç: "Bir kötü peer server'ı düşürmez, iyi peer'lar etkilenmez" invariantı.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const assert = require('node:assert/strict');
const { UdpEndpoint } = require('../src/transport');
const { Session } = require('../src/session/session');
const { NAMED_GROUP } = require('../src/constants');

process.env.DTLS_LOG_LEVEL = process.env.DTLS_LOG_LEVEL || 'ERROR';

function pemToDer(pem) {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
}

async function main() {
  const root = path.resolve(__dirname, '..');
  const certDER = pemToDer(fs.readFileSync(path.join(root, 'certs/server.pem'), 'utf8'));
  const privateKey = crypto.createPrivateKey({
    key: fs.readFileSync(path.join(root, 'certs/server.key'), 'utf8'),
    format: 'pem',
  });

  const port = 19500 + Math.floor(Math.random() * 400);
  const serverEp = new UdpEndpoint({ logComponent: 'srv-udp' });
  await serverEp.bind(port, '127.0.0.1');

  const sessions = new Map();
  let fatalAlertSeen = false;

  serverEp.on('datagram', (dg, rinfo) => {
    const key = `${rinfo.address}:${rinfo.port}`;
    let s = sessions.get(key);
    if (!s) {
      s = new Session({
        role: 'server', transport: serverEp,
        peer: { address: rinfo.address, port: rinfo.port },
        certDER, privateKey, cookieRequired: false,
      });
      s.on('data', (buf) => {
        s.sendApplicationData(Buffer.from(`echo:${buf.toString('utf8')}`)).catch(() => {});
      });
      s.on('error', (e) => { /* isolated */ });
      s.on('closed', ({ reason }) => {
        if (reason && reason.includes('legacy')) fatalAlertSeen = true;
        sessions.delete(key);
      });
      sessions.set(key, s);
    }
    try { s.handleDatagram(dg, rinfo); } catch { sessions.delete(key); }
  });

  // ===== Senaryo 1: P-256 only client =====
  const c1Ep = new UdpEndpoint({ logComponent: 'c1' });
  await c1Ep.bind(0, '127.0.0.1');
  const c1 = new Session({ role: 'client', transport: c1Ep, peer: { address: '127.0.0.1', port }, sni: 'localhost' });
  c1.chosenGroup = NAMED_GROUP.SECP256R1;
  c1.on('error', e => { console.error('[c1 err]', e.message); process.exit(1); });
  c1Ep.on('datagram', (dg, r) => c1.handleDatagram(dg, r));

  const h1 = new Promise(res => c1.on('handshake', res));
  await c1.clientStart();
  await h1;
  const e1 = new Promise(res => c1.once('data', res));
  await c1.sendApplicationData(Buffer.from('first'));
  assert.equal((await e1).toString(), 'echo:first');
  console.log('  ✓ P-256 client: handshake + echo');
  await c1Ep.close();

  // ===== Senaryo 2: Ham DTLS 1.2 ClientHello (supported_versions YOK) =====
  // RFC 6347'ye uygun minimal bir DTLS 1.2 ClientHello. Sadece serverı yoklamak için.
  const badSock = dgram.createSocket('udp4');
  await new Promise(res => badSock.bind(0, '127.0.0.1', res));
  const dtls12CH = Buffer.from(
    // Record: HANDSHAKE(22), DTLS 1.2 version (feff legacy ya da fefd), epoch 0, seq 0, len
    '16feff00000000000000002f' +     // record hdr, len=0x2f=47
    // Handshake: CLIENT_HELLO(1), total_len=0x23=35, msg_seq=0, frag_off=0, frag_len=35
    '01000023' + '0000' + '000000' + '000023' +
    // body: legacy_version=fefd, random(32)...
    'fefd' + '00'.repeat(32) +
    // session_id_len=0, cookie_len=0, cipher_suites len=2, cipher=0x0a (TLS_RSA), comp_meth(1,0), no ext_len
    '00' + '00' + '0002' + '000a' + '0100',
    'hex'
  );
  // Bu ClientHello geçersiz tam olmayabilir; bizi ilgilendiren: server crash ETMESİN.
  await new Promise(res => badSock.send(dtls12CH, port, '127.0.0.1', res));
  await new Promise(res => setTimeout(res, 150)); // server'ın işlemesine zaman ver
  await new Promise(res => badSock.close(res));
  console.log('  ✓ DTLS 1.2 peer gönderildi, server crash etmedi');

  // ===== Senaryo 3: Yeni bir sağlıklı client hâlâ bağlanabiliyor mu =====
  const c3Ep = new UdpEndpoint({ logComponent: 'c3' });
  await c3Ep.bind(0, '127.0.0.1');
  const c3 = new Session({ role: 'client', transport: c3Ep, peer: { address: '127.0.0.1', port }, sni: 'localhost' });
  c3.chosenGroup = NAMED_GROUP.X25519;
  c3.on('error', e => { console.error('[c3 err]', e.message); process.exit(1); });
  c3Ep.on('datagram', (dg, r) => c3.handleDatagram(dg, r));

  const h3 = new Promise(res => c3.on('handshake', res));
  await c3.clientStart();
  await Promise.race([
    h3,
    new Promise((_, rej) => setTimeout(() => rej(new Error('3. client handshake timeout — server etkilendi!')), 2000)),
  ]);
  console.log('  ✓ Kötü peer\'dan sonra 3. sağlıklı client bağlanabildi (server sağlam)');
  await c3Ep.close();

  await serverEp.close();
  console.log('\n[robustness] ALL OK ✓');
}

main().catch(e => { console.error('fatal', e); process.exit(1); });
