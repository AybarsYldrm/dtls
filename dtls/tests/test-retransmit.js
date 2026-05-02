#!/usr/bin/env node
'use strict';
// Retransmit test — paket kaybı simülasyonu.
//
// Server'ın FLIGHT 2 (HRR) veya FLIGHT 4 (SH+...) ilk datagram'ını düşürürüz.
// Bizim retransmit timer'ı çalışmalı ve handshake ikinci denemede tamamlanmalı.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dgram = require('node:dgram');
const assert = require('node:assert/strict');
const { UdpEndpoint } = require('../src/transport');
const { Session } = require('../src/session/session');

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

  const realServerPort = 20001 + Math.floor(Math.random() * 300);
  const proxyPort = realServerPort + 1;

  // Gerçek server
  const serverEp = new UdpEndpoint({ logComponent: 'srv' });
  await serverEp.bind(realServerPort, '127.0.0.1');
  let serverSession = null;
  serverEp.on('datagram', (dg, rinfo) => {
    if (!serverSession) {
      serverSession = new Session({
        role: 'server', transport: serverEp,
        peer: { address: rinfo.address, port: rinfo.port },
        certDER, privateKey, cookieRequired: false,
      });
      serverSession.on('error', (e) => console.error('[srv err]', e.message));
    }
    serverSession.handleDatagram(dg, rinfo);
  });

  // Proxy: client ↔ proxy ↔ server. Server'dan client'a giden İLK datagram'ı düşür.
  const proxyToClient = dgram.createSocket('udp4');
  await new Promise(res => proxyToClient.bind(proxyPort, '127.0.0.1', res));
  let serverRxCount = 0;
  let clientAddr = null;

  proxyToClient.on('message', (msg, rinfo) => {
    if (rinfo.port === realServerPort) {
      // server → proxy → client
      serverRxCount += 1;
      if (serverRxCount === 1) {
        console.log(`  → server FLIGHT 1 datagram DROPPED (simulated loss)`);
        return; // DROP
      }
      proxyToClient.send(msg, clientAddr.port, clientAddr.address);
    } else {
      // client → proxy → server
      clientAddr = { address: rinfo.address, port: rinfo.port };
      proxyToClient.send(msg, realServerPort, '127.0.0.1');
    }
  });

  // Client proxy'ye bağlanıyor
  const clientEp = new UdpEndpoint({ logComponent: 'cli' });
  await clientEp.bind(0, '127.0.0.1');
  const client = new Session({
    role: 'client', transport: clientEp,
    peer: { address: '127.0.0.1', port: proxyPort }, sni: 'localhost',
  });
  client.on('error', e => { console.error('[cli err]', e.message); process.exit(1); });
  clientEp.on('datagram', (dg, r) => client.handleDatagram(dg, r));

  // Retransmit base'i testte hızlandır
  const origArm = client.armRetransmit.bind(client);
  client.armRetransmit = () => origArm(200); // 200ms
  const origArmSrv = Session.prototype.armRetransmit;
  // Server session da hızlandırılsın — serverSession henüz yok, monkey-patch et:
  setTimeout(() => {
    if (serverSession) {
      const a = serverSession.armRetransmit.bind(serverSession);
      serverSession.armRetransmit = () => a(200);
    }
  }, 50);

  const handshakeP = new Promise(res => client.on('handshake', res));
  const timeout = new Promise((_, rej) =>
    setTimeout(() => rej(new Error('handshake timeout — retransmit çalışmadı')), 5000));

  await client.clientStart();
  await Promise.race([handshakeP, timeout]);
  console.log('  ✓ handshake kurtarıldı (retransmit ile)');

  // App data hâlâ gidiyor
  const echoP = new Promise(res => {
    serverSession.on('data', (buf) => {
      serverSession.sendApplicationData(Buffer.from(`echo:${buf.toString('utf8')}`));
    });
    client.once('data', res);
  });
  await client.sendApplicationData(Buffer.from('survived'));
  const echoed = await echoP;
  assert.equal(echoed.toString('utf8'), 'echo:survived');
  console.log('  ✓ app data round-trip after retransmit');

  await clientEp.close();
  await serverEp.close();
  proxyToClient.close();
  console.log('\n[retransmit] ALL OK ✓');
}

main().catch(e => { console.error('fatal', e); process.exit(1); });
