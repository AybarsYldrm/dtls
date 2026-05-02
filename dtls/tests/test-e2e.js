#!/usr/bin/env node
'use strict';
// Full E2E — Phase 3+4:
//   1) Client ↔ Server full TLS 1.3 handshake (HRR + ECDHE + Cert + CertVerify + Finished)
//   2) Application data round-trip (client→server, server echoes back)
//   3) KeyUpdate (client-initiated, send epoch +1)
//   4) Replay window — aynı recorde iki kez beslendiğinde ikinci kez reject

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { UdpEndpoint } = require('../src/transport');
const { Session } = require('../src/session/session.js');
const { ReplayWindow } = require('../src/record/replay-window.js');

process.env.DTLS_LOG_LEVEL = process.env.DTLS_LOG_LEVEL || 'ERROR';

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

async function main() {
  const root = path.resolve(__dirname, '..');
  const certPEM = fs.readFileSync(path.join(root, 'certs/server.pem'), 'utf8');
  const keyPEM  = fs.readFileSync(path.join(root, 'certs/server.key'), 'utf8');
  const certDER = pemToDer(certPEM);
  const privateKey = crypto.createPrivateKey({ key: keyPEM, format: 'pem' });

  const port = 18000 + Math.floor(Math.random() * 1000);
  const serverEp = new UdpEndpoint({ logComponent: 'srv-udp' });
  await serverEp.bind(port, '127.0.0.1');

  const clientEp = new UdpEndpoint({ logComponent: 'cli-udp' });
  await clientEp.bind(0, '127.0.0.1');

  const serverSessions = new Map();
  let serverSide = null;
  serverEp.on('datagram', (dg, rinfo) => {
    const key = `${rinfo.address}:${rinfo.port}`;
    let s = serverSessions.get(key);
    if (!s) {
      s = new Session({
        role: 'server', transport: serverEp, peer: { address: rinfo.address, port: rinfo.port },
        certDER, privateKey, cookieRequired: true,
      });
      s.on('error', (e) => console.error('[server err]', e.message));
      s.on('data', (buf) => {
        // echo back
        s.sendApplicationData(Buffer.from(`echo:${buf.toString('utf8')}`))
          .catch(e => console.error('echo err', e));
      });
      serverSessions.set(key, s);
      serverSide = s;
    }
    s.handleDatagram(dg, rinfo);
  });

  const client = new Session({
    role: 'client', transport: clientEp,
    peer: { address: '127.0.0.1', port }, sni: 'localhost',
  });
  client.on('error', (e) => { console.error('[client err]', e.message, e.stack); process.exit(1); });
  clientEp.on('datagram', (dg, rinfo) => client.handleDatagram(dg, rinfo));

  const handshakeDone = new Promise((res) => client.on('handshake', res));
  await client.clientStart();
  await handshakeDone;

  console.log('  ✓ handshake established (client)');

  // App data
  const echoP = new Promise((res) => client.once('data', res));
  await client.sendApplicationData(Buffer.from('ping'));
  const echoed = await echoP;
  assert.equal(echoed.toString('utf8'), 'echo:ping');
  console.log('  ✓ app data round-trip (ping → echo:ping)');

  // KeyUpdate
  const beforeEpoch = client.sendEpoch;
  await client.requestKeyUpdate(false);
  // Biraz bekle ki server'ın recv tarafı da advance etsin
  await new Promise(r => setTimeout(r, 50));
  assert.equal(client.sendEpoch, beforeEpoch + 1);
  console.log(`  ✓ client KeyUpdate — send epoch ${beforeEpoch} → ${client.sendEpoch}`);

  // Yeni epoch'ta da veri gönder
  const echoP2 = new Promise((res) => client.once('data', res));
  await client.sendApplicationData(Buffer.from('post-keyupdate'));
  const echo2 = await echoP2;
  assert.equal(echo2.toString('utf8'), 'echo:post-keyupdate');
  console.log('  ✓ app data after KeyUpdate');

  // Replay window standalone test
  const w = new ReplayWindow(64);
  assert.equal(w.accept(0), true);
  assert.equal(w.accept(0), false);       // tekrar
  assert.equal(w.accept(5), true);
  assert.equal(w.accept(3), true);        // out-of-order ama pencere içinde
  assert.equal(w.accept(3), false);
  assert.equal(w.accept(200), true);      // ileri sıçrama
  assert.equal(w.accept(5), false);       // artık pencere dışı
  console.log('  ✓ replay window invariants');

  await clientEp.close();
  await serverEp.close();
  console.log('\n[full-e2e] ALL OK — Phase 3+4 ✓');
  process.exit(0);
}

main().catch((e) => { console.error('[full-e2e] fatal', e); process.exit(1); });
