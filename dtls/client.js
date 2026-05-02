#!/usr/bin/env node
'use strict';
const { UdpEndpoint } = require('./src/transport');
const { Session } = require('./src/session/session.js');
const { attachKeyLog } = require('./src/session/keylog.js');
const { mk } = require('./src/logger.js');
const log = mk('client');

const HOST = process.env.DTLS_HOST || '185.95.164.233';
const PORT = Number(process.env.DTLS_PORT || 4444);
const SNI  = process.env.DTLS_SNI  || 'nat.intranet.fitfak.net';
const KEYLOG = process.env.SSLKEYLOGFILE || null;

async function main() {
  const ep = new UdpEndpoint({ logComponent: 'udp' });
  await ep.bind(0, '0.0.0.0');
  const s = new Session({
    role: 'client', transport: ep, peer: { address: HOST, port: PORT }, sni: SNI,
  });
  if (KEYLOG) { attachKeyLog(s, KEYLOG); log.info('keylog enabled', { file: KEYLOG }); }
  s.on('peer-cert', (info) => {
    log.info('peer certificate', {
      subject: info.subject, issuer: info.issuer,
      validFrom: info.validFrom, validTo: info.validTo,
      fingerprint256: info.fingerprint256,
      san: info.subjectAltName, keyType: info.keyType,
      chainLen: info.chain.length,
    });
  });
  s.on('log', (lvl, msg, meta) => (log[lvl] || log.info)(msg, meta));
  s.on('handshake', async () => {
    log.info('Handshake tamamlandı!', { 
        chosenSuite: s.suite.name // s.suite içindeki meta veriyi yazdırır
    });
    await s.sendApplicationData(Buffer.from('hello DTLS 1.3'));
  });
  s.on('data', (buf) => {
    log.info('<< app data', { text: buf.toString('utf8') });
    // Bir KeyUpdate denemesi
    s.requestKeyUpdate(false).then(() => {
      log.info('KeyUpdate sent');
      setTimeout(() => ep.close().then(() => process.exit(0)), 500);
    });
  });
  s.on('error', (e) => { log.error('error', { err: e.message, stack: e.stack }); process.exit(2); });
  ep.on('datagram', (dg, rinfo) => s.handleDatagram(dg, rinfo));
  await s.clientStart();
}

main().catch((e) => { log.error('fatal', { err: e.message, stack: e.stack }); process.exit(1); });
