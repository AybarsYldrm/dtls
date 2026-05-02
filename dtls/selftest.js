// Self-test: ClientHello üret, binary'e yaz, tekrar parse et — roundtrip doğrula.
const crypto = require('node:crypto');
const {
  buildClientHello, parseClientHello, encodeHandshake, decodeHandshake,
  ext_supportedVersionsClient, ext_supportedGroups, ext_signatureAlgorithms,
  ext_keyShareClient, ext_serverName,
} = require('./src/handshake');
const { encodePlaintext, decodePlaintext, parseDatagram } = require('./src/record');
const { CONTENT_TYPE, HS_TYPE, NAMED_GROUP } = require('./src/constants.js');

const kp = crypto.generateKeyPairSync('x25519');
const pubRaw = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url');

const chBody = buildClientHello({
  extensions: [
    ext_serverName('localhost'),
    ext_supportedVersionsClient(),
    ext_supportedGroups([NAMED_GROUP.X25519]),
    ext_signatureAlgorithms(),
    ext_keyShareClient([{ group: NAMED_GROUP.X25519, keyExchange: pubRaw }]),
  ],
});
const hsWire = encodeHandshake({ msgType: HS_TYPE.CLIENT_HELLO, messageSeq: 0, body: chBody });
const record = encodePlaintext({ type: CONTENT_TYPE.HANDSHAKE, sequenceNumber: 0, fragment: hsWire });

console.log('✓ encode: record = %d bytes', record.length);

const recs = parseDatagram(record);
console.log('✓ parseDatagram: %d record(s)', recs.length);
const hs = decodeHandshake(recs[0].fragment);
console.log('✓ handshake: type=%s seq=%d fraglen=%d complete=%s',
  hs.msgTypeName, hs.messageSeq, hs.fragmentLength, hs.isComplete);

const parsed = parseClientHello(hs.body);
console.log('✓ ClientHello: %d cipher_suites, %d extensions, legacyCookie=%d',
  parsed.cipherSuites.length, parsed.extensions.length, parsed.legacyCookie.length);

console.log('  suites:', parsed.cipherSuites.map(c => c.name).join(', '));
console.log('  exts:', parsed.extensions.map(e => e.typeName).join(', '));

// Full roundtrip: re-encode ve karşılaştır
const rebuilt = buildClientHello({
  random: parsed.random,
  sessionId: parsed.sessionId,
  cipherSuites: parsed.cipherSuites.map(c => c.value),
  extensions: parsed.extensions.map(e => {
    const b = Buffer.alloc(4 + e.data.length);
    b.writeUInt16BE(e.type, 0);
    b.writeUInt16BE(e.data.length, 2);
    e.data.copy(b, 4);
    return b;
  }),
});
console.log('✓ roundtrip: original=%d rebuilt=%d match=%s',
  chBody.length, rebuilt.length, chBody.equals(rebuilt));
