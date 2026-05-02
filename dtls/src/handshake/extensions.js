'use strict';
// TLS/DTLS 1.3 Extensions — RFC 8446 §4.2, bazı RFC 9147 kısıtlamalarıyla.
//
// Wrapper format:
//   uint16 extension_type
//   opaque extension_data<0..2^16-1>
//
// extensions<8..2^16-1> container: 2-byte total length + back-to-back extensions.

const { EXT_TYPE, VERSION, NAMED_GROUP, SIG_SCHEME, NAMES } = require('../constants.js');

function encodeExtension(type, data) {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type, 0);
  hdr.writeUInt16BE(data.length, 2);
  return Buffer.concat([hdr, data]);
}

function encodeExtensions(exts) {
  const body = Buffer.concat(exts);
  const wrapper = Buffer.alloc(2);
  wrapper.writeUInt16BE(body.length, 0);
  return Buffer.concat([wrapper, body]);
}

function decodeExtensions(buf, offset) {
  const totalLen = buf.readUInt16BE(offset);
  const start = offset + 2;
  const end = start + totalLen;
  if (end > buf.length) throw new Error(`extensions truncated: need ${totalLen}`);
  const extensions = [];
  let o = start;
  while (o < end) {
    if (o + 4 > end) throw new Error('extension header truncated');
    const type = buf.readUInt16BE(o);
    const dataLen = buf.readUInt16BE(o + 2);
    const dataStart = o + 4;
    const dataEnd = dataStart + dataLen;
    if (dataEnd > end) throw new Error(`extension data truncated (type=${type})`);
    extensions.push({
      type,
      typeName: NAMES.EXT_TYPE[type] || `UNKNOWN(${type})`,
      data: buf.slice(dataStart, dataEnd),
    });
    o = dataEnd;
  }
  return { extensions, bytesConsumed: 2 + totalLen };
}

// ============================================================================
// Specific extension builders
// ============================================================================

// supported_versions — client: ProtocolVersion versions<2..254>
// RFC 8446 §4.2.1 — DTLS 1.3 zorunluluğu RFC 9147 §5.3'te.
function ext_supportedVersionsClient(versions = [VERSION.DTLS_1_3]) {
  const listLen = versions.length * 2;
  const body = Buffer.alloc(1 + listLen);
  body.writeUInt8(listLen, 0);
  versions.forEach((v, i) => body.writeUInt16BE(v, 1 + i * 2));
  return encodeExtension(EXT_TYPE.SUPPORTED_VERSIONS, body);
}

// server: tek seçilmiş versiyon
function ext_supportedVersionsServer(version = VERSION.DTLS_1_3) {
  const body = Buffer.alloc(2);
  body.writeUInt16BE(version, 0);
  return encodeExtension(EXT_TYPE.SUPPORTED_VERSIONS, body);
}

// supported_groups — NamedGroup named_group_list<2..2^16-1>
function ext_supportedGroups(groups = [NAMED_GROUP.X25519, NAMED_GROUP.SECP256R1]) {
  const list = Buffer.alloc(groups.length * 2);
  groups.forEach((g, i) => list.writeUInt16BE(g, i * 2));
  const body = Buffer.alloc(2 + list.length);
  body.writeUInt16BE(list.length, 0);
  list.copy(body, 2);
  return encodeExtension(EXT_TYPE.SUPPORTED_GROUPS, body);
}

// signature_algorithms — SignatureScheme supported_signature_algorithms<2..2^16-2>
function ext_signatureAlgorithms(schemes = [
  SIG_SCHEME.ECDSA_SECP256R1_SHA256,
  SIG_SCHEME.RSA_PSS_RSAE_SHA256,
  SIG_SCHEME.ED25519,
  SIG_SCHEME.RSA_PKCS1_SHA256, // cert-only ama genelde gerekir
]) {
  const list = Buffer.alloc(schemes.length * 2);
  schemes.forEach((s, i) => list.writeUInt16BE(s, i * 2));
  const body = Buffer.alloc(2 + list.length);
  body.writeUInt16BE(list.length, 0);
  list.copy(body, 2);
  return encodeExtension(EXT_TYPE.SIGNATURE_ALGORITHMS, body);
}

// key_share (client) — KeyShareEntry client_shares<0..2^16-1>
// KeyShareEntry = { NamedGroup group, opaque key_exchange<1..2^16-1> }
function ext_keyShareClient(entries /* [{ group, keyExchange: Buffer }] */) {
  const parts = entries.map(({ group, keyExchange }) => {
    const head = Buffer.alloc(4);
    head.writeUInt16BE(group, 0);
    head.writeUInt16BE(keyExchange.length, 2);
    return Buffer.concat([head, keyExchange]);
  });
  const list = Buffer.concat(parts);
  const body = Buffer.alloc(2 + list.length);
  body.writeUInt16BE(list.length, 0);
  list.copy(body, 2);
  return encodeExtension(EXT_TYPE.KEY_SHARE, body);
}

// key_share (server) — tek KeyShareEntry
function ext_keyShareServer({ group, keyExchange }) {
  const body = Buffer.alloc(4 + keyExchange.length);
  body.writeUInt16BE(group, 0);
  body.writeUInt16BE(keyExchange.length, 2);
  keyExchange.copy(body, 4);
  return encodeExtension(EXT_TYPE.KEY_SHARE, body);
}

// key_share (HRR) — sadece selected_group (RFC 8446 §4.2.8)
function ext_keyShareHRR(group) {
  const body = Buffer.alloc(2);
  body.writeUInt16BE(group, 0);
  return encodeExtension(EXT_TYPE.KEY_SHARE, body);
}

// ---------- PARSE helpers (sunucu tarafında ClientHello içindeki ext'leri çözmek için)

// supported_versions (client) -> number[]
function parse_supportedVersionsClient(data) {
  const listLen = data.readUInt8(0);
  if (1 + listLen > data.length) throw new Error('supported_versions truncated');
  if (listLen % 2) throw new Error('odd supported_versions length');
  const out = [];
  for (let i = 0; i < listLen; i += 2) out.push(data.readUInt16BE(1 + i));
  return out;
}

function parse_supportedGroups(data) {
  const listLen = data.readUInt16BE(0);
  if (listLen % 2) throw new Error('odd supported_groups length');
  const out = [];
  for (let i = 0; i < listLen; i += 2) out.push(data.readUInt16BE(2 + i));
  return out;
}

function parse_signatureAlgorithms(data) {
  const listLen = data.readUInt16BE(0);
  if (listLen % 2) throw new Error('odd signature_algorithms length');
  const out = [];
  for (let i = 0; i < listLen; i += 2) out.push(data.readUInt16BE(2 + i));
  return out;
}

// key_share (client) -> [{ group, keyExchange }]
function parse_keyShareClient(data) {
  const total = data.readUInt16BE(0);
  let o = 2;
  const end = 2 + total;
  const entries = [];
  while (o < end) {
    const group = data.readUInt16BE(o); o += 2;
    const keLen = data.readUInt16BE(o); o += 2;
    const keyExchange = data.slice(o, o + keLen); o += keLen;
    entries.push({ group, keyExchange });
  }
  return entries;
}

// key_share (server/HRR tarafında parse) — HRR ise 2 byte, SH ise KeyShareEntry
function parse_keyShareServer(data) {
  if (data.length === 2) return { kind: 'hrr', selectedGroup: data.readUInt16BE(0) };
  const group = data.readUInt16BE(0);
  const keLen = data.readUInt16BE(2);
  const keyExchange = data.slice(4, 4 + keLen);
  return { kind: 'sh', group, keyExchange };
}

function parse_serverName(data) {
  const listLen = data.readUInt16BE(0);
  let o = 2;
  const end = 2 + listLen;
  const names = [];
  while (o < end) {
    const nameType = data.readUInt8(o); o += 1;
    const nameLen  = data.readUInt16BE(o); o += 2;
    const name     = data.slice(o, o + nameLen); o += nameLen;
    names.push({ nameType, name: nameType === 0 ? name.toString('utf8') : name });
  }
  return names;
}

function parse_cookie(data) {
  const len = data.readUInt16BE(0);
  return data.slice(2, 2 + len);
}

// server_name (SNI) — RFC 6066 §3
// ServerName server_name_list<1..2^16-1>
// ServerName = { NameType name_type; HostName host_name<1..2^16-1> }
function ext_serverName(hostname) {
  const nameBuf = Buffer.from(hostname, 'utf8');
  const entry = Buffer.alloc(1 + 2 + nameBuf.length);
  entry.writeUInt8(0x00, 0); // name_type = host_name
  entry.writeUInt16BE(nameBuf.length, 1);
  nameBuf.copy(entry, 3);
  const body = Buffer.alloc(2 + entry.length);
  body.writeUInt16BE(entry.length, 0);
  entry.copy(body, 2);
  return encodeExtension(EXT_TYPE.SERVER_NAME, body);
}

// cookie — RFC 8446 §4.2.2 (HelloRetryRequest / ikinci ClientHello'da)
function ext_cookie(cookie) {
  const body = Buffer.alloc(2 + cookie.length);
  body.writeUInt16BE(cookie.length, 0);
  cookie.copy(body, 2);
  return encodeExtension(EXT_TYPE.COOKIE, body);
}

// psk_key_exchange_modes — RFC 8446 §4.2.9
function ext_pskKeyExchangeModes(modes = [0x01] /* psk_dhe_ke */) {
  const body = Buffer.alloc(1 + modes.length);
  body.writeUInt8(modes.length, 0);
  for (let i = 0; i < modes.length; i++) body.writeUInt8(modes[i], 1 + i);
  return encodeExtension(EXT_TYPE.PSK_KEY_EXCHANGE_MODES, body);
}

module.exports = {
  encodeExtension, encodeExtensions, decodeExtensions,
  ext_supportedVersionsClient, ext_supportedVersionsServer,
  ext_supportedGroups, ext_signatureAlgorithms,
  ext_keyShareClient, ext_keyShareServer, ext_keyShareHRR,
  ext_serverName, ext_cookie, ext_pskKeyExchangeModes,
  // parsers
  parse_supportedVersionsClient, parse_supportedGroups, parse_signatureAlgorithms,
  parse_keyShareClient, parse_keyShareServer,
  parse_serverName, parse_cookie,
};
