const crypto = require('crypto');

// Loglarından birebir alınmış 07:42 oturumu verileri:
const ch1Hex = "010005810000000000000581fefd9370e2148e95f3f42d0049d820ba9f0ef2922eb9d9ab6bb93974e2ec859f198f0000000613021303130101000551000b00020100000a0012001011ec001d0017001e0018001901000101002300000016000000170000000d002a002809050906090404030503060308070808081a081b081c0809080a080b080408050806040105010601002b000302fefc002d00020101003304ea04e811ec04c024c05b3de444a7a234d53c480198a07a665e25f29ccd63584637b8f948b197555fa5c3a642a4660f508fbf524191d16ece982504b81a711788ff91435adca6f32a2fd1d16cd202a823f3c81d3aa5e091064853622d5c1043233690995adcca86f45752b7d226c8b559be54bbc04a4f5b063dd3f28f0e19cda43492913bb947a830a5c7cb92156ddc503c748c23f2159c7f599ccc09c2c79a29dac56cf765b970213b4413c986f636e27623dd3bbe2ebc4ecd3b021ad4637eb67669bc874538336fdbcfca145658bb7ac33850ae3354b5fa9d7c72c4126a4ab3597654201df5f29f9b1467d8fa936ab62a25ca75e0950694c36a7f2748610a1b9f29ab3f2b3483565bb3c595299a53fb18cabc9424de60c17886409a2c57e8416793a7b82336491cdb0375632d8692898494233d803272676919ba65a4fc63788358390792b330a96e1c36a2b3851568849a1b3119bcc70979036fc7cdc6560555eb5edc6904121452afb2a8aa30ac6d7aa6830913dd932b9d3a859eeb8aa943795e196e51109d4d11b3ff021f5ce130ef2a409778c090b37626402c948b97b79432ce098a9a8712602482c95ca793024fc460b9be413398f3a7ae202cbb2c35c7724b5ef099d6bbce7fe19816c84c90e004765c28575791b58312fa3ca1d59b92249936d9272b603199cfc02c5828aea02a70dd380bcbf50fef17b3cc88880ccac83cc24ea713ca4ca88dfda08e6a93cd98e9c0c286af8248138dc6c3b7c47927085540ea2dbc5cb6999126be7738d7d3ad6365ccce17cec4e287b2b85ccfa4684fc04db1ab3fc4c83b4767205682585a61c34e5134ab80b45246cd480b02b8e344d5b45755eb2f8580ae0b352a02eb36c46a38d376905f849368d7799e07cd69624759f476cd9a4c0b32a14e2587e9fa8187d92641a4a8b9292d30446fe6101816945a4461617819ac84d79dc269215af2a3d3c84ad2e12f64737b9adb1ab5719a876bce3d75b1442a3609761507c8a474c45efe674b89f01cadf446008a8dcf478e1d004db0024e80d35789a9a1e87986631bbea02a92e0a633f9644708a9c03336970c6636c2b67e295266a2a2081ca5c0a795b09b2320848495c840a13236c4058c205a572b58c99e9bab22de67ade35cb3e0883105ac20de958ade36739819affb43412a82c946c45d9f400da60388b8ba56ee7306e28253ad507adaf03d8d31619fa170ba16b6b14a92b656bdcd0758231180be522a379a6143765cdfb800f8a2223de54c6de02cfcb8c59f64252dd00286322ddf298b4b24a33075572d5aa834a923f735c5332bbbc285932645a4426b3526e142469597ee1830f3043c8127c6b5316c8c127d5cb30fe50b21cf260acfc62f2c75b6ada3521d299fc51cb7e189c61fc914677a930bd54beed46d74370e0c54c8e9fa72d1c0c0dbd67cbec029c5664aeab686d8613c6702a30af28bbe17059ef1158c300f63f1cad194c81128693232240bd128d71b20c7f9681db3482557c442f5a0245396885b06b1e710a0c135e6e41255336d8897c89fc4a56df4059d1018ac2bbf8a3a454f124483e6bf26341695782c0bea46a66b378f4111387a35323867a320187c712757b91c9a7101d67b5e458ca82bdc03a5d40a9011c488234babae515503150c3a4d98066d109d93afc2ae2575b618878a6b1a1381bbd27efc93933d15f4d6dfb01ef53c66f38bdf9b5f";
const sh1Hex = "020000560000000000000056fefde6a48775892622e25c3a4eaf9afa26a1d6355ab616542016057d0ce51b3d393a00130100002e002b0002fefc00330024001d0020e6ccf8aafb26fd7cd6544501b95198d56bdd5a92dee6e1b5d1a2917831c1742e";
const sharedHex = "f4064c81ceae3a53020a5d03f511c79cffcd09721c76fdca8ea61d1a7a713e30";

// OpenSSL'in tam olarak beklediği (logladığı) değer:
const expectedSecret = "586577f1d190676ba28cd1c2b735c15315294732a0fc2b6a8ac88cef5b053ad9";

const ch1Wire = Buffer.from(ch1Hex, 'hex');
const shWire = Buffer.from(sh1Hex, 'hex');
const sharedSecret = Buffer.from(sharedHex, 'hex');

function hkdfExtract(hash, salt, ikm) {
  const saltBuf = (salt && salt.length > 0) ? salt : Buffer.alloc(32, 0);
  return crypto.createHmac(hash, saltBuf).update(ikm).digest();
}

function hkdfExpand(hash, prk, info, length) {
  const out = Buffer.alloc(length);
  let T = Buffer.alloc(0);
  let written = 0;
  let counter = 1;
  while (written < length) {
    const h = crypto.createHmac(hash, prk);
    h.update(T); h.update(info); h.update(Buffer.from([counter]));
    T = h.digest();
    const take = Math.min(32, length - written);
    T.copy(out, written, 0, take);
    written += take;
    counter += 1;
  }
  return out;
}

function runExperiment(prefixStr, transcriptMode) {
  const prefix = Buffer.from(prefixStr, 'ascii');
  
  function deriveSecret(secret, label, ctx) {
    const labelBuf = Buffer.from(label, 'ascii');
    // HKDF-Expand-Label (RFC 8446)
    const out = Buffer.alloc(2 + 1 + prefix.length + labelBuf.length + 1 + ctx.length);
    let o = 0;
    out.writeUInt16BE(32, o); o += 2;
    out.writeUInt8(prefix.length + labelBuf.length, o); o += 1;
    prefix.copy(out, o); o += prefix.length;
    labelBuf.copy(out, o); o += labelBuf.length;
    out.writeUInt8(ctx.length, o); o += 1;
    ctx.copy(out, o);
    return hkdfExpand('sha256', secret, out, 32);
  }

  const earlyS = hkdfExtract('sha256', Buffer.alloc(32, 0), Buffer.alloc(32, 0));
  const emptyHash = crypto.createHash('sha256').digest();
  const salt = deriveSecret(earlyS, 'derived', emptyHash);
  const hsS = hkdfExtract('sha256', salt, sharedSecret);

  let th;
  let ch = ch1Wire;
  let sh = shWire;

  if (transcriptMode === '4-byte') {
    ch = Buffer.concat([ch1Wire.slice(0,4), ch1Wire.slice(12)]);
    sh = Buffer.concat([shWire.slice(0,4), shWire.slice(12)]);
  } else if (transcriptMode === '4-byte-0303') {
    // OpenSSL'in TLS 1.3 parser'ı versiyonu 03 03 olarak farz ediyorsa
    ch = Buffer.concat([ch1Wire.slice(0,4), ch1Wire.slice(12)]);
    ch[4] = 0x03; ch[5] = 0x03;
    sh = Buffer.concat([shWire.slice(0,4), shWire.slice(12)]);
    sh[4] = 0x03; sh[5] = 0x03;
  } else if (transcriptMode === '12-byte-zeroed-seq') {
    const z = (b) => { let out = Buffer.from(b); out.writeUInt16BE(0,4); out.writeUInt8(0,6); out.writeUInt16BE(0,7); return out; };
    ch = z(ch1Wire); sh = z(shWire);
  } else if (transcriptMode === '12-byte-zeroed-all') {
    const z = (b) => { let out = Buffer.from(b); out.writeUInt16BE(0,4); out.writeUInt8(0,6); out.writeUInt16BE(0,7); out.writeUInt8(0,9); out.writeUInt16BE(0,10); return out; };
    ch = z(ch1Wire); sh = z(shWire);
  }

  th = crypto.createHash('sha256').update(ch).update(sh).digest();
  const cHsTraffic = deriveSecret(hsS, 'c hs traffic', th);
  return cHsTraffic.toString('hex');
}

// Bütün şüpheli varyasyonlar!
const prefixes = ['dtls13', 'tls13 ', 'dtls1.3', 'tls13'];
const modes = ['4-byte', '4-byte-0303', '12-byte', '12-byte-zeroed-seq', '12-byte-zeroed-all'];

let found = false;
for (let p of prefixes) {
  for (let m of modes) {
    const res = runExperiment(p, m);
    if (res === expectedSecret) {
      console.log(`\n======================================================`);
      console.log(`🎉 MATCH FOUND! BULDUM! 🎉`);
      console.log(`Prefix: '${p}'`);
      console.log(`Transcript Modeli: '${m}'`);
      console.log(`======================================================\n`);
      found = true;
      process.exit(0);
    }
  }
}

if (!found) {
  console.log("Maalesef standart senaryoların hiçbiri OpenSSL ile eşleşmedi.");
  console.log("Sorun Shared Secret'ın padding'i veya cipher suite seçimiyle ilgili olabilir.");
}