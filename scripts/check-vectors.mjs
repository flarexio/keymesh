// Independent check of tests/fixtures/v2/vectors.json with Node's OpenSSL
// primitives (not the Rust core): Argon2id, HKDF-SHA256, the recovery-code
// encoding, and a full unwrap of both key slots plus the manifest.
// XChaCha20-Poly1305 = HChaCha20 subkey + IETF ChaCha20-Poly1305
// (draft-irtf-cfrg-xchacha-03 §2.3); HChaCha20 is written out below only
// for this verification script.
// Usage: node scripts/check-vectors.mjs   (Node >= 24.7 for crypto.argon2Sync)
import { argon2Sync, createDecipheriv, createHash, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';

const v = JSON.parse(readFileSync(new URL('../tests/fixtures/v2/vectors.json', import.meta.url)));
const hex = (b) => Buffer.from(b).toString('hex');
const b64u = (s) => Buffer.from(s, 'base64url');
let failures = 0;
const check = (name, ok) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`);
  if (!ok) failures++;
};

/** u32 big-endian length before each field (keymesh `fields`). */
function fields(...parts) {
  return Buffer.concat(
    parts.flatMap((p) => {
      const b = typeof p === 'string' ? Buffer.from(p, 'utf8') : Buffer.from(p);
      const len = Buffer.alloc(4);
      len.writeUInt32BE(b.length);
      return [len, b];
    }),
  );
}
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};

function argon(password, salt, m, t, p) {
  return argon2Sync('argon2id', {
    message: Buffer.from(password.normalize('NFC'), 'utf8'),
    nonce: salt,
    memory: m,
    passes: t,
    parallelism: p,
    tagLength: 32,
  });
}

function kek(ikm, salt, kind, vaultId, slotId) {
  const info = fields('keymesh.vault', '2', 'kek', kind, vaultId, slotId);
  return Buffer.from(hkdfSync('sha256', ikm, salt ?? Buffer.alloc(0), info, 32));
}

// --- XChaCha20-Poly1305 decryption (verification only) ---------------------
function rotl(x, n) {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}
function hchacha20(key, nonce16) {
  const s = new Uint32Array(16);
  s.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(4 * i);
  for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(4 * i);
  const qr = (a, b, c, d) => {
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((w, i) => out.writeUInt32LE(s[w], 4 * i));
  return out;
}
function xopen(key, nonce, ct, aad) {
  const sub = hchacha20(key, nonce.subarray(0, 16));
  const n12 = Buffer.concat([Buffer.alloc(4), nonce.subarray(16, 24)]);
  const d = createDecipheriv('chacha20-poly1305', sub, n12, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

// --- vectors -----------------------------------------------------------------
const a = v.argon2id;
const out = argon(a.password, Buffer.from(a.salt_hex, 'hex'), a.m_kib, a.t, a.p);
check('argon2id output (OpenSSL)', hex(out) === a.output_hex);

const kp = v.kek.password;
check('password KEK (HKDF-SHA256)', hex(kek(Buffer.from(kp.ikm_hex, 'hex'), null, 'password', kp.vault_id, kp.slot_id)) === kp.kek_hex);
const kr = v.kek.recovery;
check(
  'recovery KEK (HKDF-SHA256)',
  hex(kek(Buffer.from(kr.ikm_hex, 'hex'), Buffer.from(kr.salt_hex, 'hex'), 'recovery', kr.vault_id, kr.slot_id)) === kr.kek_hex,
);

// Recovery code: Base32(0x01 ‖ secret ‖ SHA-256("keymesh recovery code" ‖ 0x01 ‖ secret)[0..2])
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) {
  let bits = 0, val = 0, s = '';
  for (const byte of buf) {
    val = (val << 8) | byte; bits += 8;
    while (bits >= 5) { s += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) s += B32[(val << (5 - bits)) & 31];
  return s;
}
const secret = Buffer.from(v.recovery_code.secret_hex, 'hex');
const sum = createHash('sha256').update('keymesh recovery code').update(Buffer.from([1])).update(secret).digest();
const text = base32(Buffer.concat([Buffer.from([1]), secret, sum.subarray(0, 2)])).match(/.{4}/g).join('-');
check('recovery code text', text === v.recovery_code.text);

function decodeCode(t) {
  const clean = t.replace(/[-\s]/g, '').toUpperCase();
  let bits = 0, val = 0;
  const bytes = [];
  for (const c of clean) {
    val = (val << 5) | B32.indexOf(c); bits += 5;
    if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(bytes).subarray(1, 33);
}

// Envelope: unwrap each slot independently, then open the manifest.
const e = v.envelope;
const file = JSON.parse(e.json);
check('envelope header', file.format === 'keymesh.vault' && file.version === 2 && file.vault_id === e.vault_id);
const canon = (k) =>
  k.alg === 'argon2id'
    ? fields('argon2id', u32(k.v), u32(k.m_kib), u32(k.t), u32(k.p), b64u(k.salt))
    : fields('hkdf-sha256', b64u(k.salt));
const slotAad = (s) => fields('keymesh.vault', '2', 'slot', file.aead, file.vault_id, s.id, s.kind, canon(s.kdf));
const pw = file.slots.find((s) => s.kind === 'password');
const rc = file.slots.find((s) => s.kind === 'recovery');
const pwIkm = argon(e.password, b64u(pw.kdf.salt), pw.kdf.m_kib, pw.kdf.t, pw.kdf.p);
const dekA = xopen(kek(pwIkm, null, 'password', file.vault_id, pw.id), b64u(pw.wrapped.nonce), b64u(pw.wrapped.ct), slotAad(pw));
const dekB = xopen(
  kek(decodeCode(e.recovery_code), b64u(rc.kdf.salt), 'recovery', file.vault_id, rc.id),
  b64u(rc.wrapped.nonce),
  b64u(rc.wrapped.ct),
  slotAad(rc),
);
check('both slots unwrap the same 32-byte DEK', dekA.length === 32 && dekA.equals(dekB));

const digest = createHash('sha256').update(u32(file.slots.length));
for (const s of file.slots) {
  digest.update(fields(s.id, s.kind, canon(s.kdf), b64u(s.wrapped.nonce), b64u(s.wrapped.ct)));
}
const maad = fields('keymesh.vault', '2', 'manifest', file.aead, file.vault_id, u64(file.revision), digest.digest());
const manifest = JSON.parse(xopen(dekA, b64u(file.manifest.nonce), b64u(file.manifest.ct), maad));
check('manifest opens and matches header', manifest.vault_id === file.vault_id && manifest.revision === file.revision);
const titles = file.items
  .map((it) => {
    const aad = fields('keymesh.vault', '2', 'item', file.aead, file.vault_id, it.id, u64(it.rev));
    return JSON.parse(xopen(dekA, b64u(it.sealed.nonce), b64u(it.sealed.ct), aad)).title;
  })
  .sort();
check('items decrypt to the expected titles', JSON.stringify(titles) === JSON.stringify(e.titles));

let wrongRejected = false;
try {
  const bad = argon('synthetic wrong passphrase', b64u(pw.kdf.salt), pw.kdf.m_kib, pw.kdf.t, pw.kdf.p);
  xopen(kek(bad, null, 'password', file.vault_id, pw.id), b64u(pw.wrapped.nonce), b64u(pw.wrapped.ct), slotAad(pw));
} catch {
  wrongRejected = true;
}
check('wrong password fails authentication', wrongRejected);

if (failures) {
  console.error(`${failures} vector check(s) failed`);
  process.exit(1);
}
console.log('all vector checks passed');
