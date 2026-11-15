// Optional favicon route (M5 C3), same program as serve.mjs. OFF unless the
// server runs with KEYMESH_FAVICON=1; the app asks only after an explicit
// per-browser opt-in. Design and limits: .supervision/m5c-format-gate.md C3.
//
// * Host: IDNA → ASCII, a public-looking DNS name only (no IP literals,
//   single labels, localhost, .local/.internal/.lan/.home.arpa/.cloud).
// * Every resolved address must be public unicast (IPv4 and IPv6, IPv4-mapped
//   IPv6 refused). The connection uses the vetted address only (pinned
//   lookup), HTTPS on 443, certificate checked for the host, no cookies.
// * At most 2 redirects, each revalidated from scratch; 3 s total; 64 KiB.
// * Only PNG. It is fully decoded (CRC, bounded inflate, filters) and
//   re-encoded into a fresh RGBA PNG; nothing from the origin is passed
//   through. Anything else → null (the app keeps its local icon).
// * No host names are logged. Results are cached in memory; requests are
//   rate limited per process.
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { BlockList, isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { crc32, deflateSync, inflateSync } from 'node:zlib';

export const LIMITS = Object.freeze({
  totalMs: 3000,
  maxBytes: 64 * 1024,
  maxSide: 256,
  redirects: 2,
  ratePerMinute: 30,
  cacheEntries: 256,
  cacheMs: 24 * 3600 * 1000,
  maxInFlight: 4,
  maxChunks: 64,
});

const BLOCKED_SUFFIXES = ['.local', '.internal', '.lan', '.home.arpa', '.cloud', '.localhost', '.test', '.example', '.invalid', '.onion'];

/** Normalized ASCII host, or null if it may not be fetched. */
export function normalizeHost(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 253) return null;
  if (isIP(input.replace(/^\[|\]$/g, ''))) return null;
  // URL syntax would be silently dropped by domainToASCII ("a.com/x" → "a.com").
  if (/[\/\\@:?#%\s\[\]]/.test(input)) return null;
  const ascii = domainToASCII(input.trim().toLowerCase().replace(/\.$/, ''));
  if (!ascii || ascii.length > 253) return null;
  if (!/^[a-z0-9.-]+$/.test(ascii)) return null;
  const labels = ascii.split('.');
  if (labels.length < 2) return null;
  if (labels.some((l) => l.length === 0 || l.length > 63 || l.startsWith('-') || l.endsWith('-'))) return null;
  if (/^\d+$/.test(labels[labels.length - 1])) return null; // numeric TLD (e.g. 1.2.3.4 in disguise)
  if (ascii === 'localhost' || BLOCKED_SUFFIXES.some((s) => ascii === s.slice(1) || ascii.endsWith(s))) return null;
  return ascii;
}

// Address policy: an ALLOWLIST, not a partial denylist.
// * IPv4: every address except the IANA special-purpose registry blocks
//   below (RFC 6890 and updates).
// * IPv6: ONLY global unicast 2000::/3, minus its special-purpose blocks.
//   Everything outside 2000::/3 (::2, 100::/64 discard, fc00::/7, fe80::/10,
//   ff00::/8, 64:ff9b::/96, IPv4-mapped/compatible...) is refused.
// * Separate lists per family, so no IPv4/IPv4-mapped cross-matching.
const v4Special = new BlockList();
for (const [net, bits] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.31.196.0', 24], ['192.52.193.0', 24], ['192.88.99.0', 24],
  ['192.168.0.0', 16], ['192.175.48.0', 24], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
]) v4Special.addSubnet(net, bits, 'ipv4');
const v6Global = new BlockList();
v6Global.addSubnet('2000::', 3, 'ipv6');
const v6Special = new BlockList();
for (const [net, bits] of [
  ['2001::', 23], // IETF protocol assignments (Teredo, benchmarking, ORCHID, AMT, ...)
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4 (embeds IPv4)
  ['2620:4f:8000::', 48], // direct delegation AS112
  ['3fff::', 20], // documentation (RFC 9637)
]) v6Special.addSubnet(net, bits, 'ipv6');

/** True only for a public unicast address (see the policy above). */
export function isPublicAddress(address, family) {
  if (typeof address !== 'string') return false;
  const fam = isIP(address);
  if (fam === 0 || (family !== undefined && family !== fam)) return false; // family must match the text
  if (fam === 4) return !v4Special.check(address, 'ipv4');
  if (address.includes('.') || address.includes('%')) return false; // embedded IPv4 or a zone id
  return v6Global.check(address, 'ipv6') && !v6Special.check(address, 'ipv6');
}

// ---- PNG: full decode and fresh re-encode -------------------------------

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const CHANNELS = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td) >>> 0);
  return Buffer.concat([len, td, crc]);
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/**
 * Decode a PNG (8-bit, non-interlaced, gray/RGB/palette/gray-alpha/RGBA)
 * and return a NEW PNG with only IHDR/IDAT/IEND, RGBA. Null on anything
 * else: bad signature or CRC, unknown critical chunk, too large, bomb.
 */
export function sanitizePng(buf, maxSide = LIMITS.maxSide) {
  try {
    if (!Buffer.isBuffer(buf) || buf.length < 8 + 25 || !buf.subarray(0, 8).equals(SIG)) return null;
    // Canonical structure, checked chunk by chunk BEFORE anything is
    // inflated: IHDR first (exactly once); PLTE at most once, only for
    // palette images, before IDAT; tRNS at most once, only for palette
    // images, after PLTE and before IDAT, no longer than the palette; IDAT
    // chunks consecutive; IEND last with no data and nothing after it;
    // unknown critical chunks refused; at most `maxChunks` chunks.
    let off = 8;
    let ihdr = null;
    let plte = null;
    let trns = null;
    const idat = [];
    let ended = false;
    let idatDone = false;
    let count = 0;
    while (off + 12 <= buf.length) {
      if (++count > LIMITS.maxChunks) return null;
      const len = buf.readUInt32BE(off);
      const type = buf.toString('latin1', off + 4, off + 8);
      if (!/^[A-Za-z]{4}$/.test(type) || len > buf.length - off - 12) return null;
      const data = buf.subarray(off + 8, off + 8 + len);
      if ((crc32(buf.subarray(off + 4, off + 8 + len)) >>> 0) !== buf.readUInt32BE(off + 8 + len)) return null;
      off += 12 + len;
      if (!ihdr && type !== 'IHDR') return null;
      if (idat.length && type !== 'IDAT') idatDone = true;
      if (type === 'IHDR') {
        if (ihdr || len !== 13) return null;
        ihdr = { w: data.readUInt32BE(0), h: data.readUInt32BE(4), depth: data[8], color: data[9], comp: data[10], filter: data[11], interlace: data[12] };
        if (ihdr.w < 1 || ihdr.h < 1 || ihdr.w > maxSide || ihdr.h > maxSide) return null; // before any allocation
      } else if (type === 'PLTE') {
        if (plte || idat.length || ihdr.color !== 3 || len === 0 || len % 3 !== 0 || len > 768) return null;
        plte = data;
      } else if (type === 'tRNS') {
        if (trns || idat.length || ihdr.color !== 3 || !plte || len > plte.length / 3) return null;
        trns = data;
      } else if (type === 'IDAT') {
        if (idatDone) return null; // not consecutive
        idat.push(data);
      } else if (type === 'IEND') {
        if (len !== 0 || off !== buf.length) return null;
        ended = true;
        break;
      } else if ((type.charCodeAt(0) & 0x20) === 0) return null; // unknown critical chunk
    }
    if (!ihdr || !ended || idat.length === 0) return null;
    const { w, h, depth, color, comp, filter, interlace } = ihdr;
    if (depth !== 8 || comp !== 0 || filter !== 0 || interlace !== 0 || !(color in CHANNELS)) return null;
    if (color === 3 && (!plte || plte.length % 3 !== 0)) return null;
    const ch = CHANNELS[color];
    const stride = w * ch;
    const expected = (stride + 1) * h;
    const raw = inflateSync(Buffer.concat(idat), { maxOutputLength: expected });
    if (raw.length !== expected) return null;
    const px = Buffer.alloc(stride * h);
    for (let y = 0; y < h; y++) {
      const ft = raw[y * (stride + 1)];
      const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
      for (let x = 0; x < stride; x++) {
        const a = x >= ch ? px[y * stride + x - ch] : 0;
        const b = y > 0 ? px[(y - 1) * stride + x] : 0;
        const c = x >= ch && y > 0 ? px[(y - 1) * stride + x - ch] : 0;
        let v = line[x];
        if (ft === 1) v += a;
        else if (ft === 2) v += b;
        else if (ft === 3) v += (a + b) >> 1;
        else if (ft === 4) v += paeth(a, b, c);
        else if (ft !== 0) return null;
        px[y * stride + x] = v & 0xff;
      }
    }
    const out = Buffer.alloc((w * 4 + 1) * h);
    for (let y = 0; y < h; y++) {
      out[y * (w * 4 + 1)] = 0;
      for (let x = 0; x < w; x++) {
        const i = y * stride + x * ch;
        let r, g, bl, al = 255;
        if (color === 0) r = g = bl = px[i];
        else if (color === 4) { r = g = bl = px[i]; al = px[i + 1]; }
        else if (color === 2) { r = px[i]; g = px[i + 1]; bl = px[i + 2]; }
        else if (color === 6) { r = px[i]; g = px[i + 1]; bl = px[i + 2]; al = px[i + 3]; }
        else {
          const k = px[i];
          if (k * 3 + 2 >= plte.length) return null;
          r = plte[k * 3]; g = plte[k * 3 + 1]; bl = plte[k * 3 + 2];
          if (trns && k < trns.length) al = trns[k];
        }
        out.set([r, g, bl, al], y * (w * 4 + 1) + 1 + x * 4);
      }
    }
    const hdr = Buffer.alloc(13);
    hdr.writeUInt32BE(w, 0);
    hdr.writeUInt32BE(h, 4);
    hdr.set([8, 6, 0, 0, 0], 8);
    return Buffer.concat([SIG, chunk('IHDR', hdr), chunk('IDAT', deflateSync(out)), chunk('IEND', Buffer.alloc(0))]);
  } catch {
    return null;
  }
}

// ---- Fetching ------------------------------------------------------------

/** Real network: resolve all, connect to the vetted address only. */
export const realNet = {
  async resolve(host) {
    // dns.lookup can't be cancelled; fetchFavicon's deadline bounds it and
    // ignores a late answer.
    return dnsLookup(host, { all: true, verbatim: true });
  },
  get(host, address, family, path, signal, maxBytes) {
    return new Promise((resolve, reject) => {
      const req = httpsRequest(
        {
          host,
          servername: host,
          port: 443,
          path,
          method: 'GET',
          signal,
          headers: { 'user-agent': 'keymesh-favicon', accept: 'image/png' },
          lookup: (_h, _o, cb) => cb(null, address, family), // pinned: no second resolution
          agent: false,
        },
        (res) => {
          const parts = [];
          let n = 0;
          res.on('data', (d) => {
            n += d.length;
            if (n > maxBytes) {
              req.destroy();
              reject(new Error('too large'));
            } else parts.push(d);
          });
          res.on('end', () => resolve({ status: res.statusCode ?? 0, location: res.headers.location ?? null, body: Buffer.concat(parts) }));
          res.on('error', reject);
        },
      );
      req.on('error', reject);
      req.end();
    });
  },
};

/**
 * Fetch and sanitize a favicon for `input` host, or null. `net` is
 * injectable (tests never touch the network).
 */
export async function fetchFavicon(input, net = realNet, limits = LIMITS) {
  const ac = new AbortController();
  let timer;
  // One deadline for EVERYTHING (DNS, every hop, the body, the decode).
  const deadline = new Promise((resolve) => {
    timer = setTimeout(() => {
      ac.abort();
      resolve(null);
    }, limits.totalMs);
  });
  const work = (async () => {
    let host = normalizeHost(input);
    let path = '/favicon.ico';
    const tried = new Set();
    for (let hop = 0; host && hop <= limits.redirects; hop++) {
      const key = `${host}${path}`;
      if (tried.has(key)) return null; // loop
      tried.add(key);
      if (ac.signal.aborted) return null;
      const addrs = await net.resolve(host, ac.signal);
      if (ac.signal.aborted) return null; // late DNS answer: never connect
      if (!Array.isArray(addrs) || addrs.length === 0 || addrs.length > 32) return null;
      if (!addrs.every((a) => a && isPublicAddress(a.address, a.family))) return null;
      const pick = addrs[0];
      const res = await net.get(host, pick.address, pick.family, path, ac.signal, limits.maxBytes);
      if (ac.signal.aborted) return null;
      if (res.status >= 300 && res.status < 400 && res.location) {
        let next;
        try {
          next = new URL(res.location, `https://${host}${path}`);
        } catch {
          return null;
        }
        if (next.protocol !== 'https:' || (next.port && next.port !== '443') || next.username || next.password) return null;
        host = normalizeHost(next.hostname);
        path = next.pathname;
        continue;
      }
      if (res.status !== 200 || res.body.length > limits.maxBytes) return null;
      const png = sanitizePng(res.body, limits.maxSide);
      if (png) return png;
      if (path === '/favicon.ico' && hop === 0) {
        path = '/apple-touch-icon.png';
        continue;
      }
      return null;
    }
    return null;
  })().catch(() => null);
  try {
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
    ac.abort(); // anything still running stops now
  }
}

/** Route state: an in-memory cache and a per-process rate limit. */
export function createFaviconRoute({ enabled, net = realNet, limits = LIMITS, now = () => Date.now() } = {}) {
  const cache = new Map();
  let window = { start: 0, count: 0 };
  let inFlight = 0;
  return async function route(url) {
    if (!enabled) return { status: 404 };
    const host = normalizeHost(url.searchParams.get('host') ?? '');
    if (!host || [...url.searchParams.keys()].some((k) => k !== 'host')) return { status: 400 };
    const hit = cache.get(host);
    if (hit && now() - hit.at < limits.cacheMs) return hit.png ? { status: 200, body: hit.png } : { status: 404 };
    const t = now();
    if (t - window.start >= 60_000) window = { start: t, count: 0 };
    if (++window.count > limits.ratePerMinute) return { status: 429 };
    if (inFlight >= limits.maxInFlight) return { status: 429 };
    inFlight++;
    let png;
    try {
      png = await fetchFavicon(host, net, limits);
    } finally {
      inFlight--;
    }
    cache.delete(host);
    cache.set(host, { at: now(), png });
    while (cache.size > limits.cacheEntries) cache.delete(cache.keys().next().value);
    return png ? { status: 200, body: png } : { status: 404 };
  };
}
