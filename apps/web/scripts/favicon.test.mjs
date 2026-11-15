// Adversarial tests for the optional favicon route (M5 C3). Every test uses
// an injected resolver/connector: NO real DNS or network request is made.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc32, deflateSync } from 'node:zlib';
import { createFaviconRoute, fetchFavicon, isPublicAddress, normalizeHost, sanitizePng, LIMITS } from './favicon.mjs';

const SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const c = Buffer.alloc(4);
  c.writeUInt32BE(crc32(td) >>> 0);
  return Buffer.concat([len, td, c]);
}
function png({ w = 2, h = 2, color = 6, raw, extra = [] } = {}) {
  const ch = { 0: 1, 2: 3, 4: 2, 6: 4 }[color];
  const rows = raw ?? Buffer.concat(Array.from({ length: h }, (_, y) => Buffer.from([y % 2 ? 2 : 1, ...Array(w * ch).fill(17)])));
  const hdr = Buffer.alloc(13);
  hdr.writeUInt32BE(w, 0);
  hdr.writeUInt32BE(h, 4);
  hdr.set([8, color, 0, 0, 0], 8);
  return Buffer.concat([SIG, chunk('IHDR', hdr), ...extra, chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))]);
}

/** Scripted network. `dns`: host → addresses; `http`: "host/path" → response. */
function mockNet(dns, http) {
  const calls = { resolve: [], get: [] };
  return {
    calls,
    async resolve(host) {
      calls.resolve.push(host);
      const a = typeof dns[host] === 'function' ? dns[host]() : dns[host];
      if (!a) throw new Error('ENOTFOUND');
      return a.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
    },
    async get(host, address, family, path, signal, maxBytes) {
      calls.get.push({ host, address, path });
      const r = http[`${host}${path}`];
      if (!r) return { status: 404, location: null, body: Buffer.alloc(0) };
      if (r.hang) await new Promise((res, rej) => signal.addEventListener('abort', () => rej(new Error('aborted'))));
      if (r.body && r.body.length > maxBytes) throw new Error('too large');
      return { status: r.status ?? 200, location: r.location ?? null, body: r.body ?? Buffer.alloc(0) };
    },
  };
}
const PUB = ['93.184.216.34'];

test('host validation: public DNS names only; IDNA; no literals, single labels or internal suffixes', () => {
  assert.equal(normalizeHost('Example.COM.'), 'example.com');
  assert.equal(normalizeHost('bücher.de'), 'xn--bcher-kva.de');
  for (const bad of ['', 'localhost', 'intranet', '127.0.0.1', '[::1]', '::1', '1.2.3.4', '0x7f.1', 'a..b.com', '-a.com',
    'svc.local', 'db.internal', 'keymesh.cloud', 'ca.cloud', 'nas.lan', 'x.home.arpa', 'x.localhost', 'a.test', 'x.example',
    'x.onion', 'evil.com/path', 'user@evil.com', 'evil.com:8080', 'a'.repeat(300) + '.com', '2130706433', 'x.1']) {
    assert.equal(normalizeHost(bad), null, bad);
  }
});

test('address classes: every private, special and mapped range is refused', () => {
  for (const ok of ['93.184.216.34', '8.8.8.8', '2606:2800:220:1:248:1893:25c8:1946']) assert.equal(isPublicAddress(ok), true, ok);
  for (const bad of ['0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.0.0.8', '192.0.2.1', '192.88.99.1', '192.168.1.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    '::', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', '100::1', '2001:db8::1', '2002:7f00:1::',
    'fc00::1', 'fd12:3456::1', 'fe80::1', 'fec0::1', 'ff02::1', '::127.0.0.1', 'not-an-ip', '']) {
    assert.equal(isPublicAddress(bad), false, bad);
  }
});

test('a good PNG is fully decoded and re-encoded (fresh bytes, RGBA, only IHDR/IDAT/IEND)', () => {
  const src = png({ extra: [chunk('tEXt', Buffer.from('Comment\0<script>alert(1)</script>'))] });
  const out = sanitizePng(src);
  assert.ok(out);
  assert.notDeepEqual(out, src);
  assert.ok(!out.includes(Buffer.from('script')));
  const types = [];
  for (let o = 8; o < out.length; ) {
    const len = out.readUInt32BE(o);
    types.push(out.toString('latin1', o + 4, o + 8));
    o += 12 + len;
  }
  assert.deepEqual(types, ['IHDR', 'IDAT', 'IEND']);
  assert.equal(out[8 + 8 + 9], 6); // RGBA
  for (const color of [0, 2, 4]) assert.ok(sanitizePng(png({ color })), `color ${color}`);
});

test('hostile images are refused: SVG/HTML/ICO, bad CRC, oversize, interlace, bomb, junk filters, unknown critical chunk', () => {
  assert.equal(sanitizePng(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>')), null);
  assert.equal(sanitizePng(Buffer.from('<!doctype html><html>')), null);
  assert.equal(sanitizePng(Buffer.from([0, 0, 1, 0, 1, 0, 16, 16])), null); // ICO header
  const good = png();
  const badCrc = Buffer.from(good);
  badCrc[badCrc.length - 20] ^= 1;
  assert.equal(sanitizePng(badCrc), null);
  assert.equal(sanitizePng(png({ w: 257, h: 1, raw: Buffer.alloc(1 + 257 * 4) })), null);
  // Decompression bomb: small header, IDAT inflating far beyond w*h.
  const bomb = png({ w: 2, h: 2, raw: Buffer.alloc(10 * 1024 * 1024) });
  assert.ok(bomb.length < 20_000);
  assert.equal(sanitizePng(bomb), null);
  assert.equal(sanitizePng(png({ raw: Buffer.from([9, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1]) })), null);
  assert.equal(sanitizePng(png({ extra: [chunk('ABCD', Buffer.alloc(1))] })), null);
  const ihdr = Buffer.from(good);
  ihdr[8 + 8 + 12] = 1; // interlace flag, CRC now wrong too
  assert.equal(sanitizePng(ihdr), null);
});

test('fetch: public host, pinned address used, PNG sanitized', async () => {
  const net = mockNet({ 'icons.example.com': PUB }, { 'icons.example.com/favicon.ico': { body: png() } });
  const out = await fetchFavicon('icons.example.com', net);
  assert.ok(out);
  assert.deepEqual(net.calls.get.map((c) => [c.host, c.address, c.path]), [['icons.example.com', PUB[0], '/favicon.ico']]);
});

test('fetch: falls back to apple-touch-icon only when favicon.ico is not PNG', async () => {
  const net = mockNet({ 'a.example.com': PUB }, {
    'a.example.com/favicon.ico': { body: Buffer.from([0, 0, 1, 0]) },
    'a.example.com/apple-touch-icon.png': { body: png() },
  });
  assert.ok(await fetchFavicon('a.example.com', net));
});

test('SSRF: any private address in the answer refuses the host; nothing is requested', async () => {
  for (const addrs of [['10.0.0.5'], ['93.184.216.34', '127.0.0.1'], ['::ffff:169.254.169.254'], ['fd00::1']]) {
    const net = mockNet({ 'evil.example.com': addrs }, { 'evil.example.com/favicon.ico': { body: png() } });
    assert.equal(await fetchFavicon('evil.example.com', net), null, addrs.join());
    assert.equal(net.calls.get.length, 0);
  }
});

test('SSRF: DNS rebinding cannot redirect the connection (only the vetted address is ever used)', async () => {
  let n = 0;
  const net = mockNet({ 'rebind.example.com': () => (n++ === 0 ? PUB : ['127.0.0.1']) }, { 'rebind.example.com/favicon.ico': { body: png() } });
  assert.ok(await fetchFavicon('rebind.example.com', net));
  assert.equal(net.calls.resolve.length, 1);
  assert.equal(net.calls.get[0].address, PUB[0]);
});

test('SSRF: redirects are revalidated; private, http, odd ports, credentials and loops are refused', async () => {
  const cases = [
    ['https://127.0.0.1/x.png', 0],
    ['https://intranet.local/x.png', 0],
    ['http://cdn.example.com/x.png', 0],
    ['https://cdn.example.com:8443/x.png', 0],
    ['https://user:pw@cdn.example.com/x.png', 0],
  ];
  for (const [loc] of cases) {
    const net = mockNet({ 'r.example.com': PUB, 'cdn.example.com': PUB }, {
      'r.example.com/favicon.ico': { status: 302, location: loc },
      'cdn.example.com/x.png': { body: png() },
    });
    assert.equal(await fetchFavicon('r.example.com', net), null, loc);
    assert.ok(!net.calls.get.some((c) => c.host !== 'r.example.com'), loc);
  }
  // A redirect to a host that resolves privately.
  const priv = mockNet({ 'r.example.com': PUB, 'inside.example.com': ['192.168.1.2'] }, {
    'r.example.com/favicon.ico': { status: 301, location: 'https://inside.example.com/i.png' },
    'inside.example.com/i.png': { body: png() },
  });
  assert.equal(await fetchFavicon('r.example.com', priv), null);
  assert.equal(priv.calls.get.length, 1);
  // Loop and too many hops.
  const loop = mockNet({ 'l.example.com': PUB }, { 'l.example.com/favicon.ico': { status: 302, location: '/favicon.ico' } });
  assert.equal(await fetchFavicon('l.example.com', loop), null);
  const hops = mockNet({ 'h.example.com': PUB }, {
    'h.example.com/favicon.ico': { status: 302, location: '/a' },
    'h.example.com/a': { status: 302, location: '/b' },
    'h.example.com/b': { status: 302, location: '/c' },
    'h.example.com/c': { body: png() },
  });
  assert.equal(await fetchFavicon('h.example.com', hops), null);
  // A valid public redirect works.
  const ok = mockNet({ 'r.example.com': PUB, 'cdn.example.com': PUB }, {
    'r.example.com/favicon.ico': { status: 302, location: 'https://cdn.example.com/x.png' },
    'cdn.example.com/x.png': { body: png() },
  });
  assert.ok(await fetchFavicon('r.example.com', ok));
});

test('resources: oversize, slow responses and errors give null within the time limit', async () => {
  const big = mockNet({ 'b.example.com': PUB }, { 'b.example.com/favicon.ico': { body: Buffer.alloc(LIMITS.maxBytes + 1) } });
  assert.equal(await fetchFavicon('b.example.com', big), null);
  const slow = mockNet({ 's.example.com': PUB }, { 's.example.com/favicon.ico': { hang: true } });
  const t0 = Date.now();
  assert.equal(await fetchFavicon('s.example.com', slow, { ...LIMITS, totalMs: 50 }), null);
  assert.ok(Date.now() - t0 < 1000);
  assert.equal(await fetchFavicon('nx.example.com', mockNet({}, {})), null);
});

test('route: disabled → 404 without any lookup; bad input 400; cache; rate limit', async () => {
  const net = mockNet({ 'c.example.com': PUB }, { 'c.example.com/favicon.ico': { body: png() } });
  const off = createFaviconRoute({ enabled: false, net });
  assert.equal((await off(new URL('http://x/api/favicon?host=c.example.com'))).status, 404);
  assert.equal(net.calls.resolve.length, 0);
  let t = 0;
  const route = createFaviconRoute({ enabled: true, net, now: () => t, limits: { ...LIMITS, ratePerMinute: 2 } });
  assert.equal((await route(new URL('http://x/api/favicon?host=127.0.0.1'))).status, 400);
  assert.equal((await route(new URL('http://x/api/favicon?host=c.example.com&title=secret'))).status, 400);
  assert.equal((await route(new URL('http://x/api/favicon'))).status, 400);
  const r1 = await route(new URL('http://x/api/favicon?host=c.example.com'));
  assert.equal(r1.status, 200);
  await route(new URL('http://x/api/favicon?host=c.example.com'));
  assert.equal(net.calls.get.length, 1); // cached
  assert.equal((await route(new URL('http://x/api/favicon?host=d.example.com'))).status, 404);
  assert.equal((await route(new URL('http://x/api/favicon?host=e.example.com'))).status, 429);
  t += 60_000;
  assert.notEqual((await route(new URL('http://x/api/favicon?host=e.example.com'))).status, 429);
});

// ---- Gate-response regressions (parent review 2026-11-16) -----------------

test('address policy is an allowlist: IPv6 only in 2000::/3 minus special blocks; reserved IPv4 refused', () => {
  // Parent probe: these were wrongly "public" before.
  for (const bad of ['::2', '100:0:0:1::1', '3fff::1', '3fff:fff::1',
    // other non-global or special IPv6, in abbreviated and expanded forms
    '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:ffff:7f00:0001', '::ffff:0:0', '1::1', '4000::1', 'e000::1',
    '2001:0000:4136:e378:8000:63bf:3fff:fdd2', '2001:2::1', '2001:10::1', '2001:20::1', '2001:db8:ffff::1',
    '2002:c000:0204::1', '2620:4f:8000::1', 'fe80::1%eth0', '::ffff:93.184.216.34', '64:ff9b::93.184.216.34',
    // special-purpose IPv4
    '192.31.196.1', '192.52.193.1', '192.175.48.1', '240.0.0.1', '255.255.255.255', '0.1.2.3']) {
    assert.equal(isPublicAddress(bad), false, bad);
  }
  for (const ok of ['2606:2800:220:1:248:1893:25c8:1946', '2a00:1450:4001:82a::200e', '2001:4860:4860::8888', '1.1.1.1', '93.184.216.34']) {
    assert.equal(isPublicAddress(ok), true, ok);
  }
  // The DNS family must match the address text.
  assert.equal(isPublicAddress('93.184.216.34', 6), false);
  assert.equal(isPublicAddress('2606:2800:220:1:248:1893:25c8:1946', 4), false);
  assert.equal(isPublicAddress('93.184.216.34', 4), true);
});

test('mixed DNS answers: one non-public address (any family) refuses the host; nothing is requested', async () => {
  for (const addrs of [['93.184.216.34', '::2'], ['2606:2800:220:1:248:1893:25c8:1946', '100:0:0:1::1'], ['93.184.216.34', '3fff::1']]) {
    const net = mockNet({ 'mix.example.com': addrs }, { 'mix.example.com/favicon.ico': { body: png() } });
    assert.equal(await fetchFavicon('mix.example.com', net), null, addrs.join());
    assert.equal(net.calls.get.length, 0, addrs.join());
  }
  // A resolver answer whose family disagrees with the text is refused.
  const liar = { calls: { get: [] }, async resolve() { return [{ address: '93.184.216.34', family: 6 }]; }, async get() { liar.calls.get.push(1); return { status: 200, body: png() }; } };
  assert.equal(await fetchFavicon('liar.example.com', liar), null);
  assert.equal(liar.calls.get.length, 0);
});

test('one deadline bounds DNS too: a never-settling or late resolver ends in time and never connects', async () => {
  let connected = 0;
  const never = { async resolve() { return new Promise(() => {}); }, async get() { connected++; return { status: 200, body: png() }; } };
  let t0 = Date.now();
  assert.equal(await fetchFavicon('slow-dns.example.com', never, { ...LIMITS, totalMs: 40 }), null);
  let elapsed = Date.now() - t0;
  assert.ok(elapsed >= 35 && elapsed < 500, `elapsed ${elapsed}`);
  // Parent reproduction: resolver answers at 180 ms with a 20 ms limit.
  const late = { async resolve() { await new Promise((r) => setTimeout(r, 180)); return [{ address: '93.184.216.34', family: 4 }]; }, async get() { connected++; return { status: 200, body: png() }; } };
  t0 = Date.now();
  assert.equal(await fetchFavicon('late-dns.example.com', late, { ...LIMITS, totalMs: 20 }), null);
  elapsed = Date.now() - t0;
  assert.ok(elapsed < 120, `returned at the deadline, not after DNS (${elapsed} ms)`);
  await new Promise((r) => setTimeout(r, 250)); // let the late DNS answer arrive
  assert.equal(connected, 0, 'no connector call after the deadline');
});

test('a stalled response body is cut at the deadline; the connector sees the abort', async () => {
  let aborted = false;
  const stall = { async resolve() { return [{ address: '93.184.216.34', family: 4 }]; }, get(_h, _a, _f, _p, signal) { return new Promise((_, rej) => signal.addEventListener('abort', () => { aborted = true; rej(new Error('aborted')); })); } };
  const t0 = Date.now();
  assert.equal(await fetchFavicon('stall.example.com', stall, { ...LIMITS, totalMs: 40 }), null);
  assert.ok(Date.now() - t0 < 500);
  assert.equal(aborted, true);
});

test('concurrency is bounded per process', async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const held = { async resolve() { await gate; return [{ address: '93.184.216.34', family: 4 }]; }, async get() { return { status: 200, body: png() }; } };
  const route = createFaviconRoute({ enabled: true, net: held, limits: { ...LIMITS, maxInFlight: 2, totalMs: 2000 } });
  const a = route(new URL('http://x/api/favicon?host=a1.example.com'));
  const b = route(new URL('http://x/api/favicon?host=a2.example.com'));
  assert.equal((await route(new URL('http://x/api/favicon?host=a3.example.com'))).status, 429);
  release();
  assert.equal((await a).status, 200);
  assert.equal((await b).status, 200);
});

test('PNG structure is canonical: order, counts, palette/transparency rules, nothing after IEND', () => {
  const hdr = (w, h, color) => {
    const b = Buffer.alloc(13);
    b.writeUInt32BE(w, 0);
    b.writeUInt32BE(h, 4);
    b.set([8, color, 0, 0, 0], 8);
    return chunk('IHDR', b);
  };
  const rows = (w, h, ch) => deflateSync(Buffer.concat(Array.from({ length: h }, () => Buffer.from([0, ...Array(w * ch).fill(1)]))));
  const make = (...cs) => Buffer.concat([SIG, ...cs]);
  const iend = chunk('IEND', Buffer.alloc(0));
  const pal = chunk('PLTE', Buffer.from([1, 2, 3, 4, 5, 6]));
  // A valid palette image with transparency decodes.
  assert.ok(sanitizePng(make(hdr(2, 2, 3), pal, chunk('tRNS', Buffer.from([0, 255])), chunk('IDAT', rows(2, 2, 1)), iend)));
  const bad = {
    'IHDR not first': make(chunk('tEXt', Buffer.from('a\0b')), hdr(2, 2, 6), chunk('IDAT', rows(2, 2, 4)), iend),
    'two IHDR': make(hdr(2, 2, 6), hdr(2, 2, 6), chunk('IDAT', rows(2, 2, 4)), iend),
    'palette image without PLTE': make(hdr(2, 2, 3), chunk('IDAT', rows(2, 2, 1)), iend),
    'PLTE on an RGBA image': make(hdr(2, 2, 6), pal, chunk('IDAT', rows(2, 2, 4)), iend),
    'PLTE after IDAT': make(hdr(2, 2, 3), chunk('IDAT', rows(2, 2, 1)), pal, iend),
    'two PLTE': make(hdr(2, 2, 3), pal, pal, chunk('IDAT', rows(2, 2, 1)), iend),
    'tRNS longer than the palette': make(hdr(2, 2, 3), pal, chunk('tRNS', Buffer.from([0, 1, 2])), chunk('IDAT', rows(2, 2, 1)), iend),
    'tRNS before PLTE': make(hdr(2, 2, 3), chunk('tRNS', Buffer.from([0])), pal, chunk('IDAT', rows(2, 2, 1)), iend),
    'tRNS on RGB': make(hdr(2, 2, 2), chunk('tRNS', Buffer.alloc(6)), chunk('IDAT', rows(2, 2, 3)), iend),
    'palette index outside PLTE': make(hdr(1, 1, 3), pal, chunk('IDAT', deflateSync(Buffer.from([0, 9]))), iend),
    'IDAT not consecutive': (() => {
      const z = rows(2, 2, 4);
      return make(hdr(2, 2, 6), chunk('IDAT', z.subarray(0, 4)), chunk('tEXt', Buffer.from('a\0b')), chunk('IDAT', z.subarray(4)), iend);
    })(),
    'data after IEND': Buffer.concat([make(hdr(2, 2, 6), chunk('IDAT', rows(2, 2, 4)), iend), Buffer.from('<script>')]),
    'IEND with data': make(hdr(2, 2, 6), chunk('IDAT', rows(2, 2, 4)), chunk('IEND', Buffer.from([1]))),
    'too many chunks': make(hdr(2, 2, 6), ...Array.from({ length: 70 }, () => chunk('tEXt', Buffer.from('a\0b'))), chunk('IDAT', rows(2, 2, 4)), iend),
    'zero width': make(hdr(0, 2, 6), chunk('IDAT', rows(0, 2, 4)), iend),
  };
  for (const [name, b] of Object.entries(bad)) assert.equal(sanitizePng(b), null, name);
});

test('the route is never cached by the installed app (service worker) and adds no third-party access', async () => {
  const { readFileSync } = await import('node:fs');
  const cfg = JSON.parse(readFileSync(new URL('../ngsw-config.json', import.meta.url), 'utf8'));
  assert.deepEqual(cfg.dataGroups ?? [], [], 'no runtime data caching');
  const assets = JSON.stringify(cfg.assetGroups);
  assert.ok(!assets.includes('/api'), 'no /api in asset groups');
  assert.ok(!(cfg.navigationUrls ?? []).some((u) => u.includes('api')), 'not a navigation URL');
});
