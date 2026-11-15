// Containment regressions for scripts/serve.mjs, on 127.0.0.1:4313 only,
// with a temporary synthetic tree (deleted afterwards). Run: npm run test:serve
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = 4313;
const OUTSIDE = 'SYNTHETIC-OUTSIDE-ROOT-MARKER';
const base = mkdtempSync(join(tmpdir(), 'keymesh-serve-'));
const root = join(base, 'browser');
let server;
let serverOutput = '';

function get(path) {
  return new Promise((resolve, reject) => {
    // Raw path: no client-side normalization of `..` or encodings.
    const r = request({ host: '127.0.0.1', port: PORT, path, method: 'GET' }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, body, type: res.headers['content-type'] ?? '' }));
    });
    r.on('error', reject);
    r.end();
  });
}

before(async () => {
  mkdirSync(join(root, 'wasm'), { recursive: true });
  writeFileSync(join(root, 'index.html'), '<!doctype html><title>synthetic index</title>');
  writeFileSync(join(root, 'main-TEST.js'), 'console.log("synthetic")');
  writeFileSync(join(root, 'wasm', 'core.wasm'), 'synthetic-wasm');
  mkdirSync(join(root, 'icons'));
  writeFileSync(join(root, 'icons', 'icon.png'), 'synthetic-png');
  writeFileSync(join(root, 'manifest.webmanifest'), '{"name":"synthetic"}');
  writeFileSync(join(root, 'ngsw.json'), '{"configVersion":1}');
  // Siblings that share the root's name prefix, and a file outside it.
  writeFileSync(join(base, 'browser-sibling.txt'), OUTSIDE);
  mkdirSync(join(base, 'browserx'));
  writeFileSync(join(base, 'browserx', 'x.txt'), OUTSIDE);
  writeFileSync(join(base, 'outside.txt'), OUTSIDE);
  // Symlinks inside the root that point outside it.
  symlinkSync(join(base, 'outside.txt'), join(root, 'link-file.txt'));
  symlinkSync(base, join(root, 'link-dir'));
  const script = fileURLToPath(new URL('./serve.mjs', import.meta.url));
  server = spawn(process.execPath, [script, String(PORT)], {
    env: { ...process.env, HOST: '127.0.0.1', STATIC_ROOT: root, TLS_CERT: '', TLS_KEY: '', KEYMESH_FAVICON: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => (serverOutput += d));
  server.stderr.on('data', (d) => (serverOutput += d));
  await new Promise((resolve, reject) => {
    server.stdout.once('data', resolve);
    server.once('exit', (c) => reject(new Error(`server exited ${c}`)));
  });
});

after(() => {
  server?.kill();
  rmSync(base, { recursive: true, force: true });
});

test('normal assets and SPA fallback still work', async () => {
  assert.equal((await get('/')).body.includes('synthetic index'), true);
  const js = await get('/main-TEST.js');
  assert.equal(js.status, 200);
  assert.match(js.type, /javascript/);
  const wasm = await get('/wasm/core.wasm');
  assert.equal(wasm.status, 200);
  assert.equal(wasm.type, 'application/wasm');
  // Unknown app routes get the SPA shell.
  const route = await get('/some/app/route');
  assert.equal(route.status, 200);
  assert.ok(route.body.includes('synthetic index'));
});

test('PWA files get their own MIME types, and missing files are never the SPA shell', async () => {
  const manifest = await get('/manifest.webmanifest');
  assert.equal(manifest.status, 200);
  assert.equal(manifest.type, 'application/manifest+json');
  const png = await get('/icons/icon.png');
  assert.equal(png.status, 200);
  assert.equal(png.type, 'image/png');
  const ngsw = await get('/ngsw.json');
  assert.equal(ngsw.status, 200);
  assert.match(ngsw.type, /^application\/json/);
  // A missing file name (it has an extension) is a 404, so a service worker
  // or script can never receive index.html in place of ngsw.json or a chunk.
  for (const path of ['/missing.js', '/ngsw-missing.json', '/wasm/missing.wasm', '/icons/missing.png', '/a/b.webmanifest']) {
    const r = await get(path);
    assert.equal(r.status, 404, path);
    assert.ok(!r.body.includes('synthetic index'), path);
  }
});

for (const path of [
  '/..%2fbrowser-sibling.txt',
  '/..%2Fbrowser-sibling.txt',
  '/..%2fbrowserx%2fx.txt',
  '/..%2foutside.txt',
  '/%2e%2e%2foutside.txt',
  '/..%5coutside.txt',
  '/wasm/..%2f..%2foutside.txt',
  '/link-file.txt',
  '/link-dir/outside.txt',
  '/link-dir/browser-sibling.txt',
]) {
  test(`never serves outside the root: ${path}`, async () => {
    const r = await get(path);
    assert.ok(!r.body.includes(OUTSIDE), `${path} leaked a file outside the root (status ${r.status})`);
    assert.ok(r.status === 404 || r.status === 400, `${path}: status ${r.status}`);
  });
}

for (const path of ['/%E0%A4%A', '/%', '/a%00b']) {
  test(`malformed or NUL paths are rejected: ${JSON.stringify(path)}`, async () => {
    const r = await get(path);
    assert.equal(r.status, 400);
    assert.ok(!r.body.includes(OUTSIDE));
  });
}

// A second tree whose index.html is a symlink pointing OUTSIDE the root:
// the SPA fallback must get the same containment as explicit files.
test('an outward index.html symlink is never served, not even as the SPA fallback', async () => {
  const base2 = mkdtempSync(join(tmpdir(), 'keymesh-serve-idx-'));
  const root2 = join(base2, 'browser');
  mkdirSync(root2);
  writeFileSync(join(base2, 'outside-index.html'), OUTSIDE);
  symlinkSync(join(base2, 'outside-index.html'), join(root2, 'index.html'));
  writeFileSync(join(root2, 'main-TEST.js'), 'console.log("synthetic")');
  const PORT2 = PORT + 1;
  const script = fileURLToPath(new URL('./serve.mjs', import.meta.url));
  const srv = spawn(process.execPath, [script, String(PORT2)], {
    env: { ...process.env, HOST: '127.0.0.1', STATIC_ROOT: root2, TLS_CERT: '', TLS_KEY: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await new Promise((resolve, reject) => {
      srv.stdout.once('data', resolve);
      srv.once('exit', (c) => reject(new Error(`server exited ${c}`)));
    });
    const get2 = (path) =>
      new Promise((resolve, reject) => {
        const r = request({ host: '127.0.0.1', port: PORT2, path, method: 'GET' }, (res) => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', (c) => (body += c));
          res.on('end', () => resolve({ status: res.statusCode, body }));
        });
        r.on('error', reject);
        r.end();
      });
    for (const path of ['/', '/missing-app-route', '/index.html']) {
      const r = await get2(path);
      assert.ok(!r.body.includes(OUTSIDE), `${path} served the outside index (status ${r.status})`);
      assert.equal(r.status, 404, `${path}: status ${r.status}`);
    }
    // Real files inside the root are still served.
    assert.equal((await get2('/main-TEST.js')).status, 200);
  } finally {
    srv.kill();
    rmSync(base2, { recursive: true, force: true });
  }
});

test('favicon route: off by default (404, never the SPA shell), other /api paths 404, no host names logged', async () => {
  for (const p of ['/api/favicon?host=icons.example.com', '/api/favicon', '/api/other', '/api/']) {
    const r = await get(p);
    assert.equal(r.status, 404, p);
    assert.ok(!r.body.includes('synthetic index'), p);
  }
  assert.ok(!serverOutput.includes('icons.example.com'));
});

test('favicon responses are never stored by the browser (no-store), even errors', async () => {
  const r = await new Promise((resolve, reject) => {
    const q = request({ host: '127.0.0.1', port: PORT, path: '/api/favicon?host=icons.example.com', method: 'GET' }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.headers['cache-control']));
    });
    q.on('error', reject);
    q.end();
  });
  assert.equal(r, 'no-store');
});
