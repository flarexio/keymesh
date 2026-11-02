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
    env: { ...process.env, HOST: '127.0.0.1', STATIC_ROOT: root, TLS_CERT: '', TLS_KEY: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
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
