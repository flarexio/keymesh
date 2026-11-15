/**
 * Installable app (PWA): manifest, service worker, offline reopen, updates.
 *
 * Real production build with the real Angular service worker, real WASM and
 * workers, in Chromium on loopback. SYNTHETIC DATA ONLY. Offline and update
 * tests serve their own copy of the build on a private loopback port, so a
 * "new version" is a real deployment (files changed, ngsw.json regenerated
 * with Angular's own ngsw-config tool) and "offline" is the server really
 * stopped, not only emulated. No service worker or browser data is tampered
 * with to force a pass; the one corruption test does so deliberately and
 * checks the user-visible recovery.
 */
import { BrowserContext, Page, expect, test } from '@playwright/test';
import { ChildProcess, execFileSync, spawn } from 'node:child_process';
import { cpSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { M, RFC_URI, newItem, start, storedBytes } from './helpers';
import { qrPng } from './qr-fixtures';

const DIST = join(__dirname, '../dist/web/browser');
const SERVE = join(__dirname, '../scripts/serve.mjs');
const NGSW_CONFIG = join(__dirname, '../node_modules/@angular/service-worker/ngsw-config.js');
const PW = 'synthetic pwa passphrase one';

interface Site {
  root: string;
  origin: string;
  stop(): Promise<void>;
  restart(): Promise<void>;
}

/** Serve a private copy of the build (loopback only) so it can be redeployed. */
async function site(dir: string, port: number): Promise<Site> {
  const root = join(dir, 'site');
  cpSync(DIST, root, { recursive: true });
  let proc: ChildProcess | null = null;
  const up = async () => {
    proc = spawn(process.execPath, [SERVE, String(port)], {
      env: { ...process.env, HOST: '127.0.0.1', STATIC_ROOT: root, TLS_CERT: '', TLS_KEY: '' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    await new Promise<void>((resolve, reject) => {
      proc!.stdout!.once('data', () => resolve());
      proc!.once('exit', (c) => reject(new Error(`server exited ${c}`)));
    });
  };
  await up();
  return {
    root,
    origin: `http://127.0.0.1:${port}`,
    stop: async () => {
      const p = proc;
      proc = null;
      if (!p || p.exitCode !== null) return;
      await new Promise<void>((resolve) => {
        p.once('exit', () => resolve());
        p.kill();
      });
    },
    restart: up,
  };
}

/** Deploy a new version: edit files, then regenerate ngsw.json with Angular's tool. */
function deploy(s: Site, edit: (root: string) => void): void {
  edit(s.root);
  // The tool resolves both paths against its working directory.
  const web = join(__dirname, '..');
  execFileSync(process.execPath, [NGSW_CONFIG, relative(web, s.root), 'ngsw-config.json', '/'], { cwd: web, stdio: 'pipe' });
}

const mainJs = (root: string) => readdirSync(root).find((f) => /^main-.*\.js$/.test(f))!;

/** Wait until this page is controlled and every app file is in CacheStorage. */
async function installed(page: Page): Promise<void> {
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => undefined));
  if (!(await page.evaluate(() => !!navigator.serviceWorker.controller))) {
    await page.reload();
    await expect.poll(() => page.evaluate(() => !!navigator.serviceWorker.controller)).toBe(true);
  }
  const expected: string[] = await page.evaluate(async () =>
    (await (await fetch('/ngsw.json', { cache: 'no-store' })).json()).assetGroups.flatMap((g: { urls: string[] }) => g.urls),
  );
  await expect
    .poll(() => page.evaluate(async (urls) => {
      const have = new Set<string>();
      for (const k of await caches.keys()) for (const r of await (await caches.open(k)).keys()) have.add(new URL(r.url).pathname);
      return urls.filter((u) => !have.has(u));
    }, expected), { timeout: 30_000 })
    .toEqual([]);
}

/** Every cache, URL and body in CacheStorage (bodies as text, for marker scanning). */
async function cacheDump(page: Page): Promise<{ entries: { cache: string; url: string }[]; text: string }> {
  return page.evaluate(async () => {
    const entries: { cache: string; url: string }[] = [];
    let text = '';
    for (const k of await caches.keys()) {
      const c = await caches.open(k);
      for (const req of await c.keys()) {
        const u = new URL(req.url);
        entries.push({ cache: k, url: u.pathname + u.search });
        const res = await c.match(req);
        text += new TextDecoder('latin1').decode(new Uint8Array(await res!.arrayBuffer())) + '\n';
      }
    }
    return { entries, text };
  });
}

async function createPasswordVault(page: Page): Promise<string> {
  await expect(page.getByTestId('protected-section')).toBeVisible();
  await page.getByTestId('create-password').fill(PW);
  await page.getByTestId('create-password-confirm').fill(PW);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const code = await page.getByTestId('recovery-code').evaluate((el) =>
    Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'),
  );
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  return code;
}

async function unlock(page: Page): Promise<void> {
  await page.getByTestId('unlock-password').fill(PW);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
}

test('manifest, icons and service-worker files: real MIME types, root scope, no SPA fallback, CSP kept', async ({ page, request }) => {
  const m = await request.get('/manifest.webmanifest');
  expect(m.status()).toBe(200);
  expect(m.headers()['content-type']).toBe('application/manifest+json');
  const manifest = await m.json();
  expect(manifest).toMatchObject({ id: '/', name: 'Keymesh', short_name: 'Keymesh', start_url: '/', scope: '/', display: 'standalone' });
  const purposes = new Map<string, string>();
  for (const icon of manifest.icons as { src: string; sizes: string; purpose: string }[]) {
    const r = await request.get('/' + icon.src);
    expect(r.headers()['content-type']).toBe('image/png');
    const b = await r.body();
    expect(`${b.readUInt32BE(16)}x${b.readUInt32BE(20)}`).toBe(icon.sizes);
    purposes.set(icon.purpose, icon.sizes);
  }
  expect(purposes.get('maskable')).toBe('512x512');
  expect(purposes.get('any')).toBeTruthy();
  for (const [path, type] of [
    ['/ngsw-worker.js', /^text\/javascript/],
    ['/ngsw.json', /^application\/json/],
    ['/wasm/zxing_reader.wasm', /^application\/wasm$/],
    ['/icons/apple-touch-icon.png', /^image\/png$/],
  ] as const) {
    const r = await request.get(path);
    expect(r.status(), path).toBe(200);
    expect(r.headers()['content-type'], path).toMatch(type);
    expect(r.headers()['content-security-policy'], path).toContain("default-src 'self'");
  }
  for (const path of ['/ngsw-missing.json', '/chunk-MISSING.js', '/wasm/missing.wasm']) {
    const r = await request.get(path);
    expect(r.status(), path).toBe(404);
  }

  await page.goto('/');
  await expect(page.locator('link[rel=manifest]')).toHaveAttribute('href', 'manifest.webmanifest');
  const reg = await page.evaluate(async () => {
    const r = await navigator.serviceWorker.ready;
    return { scope: r.scope, script: r.active?.scriptURL };
  });
  expect(reg.scope).toBe(new URL('/', page.url()).href);
  expect(reg.script).toBe(new URL('/ngsw-worker.js', page.url()).href);
});

test('offline reopen: after one online visit, the stopped-server app unlocks the stored password vault; caches hold no secrets', async ({ browser }, testInfo) => {
  const s = await site(testInfo.outputPath(), 4321);
  const ctx = await browser.newContext({ baseURL: s.origin });
  const page = await ctx.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  try {
    await page.goto('/');
    const code = await createPasswordVault(page);
    await newItem(page, 'login');
    await page.locator('input[name=title]').fill(M.loginTitle);
    await page.locator('input[name=password]').fill(M.password);
    await page.locator('textarea[name=urls]').fill('https://github.com/login');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.locator('#detail-title')).toHaveText(M.loginTitle);
    await installed(page);
    await page.getByTestId('lock').click();

    // Really offline: server stopped AND network emulation off.
    await s.stop();
    await ctx.setOffline(true);
    await page.reload();
    await unlock(page);
    await expect(page.locator('.item-list .title', { hasText: M.loginTitle })).toBeVisible();
    // Local login icon offline too (lazy brand chunk came from the cache).
    await expect(page.locator('.item-list km-item-icon [data-icon=brand]')).toHaveAttribute('data-brand', 'github');
    await page.screenshot({ path: testInfo.outputPath('offline-unlocked.png') });
    // QR import offline (zxing worker and WASM from the cache), no camera needed.
    await newItem(page, 'totp');
    await page.getByTestId('qr-file').setInputFiles({ name: 'qr.png', mimeType: 'image/png', buffer: await qrPng(RFC_URI) });
    await expect(page.getByTestId('qr-status')).toHaveAttribute('data-state', 'found');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByTestId('totp-code')).toHaveText(/^\d{8}$/);

    // CacheStorage: the app's own versioned files plus the worker's bookkeeping
    // (":db:" caches: manifests and version assignments). No secret anywhere.
    const dump = await cacheDump(page);
    expect(dump.entries.length).toBeGreaterThan(10);
    for (const { cache, url } of dump.entries) {
      if (/:db:/.test(cache)) continue;
      expect(cache, url).toMatch(/:assets:app:cache$/);
      expect(url, 'cached URL').toMatch(/^\/(index\.html|favicon\.ico|manifest\.webmanifest|preferences-boot\.js|(main|chunk|worker|styles)-[\w-]+\.(js|css)|wasm\/[\w_]+\.wasm|icons\/[\w-]+\.png)$/);
    }
    const lower = dump.text.toLowerCase();
    for (const secret of [PW, code, M.password, M.loginTitle, M.totpSecret, 'synthissuer']) {
      expect(lower.includes(secret.toLowerCase()), 'secret in CacheStorage').toBe(false);
    }
    expect(errors).toEqual([]);
  } finally {
    await ctx.close();
    await s.stop();
  }
});

test('update: v1 → v2 is offered, never forced; an open vault asks and locks first; no mixed versions; IndexedDB kept', async ({ browser }, testInfo) => {
  const s = await site(testInfo.outputPath(), 4322);
  const ctx = await browser.newContext({ baseURL: s.origin });
  const page = await ctx.newPage();
  try {
    await start(page, 'synthetic-fixture');
    await newItem(page, 'secure_note');
    await page.locator('input[name=title]').fill('Synthetic kept note');
    await page.locator('textarea[name=body]').fill('synthetic body');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.locator('#detail-title')).toHaveText('Synthetic kept note');
    await installed(page);
    expect(await page.evaluate(() => (window as { __kmVersion?: number }).__kmVersion)).toBeUndefined();

    // Deploy v2: new index.html AND new main bundle content under the same URL.
    deploy(s, (root) => {
      writeFileSync(join(root, 'index.html'), readFileSync(join(root, 'index.html'), 'utf8').replace('<head>', '<head><meta name="km-e2e" content="v2">'));
      writeFileSync(join(root, mainJs(root)), readFileSync(join(root, mainJs(root)), 'utf8') + '\n;window.__kmVersion=2;\n');
    });

    // A navigation lets the worker find v2; the page itself still runs v1.
    await page.reload();
    await page.getByRole('button', { name: en['start.stored.open'] }).click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    await expect(page.getByTestId('update-banner')).toHaveAttribute('data-state', 'ready', { timeout: 30_000 });
    await expect(page.getByTestId('update-banner')).toContainText(en['update.ready']);
    await page.screenshot({ path: testInfo.outputPath('update-banner.png') });
    expect(await page.evaluate(() => (window as { __kmVersion?: number }).__kmVersion)).toBeUndefined();
    await expect(page.locator('meta[name=km-e2e]')).toHaveCount(0);
    // Still fully working on v1 while v2 waits (lazy worker from the v1 cache).
    await newItem(page, 'totp');
    await page.getByTestId('qr-file').setInputFiles({ name: 'qr.png', mimeType: 'image/png', buffer: await qrPng(RFC_URI) });
    await expect(page.getByTestId('qr-status')).toHaveAttribute('data-state', 'found');

    // Open vault + unsaved form: declining keeps everything.
    await page.getByTestId('update-reload').click();
    await expect(page.locator('#confirm-body')).toHaveText(en['update.confirmBody']);
    await page.locator('dialog[open]').getByRole('button', { name: en['common.cancel'] }).click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    await expect(page.getByTestId('qr-status')).toHaveAttribute('data-state', 'found');

    // Accepting locks, then reloads into v2 as a whole.
    await page.getByTestId('update-reload').click();
    await Promise.all([page.waitForEvent('load'), page.getByTestId('confirm-accept').click()]);
    await expect(page.locator('meta[name=km-e2e]')).toHaveAttribute('content', 'v2');
    expect(await page.evaluate(() => (window as { __kmVersion?: number }).__kmVersion)).toBe(2);
    await expect(page.getByTestId('update-banner')).toHaveCount(0);
    // The stored vault was not touched by the update.
    await page.getByRole('button', { name: en['start.stored.open'] }).click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    await expect(page.locator('.item-list .title', { hasText: 'Synthetic kept note' })).toBeVisible();
  } finally {
    await ctx.close();
    await s.stop();
  }
});

test('update with an ephemeral demo vault: the warning says the vault becomes unreadable; declining keeps it', async ({ browser }, testInfo) => {
  const s = await site(testInfo.outputPath(), 4325);
  const ctx = await browser.newContext({ baseURL: s.origin });
  const page = await ctx.newPage();
  try {
    await page.goto('/');
    await installed(page);
    deploy(s, (root) => {
      writeFileSync(join(root, 'index.html'), readFileSync(join(root, 'index.html'), 'utf8').replace('<head>', '<head><meta name="km-e2e" content="v2">'));
    });
    await page.reload(); // the worker finds v2; this page still runs v1
    await page.locator('input[name=mode][value=ephemeral]').check();
    await page.getByTestId('start-vault').click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'ephemeral');
    await expect(page.getByTestId('update-banner')).toHaveAttribute('data-state', 'ready', { timeout: 30_000 });
    // Even locked, a reload would lose the in-memory key.
    await page.getByTestId('lock').click();
    await page.getByTestId('update-reload').click();
    await expect(page.locator('#confirm-body')).toHaveText(en['update.confirmBodyEphemeral']);
    await page.screenshot({ path: testInfo.outputPath('update-ephemeral-warning.png') });
    await page.locator('dialog[open]').getByRole('button', { name: en['common.cancel'] }).click();
    await expect(page.locator('meta[name=km-e2e]')).toHaveCount(0);
    await page.getByTestId('unlock').click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'ephemeral');
  } finally {
    await ctx.close();
    await s.stop();
  }
});

/** Record the service worker's version events on this page (real events, not debug text). */
async function recordSwEvents(page: Page): Promise<void> {
  await page.evaluate(() => {
    const w = window as unknown as { swEvents: string[] };
    w.swEvents = [];
    navigator.serviceWorker.addEventListener('message', (ev) => {
      if (typeof ev.data?.type === 'string') w.swEvents.push(ev.data.type);
    });
  });
}
const swEvents = (page: Page) => page.evaluate(() => (window as unknown as { swEvents: string[] }).swEvents);
const count = async (page: Page, type: string) => (await swEvents(page)).filter((t) => t === type).length;
const swState = (page: Page) => page.evaluate(async () => (await (await fetch('/ngsw/state')).text()).match(/Driver state: (\w+)/)?.[1]);

test('a genuinely failed update: real failure event, degraded warning, bounded retry, online recovery, then offline reopen; ciphertext unchanged', async ({ browser }, testInfo) => {
  const s = await site(testInfo.outputPath(), 4323);
  const ctx = await browser.newContext({ baseURL: s.origin });
  const page = await ctx.newPage();
  try {
    await page.goto('/');
    await installed(page);
    await createPasswordVault(page);
    const before = await storedBytes(page, 'keymesh-vault');
    expect(before.length).toBeGreaterThan(0);
    await recordSwEvents(page);

    // v2 with a NEW main bundle (new expected hash in ngsw.json) ...
    deploy(s, (root) => {
      writeFileSync(join(root, 'index.html'), readFileSync(join(root, 'index.html'), 'utf8').replace('<head>', '<head><meta name="km-e2e" content="v2">'));
      writeFileSync(join(root, mainJs(root)), readFileSync(join(root, mainJs(root)), 'utf8') + '\n;window.__kmVersion=2;\n');
    });
    const goodMain = readFileSync(join(s.root, mainJs(s.root)));
    // ... whose served main is then damaged: the download cannot match its hash.
    writeFileSync(join(s.root, mainJs(s.root)), Buffer.concat([goodMain, Buffer.from('\n/* damaged after hashing */\n')]));

    const other = await ctx.newPage();
    await other.goto('/'); // a navigation makes the worker check for updates
    await other.close();
    await expect.poll(() => count(page, 'VERSION_INSTALLATION_FAILED'), { timeout: 30_000 }).toBe(1);
    expect(await count(page, 'VERSION_READY')).toBe(0);
    expect(await swState(page)).toBe('EXISTING_CLIENTS_ONLY');
    await expect(page.getByTestId('update-banner')).toHaveAttribute('data-state', 'failed');
    await expect(page.getByTestId('update-banner')).toContainText(en['update.failed']);
    await page.screenshot({ path: testInfo.outputPath('update-failed.png') });
    expect((await storedBytes(page, 'keymesh-vault')).equals(before)).toBe(true);

    // A retry while the server is still broken fails again (bounded, reported).
    await page.getByTestId('update-retry').click();
    await expect.poll(() => count(page, 'VERSION_INSTALLATION_FAILED'), { timeout: 30_000 }).toBe(2);
    await expect(page.getByTestId('update-banner')).toHaveAttribute('data-state', 'failed');

    // Degraded and offline: an avoidable reload is warned about first.
    await ctx.setOffline(true);
    const dialog = page.waitForEvent('dialog');
    void page.evaluate(() => location.reload());
    const d = await dialog;
    expect(d.type()).toBe('beforeunload');
    await d.dismiss();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected'); // same page, still open

    // The deployment is fixed; coming back online retries once by itself.
    writeFileSync(join(s.root, mainJs(s.root)), goodMain);
    await ctx.setOffline(false);
    await expect.poll(() => count(page, 'VERSION_READY'), { timeout: 30_000 }).toBe(1);
    expect(await swState(page)).toBe('NORMAL');
    await expect(page.getByTestId('update-banner')).toHaveAttribute('data-state', 'ready');

    // Confirmed reload (vault open: ask, lock) into v2 as a whole.
    await page.getByTestId('update-reload').click();
    await Promise.all([page.waitForEvent('load'), page.getByTestId('confirm-accept').click()]);
    await expect(page.locator('meta[name=km-e2e]')).toHaveAttribute('content', 'v2');
    expect(await page.evaluate(() => (window as { __kmVersion?: number }).__kmVersion)).toBe(2);

    // After recovery the app reopens offline again and unlocks; bytes unchanged.
    await s.stop();
    await ctx.setOffline(true);
    const doc = await page.reload();
    expect(doc?.status()).toBe(200);
    await unlock(page);
    expect((await storedBytes(page, 'keymesh-vault')).equals(before)).toBe(true);
  } finally {
    await ctx.close();
    await s.stop();
  }
});

test('damaged cached app file (core WASM bytes): start fails, Reload alone cannot fix it; confirmed online repair restores the app; vault and settings byte-identical', async ({ browser }, testInfo) => {
  const s = await site(testInfo.outputPath(), 4326);
  const ctx = await browser.newContext({ baseURL: s.origin });
  const page = await ctx.newPage();
  const wasmBytes = readFileSync(join(s.root, 'wasm', 'keymesh_wasm_bg.wasm'));
  try {
    await page.goto('/');
    await installed(page);
    await createPasswordVault(page);
    await page.locator('[data-theme-option="dark"]').click();
    await page.getByTestId('lock').click();
    const before = await storedBytes(page, 'keymesh-vault');
    const prefs = await page.evaluate(() => JSON.stringify(Object.entries(localStorage)));
    expect(prefs).toContain('dark');

    // Damage the cached core WASM response body (same URL and MIME type).
    const damaged = await page.evaluate(async () => {
      let n = 0;
      for (const k of await caches.keys()) {
        if (!k.endsWith(':assets:app:cache')) continue;
        const c = await caches.open(k);
        if (!(await c.match('/wasm/keymesh_wasm_bg.wasm'))) continue;
        await c.put('/wasm/keymesh_wasm_bg.wasm', new Response(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 255, 255]), { headers: { 'content-type': 'application/wasm' } }));
        n++;
      }
      return n;
    });
    expect(damaged).toBe(1);
    const cacheNames = () => page.evaluate(async () => (await caches.keys()).sort());
    const cachesBefore = await cacheNames();

    // Offline: cannot start, and cannot be repaired; nothing is changed.
    await s.stop();
    await ctx.setOffline(true);
    await page.reload();
    await expect(page.getByRole('heading', { name: en['app.failedTitle'] })).toBeVisible();
    await page.getByTestId('repair-app').click();
    await expect(page.locator('#confirm-body')).toHaveText(en['repair.confirmBody']);
    await page.getByTestId('confirm-accept').click();
    await expect(page.getByTestId('repair-status')).toHaveText(en['repair.offline']);
    await page.screenshot({ path: testInfo.outputPath('repair-offline.png') });
    expect(await cacheNames()).toEqual(cachesBefore);

    // Online again: the ordinary Reload still serves the damaged cached file.
    await s.restart();
    await ctx.setOffline(false);
    await page.getByRole('button', { name: en['app.reloadPage'] }).click();
    await expect(page.getByRole('heading', { name: en['app.failedTitle'] })).toBeVisible();
    // Declining the repair changes nothing.
    await page.getByTestId('repair-app').click();
    await page.locator('dialog[open]').getByRole('button', { name: en['common.cancel'] }).click();
    expect(await cacheNames()).toEqual(cachesBefore);
    await page.screenshot({ path: testInfo.outputPath('repair-offered.png') });

    // Confirmed repair: only this app's own caches and worker are replaced.
    await Promise.all([page.waitForEvent('load'), page.getByTestId('repair-app').click().then(() => page.getByTestId('confirm-accept').click())]);
    await unlock(page);
    expect((await storedBytes(page, 'keymesh-vault')).equals(before)).toBe(true);
    expect(await page.evaluate(() => JSON.stringify(Object.entries(localStorage)))).toBe(prefs);
    // Fresh, verified files are cached again (the core WASM matches the server).
    await installed(page);
    const cached = await page.evaluate(async () => {
      const r = await caches.match('/wasm/keymesh_wasm_bg.wasm');
      return r ? Array.from(new Uint8Array(await r.arrayBuffer()).slice(0, 64)) : null;
    });
    expect(Buffer.from(cached!).equals(wasmBytes.subarray(0, 64))).toBe(true);
  } finally {
    await ctx.close();
    await s.stop();
  }
});

test('unrecoverable cache state: the app says so, reload recovers on the new version, stored vault untouched', async ({ browser }, testInfo) => {
  const s = await site(testInfo.outputPath(), 4324);
  const ctx: BrowserContext = await browser.newContext({ baseURL: s.origin });
  const page = await ctx.newPage();
  try {
    await start(page, 'synthetic-fixture');
    await newItem(page, 'secure_note');
    await page.locator('input[name=title]').fill('Synthetic kept note');
    await page.locator('textarea[name=body]').fill('synthetic body');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.locator('#detail-title')).toHaveText('Synthetic kept note');
    await installed(page);
    const chunk = readdirSync(s.root).find((f) => /^chunk-.*\.js$/.test(f))!;
    // The browser evicted the cached copy, and a newer deployment renamed that
    // chunk (as content-hashed builds do), so the old file is gone (404).
    await page.evaluate(async (name) => {
      for (const k of await caches.keys()) await (await caches.open(k)).delete('/' + name);
    }, chunk);
    deploy(s, (root) => {
      const renamed = chunk.replace('chunk-', 'chunk-V2');
      renameSync(join(root, chunk), join(root, renamed));
      for (const f of readdirSync(root).filter((x) => x.endsWith('.js'))) {
        const js = readFileSync(join(root, f), 'utf8');
        if (js.includes(chunk)) writeFileSync(join(root, f), js.split(chunk).join(renamed));
      }
    });
    // The running v1 page needs that file again: v1 can no longer be served consistently.
    await page.evaluate((name) => fetch('/' + name).catch(() => null), chunk);
    await expect(page.getByTestId('update-banner')).toHaveAttribute('data-state', 'broken', { timeout: 30_000 });
    await expect(page.getByTestId('update-banner')).toContainText(en['update.broken']);
    // Vault open: reloading asks first and locks (same path as an update).
    await page.getByTestId('update-reload').click();
    await expect(page.locator('#confirm-body')).toHaveText(en['update.confirmBody']);
    await Promise.all([page.waitForEvent('load'), page.getByTestId('confirm-accept').click()]);
    await expect(page.getByTestId('update-banner')).toHaveCount(0);
    await page.getByRole('button', { name: en['start.stored.open'] }).click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    await expect(page.locator('.item-list .title', { hasText: 'Synthetic kept note' })).toBeVisible();
    // The recovered page runs the new deployment's chunk, not a mix.
    const loaded = await page.evaluate(() => performance.getEntriesByType('resource').map((e) => new URL(e.name).pathname));
    expect(loaded.some((u) => u.includes('chunk-V2'))).toBe(true);
  } finally {
    await ctx.close();
    await s.stop();
  }
});
