/**
 * QR import lifecycle: one operation at a time, and no late result, worker,
 * timer or camera track survives cancel, lock, hide, destroy or supersession.
 *
 * Deterministic gates (test-only init script): getUserMedia and video.play()
 * can be held and released; Worker construction/termination is counted so a
 * "no live worker" assertion is never vacuous. A pending file decode is held
 * by routing the decoder's WASM fetch. The service worker is blocked so the
 * route sees that fetch. SYNTHETIC DATA ONLY (public RFC 6238 secret).
 */
import { Browser, BrowserContext, Page, Route, TestInfo, chromium, expect, test } from '@playwright/test';
import { en } from '../src/app/core/i18n/en';
import { M, RFC_URI, newItem, start } from './helpers';
import { qrPng, qrY4m } from './qr-fixtures';

const CAM_URI = `otpauth://totp/CamIssuer:cam?secret=${M.totpSecret}&issuer=CamIssuer`;
const FILE_URI = `otpauth://totp/FileIssuer:file?secret=${M.totpSecret}&issuer=FileIssuer`;

/** Test-only gates and counters, installed before the app loads. */
function gates(): void {
  type Gate = { hold: boolean; waiting: (() => void)[] };
  const g: Record<'gum' | 'play', Gate> = { gum: { hold: false, waiting: [] }, play: { hold: false, waiting: [] } };
  const live = new Set<MediaStreamTrack>();
  const workers = { created: 0, terminated: 0 };
  const w = window as unknown as Record<string, unknown>;
  const wait = (k: 'gum' | 'play') => (g[k].hold ? new Promise<void>((r) => g[k].waiting.push(r)) : Promise.resolve());
  w['__hold'] = (k: 'gum' | 'play') => (g[k].hold = true);
  w['__pending'] = (k: 'gum' | 'play') => g[k].waiting.length;
  /** Release and let every continuation of the released call run (one macrotask). */
  w['__release'] = async (k: 'gum' | 'play') => {
    g[k].hold = false;
    g[k].waiting.splice(0).forEach((r) => r());
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
  };
  w['__liveTracks'] = () => [...live].filter((t) => t.readyState === 'live').length;
  w['__workers'] = () => ({ ...workers, live: workers.created - workers.terminated });
  if (navigator.mediaDevices?.getUserMedia) {
    const gum = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = async (c) => {
      const s = await gum(c);
      s.getTracks().forEach((t) => live.add(t));
      await wait('gum');
      return s;
    };
  }
  const play = HTMLMediaElement.prototype.play;
  HTMLMediaElement.prototype.play = async function (this: HTMLMediaElement) {
    await play.call(this);
    await wait('play');
  };
  const NativeWorker = window.Worker;
  window.Worker = class extends NativeWorker {
    private done = false;
    constructor(url: string | URL, opts?: WorkerOptions) {
      super(url, opts);
      workers.created++;
    }
    override terminate(): void {
      if (!this.done) workers.terminated++;
      this.done = true;
      super.terminate();
    }
  };
}

const call = <T>(page: Page, fn: string, arg?: string) =>
  page.evaluate(([f, a]) => (window as unknown as Record<string, (x?: string) => T>)[f](a), [fn, arg] as const);
const workers = (page: Page) => call<{ created: number; terminated: number; live: number }>(page, '__workers');
const liveTracks = (page: Page) => call<number>(page, '__liveTracks');

/** Chromium whose fake camera shows `uri` as a QR code. */
async function cameraBrowser(testInfo: TestInfo, uri: string): Promise<Browser> {
  const clip = testInfo.outputPath('cam.y4m');
  await qrY4m(uri, clip);
  return chromium.launch({
    args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${clip}`],
  });
}

async function page(browser: Browser, testInfo: TestInfo): Promise<{ ctx: BrowserContext; page: Page }> {
  const ctx = await browser.newContext({
    baseURL: testInfo.project.use.baseURL,
    permissions: ['camera'],
    serviceWorkers: 'block',
  });
  await ctx.addInitScript(gates);
  return { ctx, page: await ctx.newPage() };
}

/** Hold the decoder WASM fetch of the next QR worker (keeps one file decode pending). */
async function holdNextDecoder(ctx: BrowserContext): Promise<{ held: Promise<void>; release: () => Promise<void> }> {
  let route: Route | null = null;
  let heldResolve!: () => void;
  const held = new Promise<void>((r) => (heldResolve = r));
  let first = true;
  await ctx.route(/\/wasm\/zxing_reader\.wasm$/, async (r) => {
    if (!first) {
      await r.continue();
      return;
    }
    first = false;
    route = r;
    heldResolve();
  });
  return {
    held,
    release: async () => {
      await (route as Route | null)?.continue().catch(() => undefined);
    },
  };
}

async function totpForm(p: Page): Promise<void> {
  await start(p, 'synthetic-fixture');
  await newItem(p, 'totp');
  await expect(p.getByTestId('qr-import')).toBeVisible();
}

const setup = (p: Page) => p.locator('input[name=totpSetup]');
const isUri = async (p: Page, uri: string) => (await setup(p).inputValue()) === uri;

/** Hidden page, as the browser reports it on tab switch / app switch. */
async function hide(p: Page): Promise<void> {
  await p.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
}
async function show(p: Page): Promise<void> {
  await p.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
}

test.describe('camera start: a cancelled run never installs anything after play() or permission', () => {
  for (const [stop, how] of [
    ['cancel', async (p: Page) => p.getByTestId('qr-camera-cancel').click()],
    ['Escape', async (p: Page) => p.keyboard.press('Escape')],
    // The camera dialog is modal, so a user cannot press Lock while it is
    // open; a lock then comes from elsewhere (e.g. auto-lock). Dispatch the
    // button's click directly to run the same lock path.
    ['lock', async (p: Page) => p.getByTestId('lock').dispatchEvent('click')],
    ['hide', hide],
    ['pagehide', async (p: Page) => p.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })))],
  ] as const) {
    test(`play() pending, then ${stop}`, async ({}, testInfo) => {
      const browser = await cameraBrowser(testInfo, CAM_URI);
      try {
        const { page: p } = await page(browser, testInfo);
        await totpForm(p);
        await call(p, '__hold', 'play');
        await p.getByTestId('qr-camera').click();
        await expect.poll(() => call<number>(p, '__pending', 'play')).toBe(1);
        expect(await liveTracks(p)).toBe(1);
        await how(p);
        await expect.poll(() => liveTracks(p)).toBe(0);
        await call(p, '__release', 'play');
        // The late continuation created no worker, timer or track.
        expect(await workers(p)).toEqual({ created: 0, terminated: 0, live: 0 });
        expect(await liveTracks(p)).toBe(0);
        if (stop === 'hide') await show(p);
        // pagehide locks the vault too (auto-lock, M5 C2; bfcache rule).
        if (stop === 'lock' || stop === 'pagehide') {
          await p.getByTestId('unlock').click(); // locked in this session: Unlock
          await expect(p.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
          await newItem(p, 'totp');
        }
        // A new run works and owns its own worker.
        await p.getByTestId('qr-camera').click();
        await expect(p.getByTestId('qr-status')).toHaveAttribute('data-state', 'found', { timeout: 20_000 });
        expect(await isUri(p, CAM_URI)).toBe(true);
        await expect.poll(() => liveTracks(p)).toBe(0);
        const w = await workers(p);
        expect(w.created).toBeGreaterThan(0);
        expect(w.live).toBe(0);
      } finally {
        await browser.close();
      }
    });
  }

  test('permission pending, then cancel; a new run is not disturbed by the old grant', async ({}, testInfo) => {
    const browser = await cameraBrowser(testInfo, CAM_URI);
    try {
      const { page: p } = await page(browser, testInfo);
      await totpForm(p);
      await call(p, '__hold', 'gum');
      await p.getByTestId('qr-camera').click();
      await expect.poll(() => call<number>(p, '__pending', 'gum')).toBe(1);
      await p.getByTestId('qr-camera-cancel').click();
      await p.getByTestId('qr-camera').click(); // second run, also held
      await expect.poll(() => call<number>(p, '__pending', 'gum')).toBe(2);
      await call(p, '__release', 'gum');
      await expect(p.getByTestId('qr-status')).toHaveAttribute('data-state', 'found', { timeout: 20_000 });
      await expect.poll(() => liveTracks(p)).toBe(0);
      const w = await workers(p);
      expect(w.created).toBe(1); // only the current run made a worker
      expect(w.live).toBe(0);
    } finally {
      await browser.close();
    }
  });
});

test.describe('one QR operation at a time: the newest wins, in both completion orders', () => {
  test('a pending file decode is superseded by the camera and can never overwrite its result', async ({}, testInfo) => {
    const browser = await cameraBrowser(testInfo, CAM_URI);
    try {
      const { ctx, page: p } = await page(browser, testInfo);
      await totpForm(p);
      const gate = await holdNextDecoder(ctx);
      await p.getByTestId('qr-file').setInputFiles({ name: 'f.png', mimeType: 'image/png', buffer: await qrPng(FILE_URI) });
      await gate.held; // the file decode is now pending in its worker
      expect((await workers(p)).live).toBe(1);
      await p.getByTestId('qr-camera').click();
      await expect(p.getByTestId('qr-status')).toHaveAttribute('data-state', 'found', { timeout: 20_000 });
      expect(await isUri(p, CAM_URI)).toBe(true);
      await gate.release(); // the old file decode may now try to finish
      await expect.poll(async () => (await workers(p)).live).toBe(0);
      expect((await workers(p)).created).toBe(2);
      expect(await isUri(p, CAM_URI)).toBe(true);
      await expect(p.locator('input[name=issuer]')).toHaveValue('CamIssuer');
    } finally {
      await browser.close();
    }
  });

  test('an image pasted while the camera is starting supersedes it; the late camera run does nothing', async ({}, testInfo) => {
    const browser = await cameraBrowser(testInfo, CAM_URI);
    try {
      const { page: p } = await page(browser, testInfo);
      await totpForm(p);
      await call(p, '__hold', 'play');
      await p.getByTestId('qr-camera').click();
      await expect.poll(() => call<number>(p, '__pending', 'play')).toBe(1);
      const png = (await qrPng(FILE_URI)).toString('base64');
      await p.evaluate(async (b64) => {
        const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        const dt = new DataTransfer();
        dt.items.add(new File([bytes], 'p.png', { type: 'image/png' }));
        document.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
      }, png);
      await expect(p.getByTestId('qr-status')).toHaveAttribute('data-state', 'found');
      expect(await isUri(p, FILE_URI)).toBe(true);
      await expect(p.getByTestId('qr-dialog')).not.toHaveAttribute('open', '');
      await call(p, '__release', 'play');
      await expect.poll(() => liveTracks(p)).toBe(0);
      await expect.poll(async () => (await workers(p)).live).toBe(0);
      expect((await workers(p)).created).toBe(1); // the file's worker only
      expect(await isUri(p, FILE_URI)).toBe(true);
      await expect(p.locator('input[name=issuer]')).toHaveValue('FileIssuer');
    } finally {
      await browser.close();
    }
  });

  test('typing a setup by hand cancels a pending file decode', async ({ browser }, testInfo) => {
    const { ctx, page: p } = await page(browser, testInfo);
    await totpForm(p);
    const gate = await holdNextDecoder(ctx);
    await p.getByTestId('qr-file').setInputFiles({ name: 'f.png', mimeType: 'image/png', buffer: await qrPng(FILE_URI) });
    await gate.held;
    await setup(p).fill(RFC_URI);
    await gate.release();
    await expect.poll(async () => (await workers(p)).live).toBe(0);
    expect((await workers(p)).created).toBe(1);
    expect(await isUri(p, RFC_URI)).toBe(true);
    await expect(p.getByTestId('qr-status')).toHaveCount(0);
    await ctx.close();
  });
});

test.describe('a pending file decode is dropped on lock and hide; nothing reappears afterwards', () => {
  test('lock while decoding, release, unlock: the new form is empty', async ({ browser }, testInfo) => {
    const { ctx, page: p } = await page(browser, testInfo);
    await totpForm(p);
    const gate = await holdNextDecoder(ctx);
    await p.getByTestId('qr-file').setInputFiles({ name: 'f.png', mimeType: 'image/png', buffer: await qrPng(FILE_URI) });
    await gate.held;
    expect((await workers(p)).live).toBe(1);
    await p.getByTestId('lock').click();
    await gate.release();
    await expect.poll(async () => (await workers(p)).live).toBe(0);
    expect((await workers(p)).created).toBe(1);
    await p.getByTestId('unlock').click(); // locked in this session: Unlock
    await expect(p.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    await newItem(p, 'totp');
    await expect(setup(p)).toHaveValue('');
    await expect(p.getByTestId('qr-status')).toHaveCount(0);
    await ctx.close();
  });

  test('hide while decoding: the result never fills the hidden form', async ({ browser }, testInfo) => {
    const { ctx, page: p } = await page(browser, testInfo);
    await totpForm(p);
    const gate = await holdNextDecoder(ctx);
    await p.getByTestId('qr-file').setInputFiles({ name: 'f.png', mimeType: 'image/png', buffer: await qrPng(FILE_URI) });
    await gate.held;
    await hide(p);
    await gate.release();
    await expect.poll(async () => (await workers(p)).live).toBe(0);
    expect((await workers(p)).created).toBe(1);
    await show(p);
    await expect(setup(p)).toHaveValue('');
    await expect(p.getByTestId('qr-status')).toHaveCount(0);
    await ctx.close();
  });
});
