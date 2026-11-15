/**
 * TOTP from a QR code (upload, paste, camera) and the circular countdown.
 * Real production build, real WASM core and the real zxing-wasm decoder in
 * its worker. SYNTHETIC DATA ONLY: the secret is the public RFC 6238 vector,
 * QR images and the fake-camera clip are generated at test time. The secret
 * is never printed; the setup field stays masked.
 */
import { chromium, expect, Page, test } from '@playwright/test';
import { en } from '../src/app/core/i18n/en';
import { M, RFC_URI, newItem, openItem, start } from './helpers';
import { qrPng, qrY4m } from './qr-fixtures';

async function openTotpForm(page: Page): Promise<void> {
  await start(page, 'synthetic-fixture');
  await newItem(page, 'totp');
  await expect(page.getByTestId('qr-import')).toBeVisible();
}

async function upload(page: Page, name: string, mimeType: string, buffer: Buffer): Promise<void> {
  await page.getByTestId('qr-file').setInputFiles({ name, mimeType, buffer });
}

const status = (page: Page) => page.getByTestId('qr-status');

test('QR image upload fills a masked TOTP setup; the core validates it on save; code and countdown follow the clock', async ({ page }) => {
  await page.clock.setFixedTime(new Date(55_000));
  await openTotpForm(page);
  const before = await page.evaluate(() => performance.getEntriesByType('resource').length);
  await upload(page, 'qr.png', 'image/png', await qrPng(RFC_URI));
  await expect(status(page)).toHaveAttribute('data-state', 'found');
  await expect(status(page)).toContainText(en['qr.found']);
  // Masked, filled from the code; empty fields pre-filled from the URI.
  const setup = page.locator('input[name=totpSetup]');
  await expect(setup).toHaveAttribute('type', 'password');
  expect((await setup.inputValue()) === RFC_URI).toBe(true);
  await expect(page.locator('input[name=issuer]')).toHaveValue('SynthIssuer');
  await expect(page.locator('input[name=accountName]')).toHaveValue('synth');
  await expect(page.locator('input[name=title]')).toHaveValue('SynthIssuer');
  // Decoding made no network request beyond the app's own (already loaded) files.
  const urls = await page.evaluate((n) => performance.getEntriesByType('resource').slice(n).map((e) => e.name), before);
  const origin = new URL(page.url()).origin;
  expect(urls.every((u) => u.startsWith(origin + '/'))).toBe(true);
  expect(urls.some((u) => /jsdelivr|unpkg|cdn/.test(u))).toBe(false);

  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.locator('#detail-title')).toHaveText('SynthIssuer');
  // RFC 6238 SHA-1, 8 digits, T=55 → same 30 s window as T=59.
  await expect(page.getByTestId('totp-code')).toHaveText('94287082');
  await expect(page.getByTestId('totp-remaining')).toHaveText('5s left — new code soon');
  await expect(page.getByTestId('totp-ring')).toHaveAttribute('data-warn', 'true');
  await expect(page.locator('.totp-card')).toHaveClass(/warn/);
  // Rollover: next window starts full, no warning, new code.
  await page.clock.setFixedTime(new Date(60_000));
  await expect(page.getByTestId('totp-remaining')).toHaveText('30s remaining', { timeout: 5000 });
  await expect(page.getByTestId('totp-ring')).toHaveAttribute('data-warn', 'false');
  await expect(page.getByTestId('totp-code')).not.toHaveText('94287082');
  await page.clock.setFixedTime(new Date(66_000));
  await expect(page.getByTestId('totp-remaining')).toHaveText('24s remaining', { timeout: 5000 });
});

test('pasting a QR image works; other QR contents and bad files are refused without being used', async ({ page }) => {
  await openTotpForm(page);
  const setup = page.locator('input[name=totpSetup]');

  // Paste (clipboard image) on the form.
  const png = (await qrPng(RFC_URI)).toString('base64');
  await page.locator('input[name=title]').focus();
  await page.evaluate(async (b64) => {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const dt = new DataTransfer();
    dt.items.add(new File([bytes], 'pasted.png', { type: 'image/png' }));
    document.activeElement!.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  }, png);
  await expect(status(page)).toHaveAttribute('data-state', 'found');
  expect((await setup.inputValue()) === RFC_URI).toBe(true);
  await setup.fill('');

  for (const [text, state, key] of [
    ['https://synthmark-url.example.test/not-a-totp', 'other', 'qr.err.other'],
    [`otpauth://hotp/Synth:x?secret=${M.totpSecret}&counter=1`, 'hotp', 'qr.err.hotp'],
    ['otpauth-migration://offline?data=U1lOVEhFVElD', 'migration', 'qr.err.migration'],
  ] as const) {
    await upload(page, 'other.png', 'image/png', await qrPng(text));
    await expect(status(page)).toHaveAttribute('data-state', state);
    await expect(status(page)).toHaveText(en[key]);
    await expect(setup).toHaveValue('');
    // The refused content is never shown.
    await expect(page.locator('body')).not.toContainText('synthmark-url');
  }

  // Not an image / SVG / HTML / truncated: refused before decoding.
  await upload(page, 'x.svg', 'image/svg+xml', Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'));
  await expect(status(page)).toHaveAttribute('data-state', 'unsupported');
  await upload(page, 'x.png', 'image/png', Buffer.from('<!doctype html><script>alert(1)</script>'));
  await expect(status(page)).toHaveAttribute('data-state', 'unsupported');
  // Decompression bomb: a tiny file declaring a 30000×30000 canvas.
  const be32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
  const bomb = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...be32(13), 0x49, 0x48, 0x44, 0x52, ...be32(30000), ...be32(30000), 8, 6, 0, 0, 0, 0, 0, 0, 0]);
  await upload(page, 'bomb.png', 'image/png', bomb);
  await expect(status(page)).toHaveAttribute('data-state', 'tooManyPixels');
  // Oversized file.
  await upload(page, 'big.png', 'image/png', Buffer.concat([await qrPng(RFC_URI), Buffer.alloc(8 * 1024 * 1024)]));
  await expect(status(page)).toHaveAttribute('data-state', 'tooLarge');
  // A real image without a QR code.
  const blank = await page.evaluate(async () => {
    const c = new OffscreenCanvas(200, 200);
    const ctx = c.getContext('2d')!;
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, 200, 200);
    const b = await c.convertToBlob({ type: 'image/png' });
    return btoa(String.fromCharCode(...new Uint8Array(await b.arrayBuffer())));
  });
  await upload(page, 'blank.png', 'image/png', Buffer.from(blank, 'base64'));
  await expect(status(page)).toHaveAttribute('data-state', 'notFound');
  await expect(setup).toHaveValue('');

  // A malformed TOTP URI is still validated by the core on save.
  await upload(page, 'bad.png', 'image/png', await qrPng('otpauth://totp/Synth:x?secret=NOT*BASE32'));
  await expect(status(page)).toHaveAttribute('data-state', 'found');
  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByTestId('form-error')).toContainText(en['errors.totpSecret']);
  await expect(page.locator('#detail-title')).toHaveCount(0); // nothing was saved
});

test('locking while a QR image is being read cancels it and clears the form', async ({ page }) => {
  await openTotpForm(page);
  await upload(page, 'qr.png', 'image/png', await qrPng(RFC_URI));
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('qr-import')).toHaveCount(0);
  await expect(page.locator('input[name=totpSetup]')).toHaveCount(0);
});

test('camera: denied permission is explained; unsupported origins show no camera button', async ({ browser }) => {
  // Headless Chromium without a permission grant rejects getUserMedia.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await openTotpForm(page);
  await page.getByTestId('qr-camera').click();
  await expect(page.getByTestId('qr-camera-status')).toHaveText(
    new RegExp(`${en['qr.cameraDenied']}|${en['qr.cameraUnavailable']}`.replace(/[.?()]/g, '\\$&')),
  );
  await page.getByTestId('qr-camera-cancel').click();
  await expect(page.getByTestId('qr-dialog')).not.toHaveAttribute('open', '');
  await ctx.close();

  // Plain-HTTP non-loopback name: not a secure context, so no camera button;
  // image import still works there.
  const plain = await chromium.launch({ args: ['--host-resolver-rules=MAP keymesh-http.test 127.0.0.1'] });
  try {
    const p2 = await (await plain.newContext()).newPage();
    await p2.goto('http://keymesh-http.test:4310/');
    expect(await p2.evaluate(() => isSecureContext)).toBe(false);
    await p2.locator('input[name=mode][value=synthetic-fixture]').check();
    await p2.getByTestId('start-vault').click();
    await newItem(p2, 'totp');
    await expect(p2.getByTestId('qr-camera')).toHaveCount(0);
    await expect(p2.getByTestId('qr-import')).toContainText(en['qr.hintNoCamera']);
    await upload(p2, 'qr.png', 'image/png', await qrPng(RFC_URI));
    await expect(p2.getByTestId('qr-status')).toHaveAttribute('data-state', 'found');
  } finally {
    await plain.close();
  }
});

test('camera: a QR code in the live stream is read, then every track is stopped', async ({}, testInfo) => {
  const clip = testInfo.outputPath('qr.y4m');
  await qrY4m(RFC_URI, clip);
  const browser = await chromium.launch({
    args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${clip}`],
  });
  try {
    const ctx = await browser.newContext({ baseURL: testInfo.project.use.baseURL, permissions: ['camera'] });
    const page = await ctx.newPage();
    // Count live camera tracks the page holds.
    await page.addInitScript(() => {
      const live = new Set<MediaStreamTrack>();
      (window as unknown as { liveTracks: () => number }).liveTracks = () => [...live].filter((t) => t.readyState === 'live').length;
      const orig = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = async (c) => {
        const s = await orig(c);
        s.getTracks().forEach((t) => live.add(t));
        return s;
      };
    });
    await openTotpForm(page);
    await page.getByTestId('qr-camera').click();
    await expect(page.getByTestId('qr-dialog')).toHaveAttribute('open', '');
    await expect(status(page)).toHaveAttribute('data-state', 'found', { timeout: 20_000 });
    await expect(page.getByTestId('qr-dialog')).not.toHaveAttribute('open', '');
    expect(await page.evaluate(() => (window as unknown as { liveTracks: () => number }).liveTracks())).toBe(0);
    expect((await page.locator('input[name=totpSetup]').inputValue()) === RFC_URI).toBe(true);

    // Cancel and lock both stop the camera.
    await page.locator('input[name=totpSetup]').fill('');
    await page.getByTestId('qr-camera').click();
    await expect.poll(() => page.evaluate(() => (window as unknown as { liveTracks: () => number }).liveTracks())).toBe(1);
    await page.getByTestId('qr-camera-cancel').click();
    await expect.poll(() => page.evaluate(() => (window as unknown as { liveTracks: () => number }).liveTracks())).toBe(0);
    await page.getByTestId('qr-camera').click();
    await expect.poll(() => page.evaluate(() => (window as unknown as { liveTracks: () => number }).liveTracks())).toBe(1);
    await page.keyboard.press('Escape');
    await expect.poll(() => page.evaluate(() => (window as unknown as { liveTracks: () => number }).liveTracks())).toBe(0);
    await ctx.close();
  } finally {
    await browser.close();
  }
});

test('the countdown is decorative; seconds are text, and reduced motion stops the animation', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.clock.setFixedTime(new Date(40_000));
  await start(page, 'synthetic-fixture');
  await newItem(page, 'totp');
  await page.locator('input[name=title]').fill('Synthetic TOTP');
  await page.locator('input[name=totpSetup]').fill(RFC_URI);
  await page.getByRole('button', { name: 'Create' }).click();
  await openItem(page, 'Synthetic TOTP');
  await expect(page.getByTestId('totp-ring')).toHaveAttribute('aria-hidden', 'true');
  await expect(page.getByTestId('totp-remaining')).toHaveText('20s remaining');
  // The app-wide reduced-motion rule shortens every transition to 0.01 ms.
  const transition = await page.locator('.totp-ring .arc').evaluate((el) => getComputedStyle(el).transitionDuration);
  expect(Math.max(...transition.split(',').map((t) => parseFloat(t)))).toBeLessThan(0.001);
});
