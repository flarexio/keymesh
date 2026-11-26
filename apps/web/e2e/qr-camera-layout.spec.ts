/**
 * TOTP QR camera preview layout: the preview box sits centred in the dialog,
 * the video fills it (object-fit: cover, centred), and the scan guide frame is
 * centred on the preview, on a 390×844 phone and on desktop, with landscape
 * (640×480) and portrait (480×640) camera tracks.
 *
 * Chromium's FAKE camera (--use-fake-device-for-media-stream with a generated
 * Y4M clip). This checks layout geometry only. It is NOT a test on a real
 * phone camera (real tracks, rotation and browser UI may differ).
 */
import { Browser, Page, TestInfo, chromium, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { newItem, start } from './helpers';
import { centreMarkY4m } from './qr-fixtures';

function shot(info: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return info.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

type Box = { x: number; y: number; width: number; height: number };
const cx = (b: Box) => b.x + b.width / 2;
const cy = (b: Box) => b.y + b.height / 2;

const viewports = [
  { name: 'phone', viewport: { width: 390, height: 844 }, mobile: true },
  { name: 'desktop', viewport: { width: 1280, height: 800 }, mobile: false },
] as const;
const tracks = [
  { name: 'landscape', w: 640, h: 480 },
  { name: 'portrait', w: 480, h: 640 },
] as const;

async function openCamera(browser: Browser, info: TestInfo, vp: (typeof viewports)[number]): Promise<Page> {
  const ctx = await browser.newContext({
    baseURL: info.project.use.baseURL,
    permissions: ['camera'],
    viewport: vp.viewport,
    isMobile: vp.mobile,
    hasTouch: vp.mobile,
  });
  const page = await ctx.newPage();
  await start(page, 'synthetic-fixture');
  await newItem(page, 'totp');
  await page.getByTestId('qr-camera').click();
  await expect(page.getByTestId('qr-dialog')).toHaveAttribute('open', '');
  await page.waitForFunction(() => {
    const v = document.querySelector<HTMLVideoElement>('.qr-video video');
    return !!v && v.readyState >= 2 && v.videoWidth > 0;
  });
  return page;
}

for (const t of tracks) {
  for (const vp of viewports) {
    test(`camera preview and guide frame are centred: ${vp.name}, ${t.name} track (fake camera)`, async ({}, info) => {
      const clip = info.outputPath(`centre-${t.w}x${t.h}.y4m`);
      centreMarkY4m(clip, t.w, t.h);
      const browser = await chromium.launch({
        args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', `--use-file-for-fake-video-capture=${clip}`],
      });
      try {
        const page = await openCamera(browser, info, vp);
        const g = await page.evaluate(() => {
          const r = (el: Element) => {
            const b = el.getBoundingClientRect();
            return { x: b.x, y: b.y, width: b.width, height: b.height };
          };
          const dialog = document.querySelector('[data-testid=qr-dialog]')!;
          const body = dialog.querySelector('.qr-dialog-body')!;
          const box = dialog.querySelector('.qr-video')!;
          const video = box.querySelector('video')!;
          const frame = box.querySelector('[data-testid=qr-frame]');
          const ds = getComputedStyle(dialog);
          const vs = getComputedStyle(video);
          return {
            vw: document.documentElement.clientWidth,
            vh: window.innerHeight,
            dialog: r(dialog),
            padL: parseFloat(ds.paddingLeft) + parseFloat(ds.borderLeftWidth),
            padR: parseFloat(ds.paddingRight) + parseFloat(ds.borderRightWidth),
            body: r(body),
            box: r(box),
            video: r(video),
            frame: frame ? r(frame) : null,
            frameHidden: frame?.getAttribute('aria-hidden'),
            fit: vs.objectFit,
            pos: vs.objectPosition,
            track: [video.videoWidth, video.videoHeight],
            scrollW: document.documentElement.scrollWidth,
          };
        });
        await page.screenshot({ path: shot(info, `qr-camera-${vp.name}-${t.name}-fake-camera.png`) });

        // The stream really is the requested orientation (fake device honours the clip).
        expect(g.track).toEqual([t.w, t.h]);
        // Dialog centred in the viewport, nothing wider than the page.
        expect(Math.abs(cx(g.dialog) - g.vw / 2)).toBeLessThanOrEqual(1.5);
        expect(g.scrollW).toBeLessThanOrEqual(g.vw);
        // The body and the preview box stay inside the dialog's content box, centred.
        const inner = { x: g.dialog.x + g.padL, width: g.dialog.width - g.padL - g.padR };
        expect(g.body.x).toBeGreaterThanOrEqual(inner.x - 0.5);
        expect(g.body.x + g.body.width).toBeLessThanOrEqual(inner.x + inner.width + 0.5);
        expect(Math.abs(cx(g.box) - (inner.x + inner.width / 2))).toBeLessThanOrEqual(1.5);
        // The video fills the box exactly, and the stream is cropped around its centre.
        expect(Math.abs(g.video.x - g.box.x)).toBeLessThanOrEqual(0.5);
        expect(Math.abs(g.video.y - g.box.y)).toBeLessThanOrEqual(0.5);
        expect(Math.abs(g.video.width - g.box.width)).toBeLessThanOrEqual(0.5);
        expect(Math.abs(g.video.height - g.box.height)).toBeLessThanOrEqual(0.5);
        expect(g.fit).toBe('cover');
        expect(g.pos).toBe('50% 50%');
        // The guide frame is decorative and centred on the preview, both ways, and fits inside it.
        expect(g.frame).not.toBeNull();
        expect(g.frameHidden).toBe('true');
        const f = g.frame!;
        expect(Math.abs(cx(f) - cx(g.box))).toBeLessThanOrEqual(1);
        expect(Math.abs(cy(f) - cy(g.box))).toBeLessThanOrEqual(1);
        expect(f.x).toBeGreaterThanOrEqual(g.box.x);
        expect(f.y).toBeGreaterThanOrEqual(g.box.y);
        expect(f.x + f.width).toBeLessThanOrEqual(g.box.x + g.box.width + 0.5);
        expect(f.y + f.height).toBeLessThanOrEqual(g.box.y + g.box.height + 0.5);
        expect(Math.abs(f.width - f.height)).toBeLessThanOrEqual(1);

        // The centre mark of the stream is drawn at the centre of the preview
        // (sample the rendered pixels: dark at the centre, grey at the corners).
        const png = await page.locator('.qr-video').screenshot();
        const lum = await page.evaluate(async (b64) => {
          // An <img> (CSP allows data: images; connect-src would block fetch).
          const img = new Image();
          img.src = `data:image/png;base64,${b64}`;
          await img.decode();
          const c = new OffscreenCanvas(img.width, img.height);
          const ctx = c.getContext('2d')!;
          ctx.drawImage(img, 0, 0);
          const at = (x: number, y: number) => {
            const d = ctx.getImageData(Math.round(x), Math.round(y), 1, 1).data;
            return (d[0] + d[1] + d[2]) / 3;
          };
          // Just off the guide frame's corner lines, away from its stroke.
          return { centre: at(img.width / 2, img.height / 2), corner: at(img.width * 0.06, img.height * 0.06) };
        }, png.toString('base64'));
        expect(lum.centre).toBeLessThan(60);
        expect(lum.corner).toBeGreaterThan(90);
        await page.context().close();
      } finally {
        await browser.close();
      }
    });
  }
}
