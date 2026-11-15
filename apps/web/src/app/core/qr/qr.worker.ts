/// <reference lib="webworker" />
/**
 * QR decoder worker: zxing-cpp compiled to WebAssembly (zxing-wasm), loaded
 * from this app's own /wasm/ directory, never from a CDN. Runs isolated from
 * the vault: a hostile image can at worst crash this worker, which the page
 * then terminates. Nothing is logged and no network request carries content.
 */
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import { QR_DECODE_SIDE, type QrRequest, type QrResponse } from './qr-messages';

prepareZXingModule({
  overrides: {
    // Self-hosted binary, copied at build time (angular.json assets).
    locateFile: (path: string, prefix: string) =>
      path.endsWith('.wasm') ? new URL('wasm/zxing_reader.wasm', self.location.href).href : prefix + path,
  },
});

async function pixels(req: QrRequest): Promise<ImageData> {
  let bitmap: ImageBitmap;
  if (req.kind === 'frame') {
    bitmap = req.bitmap;
  } else {
    // Header bounds were checked by the page; still scale while decoding.
    const probe = await createImageBitmap(req.blob);
    const scale = Math.min(1, QR_DECODE_SIDE / Math.max(probe.width, probe.height));
    if (scale === 1) {
      bitmap = probe;
    } else {
      probe.close();
      bitmap = await createImageBitmap(req.blob, {
        resizeWidth: Math.max(1, Math.round(probe.width * scale)),
        resizeHeight: Math.max(1, Math.round(probe.height * scale)),
        resizeQuality: 'high',
      });
    }
  }
  try {
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('no 2d context');
    ctx.drawImage(bitmap, 0, 0);
    return ctx.getImageData(0, 0, bitmap.width, bitmap.height);
  } finally {
    bitmap.close();
  }
}

addEventListener('message', async (ev: MessageEvent<QrRequest>) => {
  const { id } = ev.data;
  let reply: QrResponse;
  let image: ImageData;
  try {
    image = await pixels(ev.data);
  } catch {
    postMessage({ id, ok: false, reason: 'load' } satisfies QrResponse);
    return;
  }
  try {
    const found = await readBarcodes(image, { formats: ['QRCode'], tryHarder: true, maxNumberOfSymbols: 1 });
    const hit = found.find((r) => r.isValid && r.text);
    reply = { id, ok: true, text: hit ? hit.text : null };
  } catch {
    reply = { id, ok: false, reason: 'decode' };
  }
  image.data.fill(0);
  postMessage(reply);
});
