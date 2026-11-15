/// <reference lib="webworker" />
/**
 * QR decoder worker: zxing-cpp compiled to WebAssembly (zxing-wasm), loaded
 * from this app's own /wasm/ directory, never from a CDN. Runs isolated from
 * the vault: a hostile image can at worst crash this worker, which the page
 * then terminates. Nothing is logged and no network request carries content.
 */
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import { decodeSize } from './image-header';
import { QR_DECODE_SIDE, type QrRequest, type QrResponse } from './qr-messages';

prepareZXingModule({
  overrides: {
    // Self-hosted binary, copied at build time (angular.json assets).
    locateFile: (path: string, prefix: string) =>
      path.endsWith('.wasm') ? new URL('wasm/zxing_reader.wasm', self.location.href).href : prefix + path,
  },
});

/**
 * Pixels for the decoder: the image is decoded ONCE, its size is read before
 * anything is closed, checked against the same bounds as the header check
 * (a header can lie), then drawn scaled so the longest side is at most
 * QR_DECODE_SIDE.
 */
async function pixels(req: QrRequest): Promise<ImageData> {
  const bitmap = req.kind === 'frame' ? req.bitmap : await createImageBitmap(req.blob);
  try {
    const size = decodeSize(bitmap.width, bitmap.height, QR_DECODE_SIDE);
    if (!size) throw new Error('image out of bounds');
    const canvas = new OffscreenCanvas(size.width, size.height);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('no 2d context');
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(bitmap, 0, 0, size.width, size.height);
    return ctx.getImageData(0, 0, size.width, size.height);
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
