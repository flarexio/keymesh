/**
 * Synthetic QR fixtures generated at test time, offline: zxing-wasm's writer
 * with its bundled binary (never the CDN default). Nothing is committed.
 */
import { writeFileSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { prepareZXingModule, writeBarcode } from 'zxing-wasm/writer';

const require = createRequire(__filename);
let prepared = false;
function prepare(): void {
  if (prepared) return;
  const wasm = readFileSync(require.resolve('zxing-wasm/writer/zxing_writer.wasm'));
  prepareZXingModule({ overrides: { wasmBinary: wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength) } });
  prepared = true;
}

/** PNG bytes of a QR code for `text`. */
export async function qrPng(text: string, scale = 6): Promise<Buffer> {
  prepare();
  const r = await writeBarcode(text, { format: 'QRCode', scale });
  if (r.error || !r.image) throw new Error('QR fixture: ' + r.error);
  return Buffer.from(await r.image.arrayBuffer());
}

/**
 * A short Y4M clip (Chromium's fake camera input) showing the QR code on a
 * white 640×480 frame: the only way to exercise a real camera stream in CI.
 */
export async function qrY4m(text: string, path: string): Promise<void> {
  prepare();
  const r = await writeBarcode(text, { format: 'QRCode', scale: 1 });
  if (r.error) throw new Error('QR fixture: ' + r.error);
  const { data, width, height } = r.symbol;
  const W = 640;
  const H = 480;
  const cell = Math.floor(Math.min(W, H) * 0.8 / Math.max(width, height));
  const ox = Math.floor((W - width * cell) / 2);
  const oy = Math.floor((H - height * cell) / 2);
  const y = Buffer.alloc(W * H, 235);
  for (let r0 = 0; r0 < height; r0++) {
    for (let c = 0; c < width; c++) {
      if (data[r0 * width + c] >= 128) continue; // white module
      for (let dy = 0; dy < cell; dy++) y.fill(16, (oy + r0 * cell + dy) * W + ox + c * cell, (oy + r0 * cell + dy) * W + ox + (c + 1) * cell);
    }
  }
  const chroma = Buffer.alloc((W / 2) * (H / 2), 128);
  const frame = Buffer.concat([Buffer.from('FRAME\n'), y, chroma, chroma]);
  const frames = Array.from({ length: 10 }, () => frame);
  writeFileSync(path, Buffer.concat([Buffer.from(`YUV4MPEG2 W${W} H${H} F10:1 Ip A1:1 C420jpeg\n`), ...frames]));
}
