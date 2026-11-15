/**
 * Image bounds checked from the file header, BEFORE the browser decodes any
 * pixels: a small file can declare a huge canvas (decompression bomb). Only
 * the formats a QR screenshot or photo realistically uses are accepted.
 */
export const QR_MAX_BYTES = 8 * 1024 * 1024;
export const QR_MAX_SIDE = 8192;
export const QR_MAX_PIXELS = 24_000_000;

export type ImageType = 'png' | 'jpeg' | 'gif' | 'webp' | 'bmp';

export interface ImageHeader {
  type: ImageType;
  width: number;
  height: number;
}

export type HeaderCheck =
  | { ok: true; header: ImageHeader }
  | { ok: false; reason: 'tooLarge' | 'unsupported' | 'tooManyPixels' };

const u16be = (b: Uint8Array, o: number) => (b[o] << 8) | b[o + 1];
const u16le = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8);
const u24le = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8) | (b[o + 2] << 16);
const u32be = (b: Uint8Array, o: number) => ((b[o] << 24) >>> 0) + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
const i32le = (b: Uint8Array, o: number) => b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
const ascii = (b: Uint8Array, o: number, s: string) => [...s].every((c, i) => b[o + i] === c.charCodeAt(0));

/** Dimensions from the header, or null for anything unrecognised or truncated. */
export function readImageHeader(b: Uint8Array): ImageHeader | null {
  // PNG: signature, then IHDR first.
  if (b.length >= 24 && ascii(b, 0, '\x89PNG\r\n\x1a\n') && ascii(b, 12, 'IHDR')) {
    return { type: 'png', width: u32be(b, 16), height: u32be(b, 20) };
  }
  if (b.length >= 10 && (ascii(b, 0, 'GIF87a') || ascii(b, 0, 'GIF89a'))) {
    return { type: 'gif', width: u16le(b, 6), height: u16le(b, 8) };
  }
  if (b.length >= 26 && ascii(b, 0, 'BM')) {
    return { type: 'bmp', width: Math.abs(i32le(b, 18)), height: Math.abs(i32le(b, 22)) };
  }
  if (b.length >= 30 && ascii(b, 0, 'RIFF') && ascii(b, 8, 'WEBP')) {
    if (ascii(b, 12, 'VP8X')) return { type: 'webp', width: u24le(b, 24) + 1, height: u24le(b, 27) + 1 };
    if (ascii(b, 12, 'VP8L') && b[20] === 0x2f) {
      const bits = b[21] | (b[22] << 8) | (b[23] << 16) | (b[24] << 24);
      return { type: 'webp', width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
    }
    if (ascii(b, 12, 'VP8 ') && b[23] === 0x9d && b[24] === 0x01 && b[25] === 0x2a) {
      return { type: 'webp', width: u16le(b, 26) & 0x3fff, height: u16le(b, 28) & 0x3fff };
    }
    return null;
  }
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) return jpeg(b);
  return null;
}

/** Walk JPEG segments to the first start-of-frame marker. */
function jpeg(b: Uint8Array): ImageHeader | null {
  let o = 2;
  while (o + 9 < b.length) {
    if (b[o] !== 0xff) return null;
    const m = b[o + 1];
    if (m === 0xff) {
      o++; // fill byte
      continue;
    }
    // SOF0..SOF15 except DHT (C4), JPG (C8) and DAC (CC).
    if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) {
      return { type: 'jpeg', height: u16be(b, o + 5), width: u16be(b, o + 7) };
    }
    if (m === 0xd8 || (m >= 0xd0 && m <= 0xd7) || m === 0x01) {
      o += 2; // markers without a length
      continue;
    }
    const len = u16be(b, o + 2);
    if (len < 2) return null;
    o += 2 + len;
  }
  return null;
}

/** Size, type and canvas bounds; never decodes the image. */
export function checkImage(bytes: Uint8Array, byteLength = bytes.length): HeaderCheck {
  if (byteLength > QR_MAX_BYTES) return { ok: false, reason: 'tooLarge' };
  const header = readImageHeader(bytes);
  if (!header || header.width < 1 || header.height < 1) return { ok: false, reason: 'unsupported' };
  if (header.width > QR_MAX_SIDE || header.height > QR_MAX_SIDE || header.width * header.height > QR_MAX_PIXELS) {
    return { ok: false, reason: 'tooManyPixels' };
  }
  return { ok: true, header };
}

/**
 * Canvas size for decoding an image of `width`×`height` (already decoded by
 * the browser): scaled so the longest side is at most `maxSide`, or null if
 * the decoded size breaks the same bounds as the header check (a header can
 * lie). Width and height must be read before the bitmap is closed: a closed
 * ImageBitmap reports 0×0.
 */
export function decodeSize(width: number, height: number, maxSide: number): { width: number; height: number } | null {
  if (!(width >= 1 && height >= 1) || width > QR_MAX_SIDE || height > QR_MAX_SIDE || width * height > QR_MAX_PIXELS) {
    return null;
  }
  const scale = Math.min(1, maxSide / Math.max(width, height));
  return { width: Math.max(1, Math.round(width * scale)), height: Math.max(1, Math.round(height * scale)) };
}
