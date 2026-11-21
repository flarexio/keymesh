import { QR_MAX_BYTES, checkImage, decodeSize, readImageHeader } from './image-header';

const bytes = (...parts: (number[] | string)[]) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === 'string' ? [...p].map((c) => c.charCodeAt(0)) : p)));
const be32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const le16 = (n: number) => [n & 255, (n >>> 8) & 255];
const le32 = (n: number) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];

const png = (w: number, h: number) => bytes('\x89PNG\r\n\x1a\n', be32(13), 'IHDR', be32(w), be32(h), [8, 6, 0, 0, 0]);
const gif = (w: number, h: number) => bytes('GIF89a', le16(w), le16(h), [0, 0, 0]);
const bmp = (w: number, h: number) => bytes('BM', new Array(16).fill(0), le32(w), le32(h), [1, 0]);
// SOI, APP0 (len 16), SOF0 (len 17, precision 8, height, width).
const jpeg = (w: number, h: number) =>
  bytes([0xff, 0xd8, 0xff, 0xe0, 0, 16], new Array(14).fill(0), [0xff, 0xc0, 0, 17, 8], [h >> 8, h & 255, w >> 8, w & 255], [3]);
const webpX = (w: number, h: number) =>
  bytes('RIFF', le32(30), 'WEBP', 'VP8X', le32(10), [0, 0, 0, 0], [(w - 1) & 255, ((w - 1) >> 8) & 255, (w - 1) >> 16, (h - 1) & 255, ((h - 1) >> 8) & 255, (h - 1) >> 16]);

describe('QR image header bounds', () => {
  it('reads the canvas size of every accepted format without decoding', () => {
    expect(readImageHeader(png(640, 480))).toEqual({ type: 'png', width: 640, height: 480 });
    expect(readImageHeader(gif(300, 200))).toEqual({ type: 'gif', width: 300, height: 200 });
    expect(readImageHeader(bmp(64, 32))).toEqual({ type: 'bmp', width: 64, height: 32 });
    expect(readImageHeader(jpeg(1024, 768))).toEqual({ type: 'jpeg', width: 1024, height: 768 });
    expect(readImageHeader(webpX(5000, 10))).toEqual({ type: 'webp', width: 5000, height: 10 });
  });

  it('accepts a normal screenshot', () => {
    expect(checkImage(png(1170, 2532))).toMatchObject({ ok: true });
  });

  it('refuses decompression bombs by declared size, before any decode', () => {
    expect(checkImage(png(30000, 30000))).toEqual({ ok: false, reason: 'tooManyPixels' });
    expect(checkImage(jpeg(9000, 10))).toEqual({ ok: false, reason: 'tooManyPixels' });
    expect(checkImage(png(6000, 6000))).toEqual({ ok: false, reason: 'tooManyPixels' }); // 36 MP
    expect(checkImage(png(0, 10))).toEqual({ ok: false, reason: 'unsupported' });
  });

  it('refuses oversized files, unknown formats and truncated headers', () => {
    expect(checkImage(png(10, 10), QR_MAX_BYTES + 1)).toEqual({ ok: false, reason: 'tooLarge' });
    expect(checkImage(bytes('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toEqual({ ok: false, reason: 'unsupported' });
    expect(checkImage(bytes('<!doctype html><title>x</title>'))).toEqual({ ok: false, reason: 'unsupported' });
    expect(checkImage(png(10, 10).slice(0, 20))).toEqual({ ok: false, reason: 'unsupported' });
    expect(checkImage(bytes([0xff, 0xd8, 0xff, 0xe0, 0, 1]))).toEqual({ ok: false, reason: 'unsupported' });
    expect(checkImage(new Uint8Array())).toEqual({ ok: false, reason: 'unsupported' });
  });
});

describe('QR decode size', () => {
  it('scales large images down to the decode side, keeping the aspect ratio', () => {
    expect(decodeSize(1740, 1740, 1600)).toEqual({ width: 1600, height: 1600 });
    expect(decodeSize(4032, 3024, 1600)).toEqual({ width: 1600, height: 1200 });
    expect(decodeSize(3024, 4032, 1600)).toEqual({ width: 1200, height: 1600 });
    expect(decodeSize(800, 600, 1600)).toEqual({ width: 800, height: 600 });
    expect(decodeSize(16000, 2, 1600)).toBeNull(); // over the side bound
  });

  it('refuses decoded sizes the header check would refuse (closed bitmaps report 0x0)', () => {
    expect(decodeSize(0, 0, 1600)).toBeNull();
    expect(decodeSize(9000, 100, 1600)).toBeNull();
    expect(decodeSize(6000, 6000, 1600)).toBeNull();
    expect(decodeSize(Number.NaN, 10, 1600)).toBeNull();
  });
});
