import { TestBed } from '@angular/core/testing';
import { QR_MAX_BYTES } from './image-header';
import { QR_WORKER, QrDecoder, outcomeOf } from './qr-decoder';
import type { QrRequest, QrResponse } from './qr-messages';

const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // RFC 6238 test vector
const be32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const pngHeader = (w: number, h: number) =>
  new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, ...be32(13), 0x49, 0x48, 0x44, 0x52, ...be32(w), ...be32(h), 8, 6, 0, 0, 0]);

/** Scripted stand-in for the decoder worker. */
class FakeWorker {
  static all: FakeWorker[] = [];
  onmessage: ((ev: MessageEvent<QrResponse>) => void) | null = null;
  onerror: ((ev: ErrorEvent) => void) | null = null;
  terminated = false;
  received: QrRequest[] = [];
  constructor(private readonly reply: (req: QrRequest) => QrResponse | 'hang' | 'crash') {
    FakeWorker.all.push(this);
  }
  postMessage(req: QrRequest): void {
    this.received.push(req);
    const r = this.reply(req);
    if (r === 'hang') return;
    queueMicrotask(() => {
      if (this.terminated) return;
      if (r === 'crash') this.onerror?.(new ErrorEvent('error'));
      else this.onmessage?.(new MessageEvent('message', { data: r }));
    });
  }
  terminate(): void {
    this.terminated = true;
  }
}

function decoder(reply: (req: QrRequest) => QrResponse | 'hang' | 'crash'): QrDecoder {
  FakeWorker.all = [];
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [{ provide: QR_WORKER, useValue: () => new FakeWorker(reply) as unknown as Worker }],
  });
  return TestBed.inject(QrDecoder);
}

const image = (w = 400, h = 400) => new Blob([pngHeader(w, h), new Uint8Array(64)], { type: 'image/png' });

describe('QR decoder (page side)', () => {
  it('returns a TOTP setup and terminates the worker', async () => {
    const uri = `otpauth://totp/Acme:bob?secret=${SECRET}&issuer=Acme`;
    const d = decoder((req) => ({ id: req.id, ok: true, text: uri }));
    expect(await d.decodeFile(image())).toEqual({ ok: true, uri, issuer: 'Acme', account: 'bob' });
    expect(FakeWorker.all).toHaveLength(1);
    expect(FakeWorker.all[0].terminated).toBe(true);
  });

  it('rejects oversized, unsupported and bomb images without starting a worker', async () => {
    const d = decoder(() => 'hang');
    const big = { size: QR_MAX_BYTES + 1, slice: () => image() } as unknown as Blob;
    expect(await d.decodeFile(big)).toEqual({ ok: false, reason: 'tooLarge' });
    expect(await d.decodeFile(new Blob(['<svg/>'], { type: 'image/svg+xml' }))).toEqual({ ok: false, reason: 'unsupported' });
    expect(await d.decodeFile(image(20000, 20000))).toEqual({ ok: false, reason: 'tooManyPixels' });
    expect(FakeWorker.all).toHaveLength(0);
  });

  it('unrelated QR contents are rejected, not imported', async () => {
    for (const [text, reason] of [
      ['https://example.test', 'other'],
      ['otpauth-migration://offline?data=AA', 'migration'],
      [`otpauth://hotp/x?secret=${SECRET}`, 'hotp'],
      [null, 'notFound'],
    ] as const) {
      const d = decoder((req) => ({ id: req.id, ok: true, text }));
      expect(await d.decodeFile(image())).toEqual({ ok: false, reason });
    }
    expect(outcomeOf('')).toEqual({ ok: false, reason: 'notFound' });
  });

  it('a decoder failure or crash is reported, and the worker is gone', async () => {
    let d = decoder((req) => ({ id: req.id, ok: false, reason: 'load' }));
    expect(await d.decodeFile(image())).toEqual({ ok: false, reason: 'load' });
    d = decoder(() => 'crash');
    expect(await d.decodeFile(image())).toEqual({ ok: false, reason: 'cancelled' });
    expect(FakeWorker.all[0].terminated).toBe(true);
  });

  it('a stuck decode times out and the worker is terminated', async () => {
    const d = decoder(() => 'hang');
    const s = d.session();
    expect(await s.decode(image(), 20)).toBe('timeout');
    expect(FakeWorker.all[0].terminated).toBe(true);
    expect(s.closed).toBe(true);
  });

  it('cancelling (close, lock) stops the decode and the worker', async () => {
    const d = decoder(() => 'hang');
    const ac = new AbortController();
    const p = d.decodeFile(image(), ac.signal);
    // Wait until the worker really exists and holds the request (header read done).
    for (let i = 0; i < 100 && !FakeWorker.all[0]?.received.length; i++) await new Promise((r) => setTimeout(r, 0));
    expect(FakeWorker.all).toHaveLength(1);
    expect(FakeWorker.all[0].received).toHaveLength(1);
    expect(FakeWorker.all[0].terminated).toBe(false);
    ac.abort();
    expect(await p).toEqual({ ok: false, reason: 'cancelled' });
    expect(FakeWorker.all[0].terminated).toBe(true);
    // Already aborted: no worker at all.
    expect(await d.decodeFile(image(), AbortSignal.abort())).toEqual({ ok: false, reason: 'cancelled' });
    expect(FakeWorker.all).toHaveLength(1); // still only the first one
  });
});
