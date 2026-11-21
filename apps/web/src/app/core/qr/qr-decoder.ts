import { Injectable, InjectionToken, inject } from '@angular/core';
import { QR_MAX_BYTES, checkImage } from './image-header';
import { type QrRequest, type QrResponse } from './qr-messages';
import { classifyQrText } from './otpauth-qr';

/** A TOTP setup read from a QR code, or why nothing usable was found. */
export type QrOutcome =
  | { ok: true; uri: string; issuer: string | null; account: string | null }
  | { ok: false; reason: QrFailure };

export type QrFailure =
  | 'tooLarge' // file bytes
  | 'unsupported' // not PNG/JPEG/GIF/WebP/BMP, or unreadable header
  | 'tooManyPixels' // declared canvas too big
  | 'notFound' // no QR code in the image
  | 'load' // the browser could not decode the image
  | 'timeout'
  | 'cancelled'
  | 'hotp'
  | 'migration'
  | 'other' // a QR code, but not a TOTP setup
  | 'tooLong';

/** Bytes read for the header check (JPEG metadata can precede the frame header). */
const HEADER_BYTES = 256 * 1024;
export const QR_DECODE_TIMEOUT_MS = 10_000;

export const QR_WORKER = new InjectionToken<() => Worker>('keymesh.qr-worker', {
  providedIn: 'root',
  factory: () => () => new Worker(new URL('./qr.worker', import.meta.url), { type: 'module' }),
});

export function outcomeOf(text: string | null): QrOutcome {
  if (text === null) return { ok: false, reason: 'notFound' };
  const c = classifyQrText(text);
  if (c.kind === 'totp') return { ok: true, uri: c.uri, issuer: c.issuer, account: c.account };
  return { ok: false, reason: c.kind === 'empty' ? 'notFound' : c.kind };
}

/**
 * One decoder worker. `close()` terminates it, which discards everything it
 * held (image pixels, decoded text). Used for one image, or for a camera
 * session that sends frames until a code is found or the scanner closes.
 */
export class QrSession {
  private worker: Worker | null;
  private seq = 0;
  private pending = new Map<number, (r: QrResponse | null) => void>();

  constructor(factory: () => Worker) {
    this.worker = factory();
    this.worker.onmessage = (ev: MessageEvent<QrResponse>) => {
      const done = this.pending.get(ev.data.id);
      this.pending.delete(ev.data.id);
      done?.(ev.data);
    };
    // A crashed worker (hostile input, OOM) fails every waiting request.
    this.worker.onerror = (e) => {
      e.preventDefault();
      this.close();
    };
  }

  get closed(): boolean {
    return this.worker === null;
  }

  /** Decoded text (null: no QR code), or a failure. Transfers `frame` bitmaps. */
  decode(input: Blob | ImageBitmap, timeoutMs = QR_DECODE_TIMEOUT_MS): Promise<QrResponse | 'timeout' | 'cancelled'> {
    const w = this.worker;
    if (!w) return Promise.resolve('cancelled');
    const id = ++this.seq;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.close(); // a stuck decode cannot be interrupted any other way
        resolve('timeout');
      }, timeoutMs);
      this.pending.set(id, (r) => {
        clearTimeout(timer);
        resolve(r ?? 'cancelled');
      });
      const req: QrRequest =
        input instanceof Blob ? { id, kind: 'blob', blob: input } : { id, kind: 'frame', bitmap: input };
      w.postMessage(req, input instanceof Blob ? [] : [input]);
    });
  }

  close(): void {
    this.worker?.terminate();
    this.worker = null;
    const waiting = [...this.pending.values()];
    this.pending.clear();
    waiting.forEach((done) => done(null));
  }
}

@Injectable({ providedIn: 'root' })
export class QrDecoder {
  private readonly factory = inject(QR_WORKER);

  /** For a camera: one worker for many frames; the caller closes it. */
  session(): QrSession {
    return new QrSession(this.factory);
  }

  /** One image file (upload or paste). The worker is gone when this resolves. */
  async decodeFile(file: Blob, signal?: AbortSignal): Promise<QrOutcome> {
    if (file.size > QR_MAX_BYTES) return { ok: false, reason: 'tooLarge' };
    const head = new Uint8Array(await file.slice(0, HEADER_BYTES).arrayBuffer());
    const check = checkImage(head, file.size);
    if (!check.ok) return { ok: false, reason: check.reason };
    if (signal?.aborted) return { ok: false, reason: 'cancelled' };
    const s = this.session();
    const stop = () => s.close();
    signal?.addEventListener('abort', stop, { once: true });
    try {
      const r = await s.decode(file);
      if (r === 'timeout' || r === 'cancelled') return { ok: false, reason: signal?.aborted ? 'cancelled' : r };
      if (!r.ok) return { ok: false, reason: 'load' };
      return outcomeOf(r.text);
    } finally {
      signal?.removeEventListener('abort', stop);
      s.close();
    }
  }
}
