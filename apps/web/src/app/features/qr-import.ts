import {
  Component,
  ElementRef,
  OnDestroy,
  effect,
  inject,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { QrDecoder, QrFailure, QrOutcome, QrSession, outcomeOf } from '../core/qr/qr-decoder';
import { VaultService } from '../core/vault.service';
import { Icon } from '../shared/icon';

export interface TotpFromQr {
  uri: string;
  issuer: string | null;
  account: string | null;
}

const FAILURES: Record<QrFailure, MessageKey> = {
  tooLarge: 'qr.err.tooLarge',
  unsupported: 'qr.err.unsupported',
  tooManyPixels: 'qr.err.tooManyPixels',
  notFound: 'qr.err.notFound',
  load: 'qr.err.load',
  timeout: 'qr.err.timeout',
  cancelled: 'qr.err.cancelled',
  hotp: 'qr.err.hotp',
  migration: 'qr.err.migration',
  other: 'qr.err.other',
  tooLong: 'qr.err.other',
};

/** Image formats the header check accepts (no SVG: it is a document, not pixels). */
const ACCEPT = 'image/png,image/jpeg,image/gif,image/webp,image/bmp';
/** Camera frames are scaled to at most this side before decoding. */
const FRAME_SIDE = 1280;
const FRAME_INTERVAL_MS = 250;

interface CameraRun {
  /** Operation token this run belongs to. */
  readonly op: number;
  stream: MediaStream | null;
  session: QrSession | null;
  loop: ReturnType<typeof setTimeout> | null;
}

/**
 * Add a TOTP from a QR code: image upload, image paste, or live camera.
 * Everything is decoded locally (core/qr). Only a TOTP otpauth URI is passed
 * on (to the form, which the Rust core validates on save); other QR contents
 * are refused without being shown. The camera is stopped on close, cancel,
 * Escape, lock, when the page is hidden, and on destroy.
 */
@Component({
  selector: 'km-qr-import',
  imports: [Icon],
  host: {
    '(document:paste)': 'onPaste($event)',
    '(document:visibilitychange)': 'onHidden()',
    '(window:pagehide)': 'stopCamera()',
  },
  template: `
    <div class="qr-import" data-testid="qr-import">
      <div class="qr-actions">
        <label class="btn btn-sm qr-upload">
          <km-icon name="upload" /><span>{{ i18n.t('qr.upload') }}</span>
          <input type="file" [accept]="accept" data-testid="qr-file" (change)="onFile($event)" />
        </label>
        @if (cameraSupported) {
          <button type="button" class="btn btn-sm" data-testid="qr-camera" (click)="startCamera()">
            <km-icon name="camera" /><span>{{ i18n.t('qr.camera') }}</span>
          </button>
        }
      </div>
      <p class="field-hint">{{ i18n.t(cameraSupported ? 'qr.hint' : 'qr.hintNoCamera') }}</p>
      @if (status(); as s) {
        <p class="qr-status" [class.error]="s.error" role="status" data-testid="qr-status" [attr.data-state]="s.state">
          <km-icon [name]="s.error ? 'alert' : s.state === 'found' ? 'check' : 'info'" />{{ i18n.t(s.key) }}
        </p>
      }
    </div>
    <dialog #cam class="dialog qr-dialog" aria-labelledby="qr-cam-title" data-testid="qr-dialog"
      (cancel)="$event.preventDefault(); stopCamera()">
      @if (cameraOpen()) {
        <div class="dialog-body qr-dialog-body">
          <h2 id="qr-cam-title">{{ i18n.t('qr.cameraTitle') }}</h2>
          <div class="qr-video">
            <video #video playsinline muted aria-hidden="true"></video>
            <span class="qr-frame" data-testid="qr-frame" aria-hidden="true"></span>
          </div>
          <p class="qr-status" [class.error]="!!cameraMsg()" role="status" data-testid="qr-camera-status">
            {{ i18n.t(cameraMsg() ?? 'qr.cameraHelp') }}
          </p>
          <div class="dialog-actions">
            <button type="button" class="btn" data-testid="qr-camera-cancel" (click)="stopCamera()">
              {{ i18n.t('common.cancel') }}
            </button>
          </div>
        </div>
      }
    </dialog>
  `,
})
export class QrImport implements OnDestroy {
  protected readonly i18n = inject(I18n);
  private readonly decoder = inject(QrDecoder);
  private readonly vault = inject(VaultService);
  readonly found = output<TotpFromQr>();

  protected readonly accept = ACCEPT;
  protected readonly cameraSupported =
    typeof isSecureContext === 'boolean' && isSecureContext && !!navigator.mediaDevices?.getUserMedia;
  protected readonly status = signal<{ key: MessageKey; error: boolean; state: string } | null>(null);
  protected readonly cameraOpen = signal(false);
  protected readonly cameraMsg = signal<MessageKey | null>(null);
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('cam');
  private readonly video = viewChild<ElementRef<HTMLVideoElement>>('video');

  /**
   * One QR operation at a time. Upload, paste and camera share this token:
   * starting any of them, cancelling, locking, hiding the page or destroying
   * the form bumps it and releases whatever the previous operation owned.
   * Every continuation re-checks it after each await, so a late file result,
   * permission grant, play() or frame can never write to the form or install
   * a worker or timer.
   */
  private op = 0;
  private fileAbort: AbortController | null = null;
  /** Resources of the camera run that owns them; released as one unit. */
  private cam: CameraRun | null = null;

  constructor() {
    // Locking the vault cancels everything in progress here.
    effect(() => {
      if (this.vault.status() !== 'unlocked') this.cancelAll();
    });
  }

  protected onFile(ev: Event): void {
    const input = ev.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = ''; // drop the browser's reference; the same file can be chosen again
    if (file) void this.decodeImage(file);
  }

  /** Image paste anywhere while this form is open; text pastes are untouched. */
  protected onPaste(ev: ClipboardEvent): void {
    const file = [...(ev.clipboardData?.files ?? [])].find((f) => f.type.startsWith('image/'));
    if (!file) return;
    ev.preventDefault();
    void this.decodeImage(file);
  }

  /** Cancel what is running and claim the next operation token. */
  private begin(): number {
    this.release();
    return ++this.op;
  }

  private async decodeImage(file: Blob): Promise<void> {
    const op = this.begin();
    const ac = (this.fileAbort = new AbortController());
    this.status.set({ key: 'qr.reading', error: false, state: 'reading' });
    const r = await this.decoder.decodeFile(file, ac.signal);
    if (op !== this.op) return; // superseded, cancelled, locked, hidden or destroyed
    this.fileAbort = null;
    this.report(r);
  }

  private report(r: QrOutcome): void {
    if (r.ok) {
      this.status.set({ key: 'qr.found', error: false, state: 'found' });
      this.found.emit({ uri: r.uri, issuer: r.issuer, account: r.account });
    } else if (r.reason !== 'cancelled') {
      this.status.set({ key: FAILURES[r.reason], error: true, state: r.reason });
    } else {
      this.status.set(null);
    }
  }

  protected async startCamera(): Promise<void> {
    if (!this.cameraSupported || this.cameraOpen()) return;
    const op = this.begin();
    const cam: CameraRun = { op, stream: null, session: null, loop: null };
    this.cam = cam;
    this.status.set(null);
    this.cameraMsg.set(null);
    this.cameraOpen.set(true);
    this.dialog().nativeElement.showModal();
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      if (op !== this.op) {
        stream.getTracks().forEach((t) => t.stop()); // closed while the permission prompt was up
        return;
      }
      cam.stream = stream;
      const video = this.video()?.nativeElement;
      if (!video) return this.cancelAll();
      video.srcObject = stream;
      await video.play();
      // Cancelled while play() was pending: release() already stopped the
      // stream; nothing else may be created for this run.
      if (op !== this.op) return;
      cam.session = this.decoder.session();
      this.schedule(cam);
    } catch (e) {
      if (op !== this.op) return;
      const name = e instanceof DOMException ? e.name : '';
      this.releaseCamera(cam);
      this.cameraMsg.set(name === 'NotAllowedError' || name === 'SecurityError' ? 'qr.cameraDenied' : 'qr.cameraUnavailable');
    }
  }

  private schedule(cam: CameraRun): void {
    if (cam.op !== this.op || this.cam !== cam) return;
    cam.loop = setTimeout(() => void this.scanFrame(cam), FRAME_INTERVAL_MS);
  }

  private async scanFrame(cam: CameraRun): Promise<void> {
    cam.loop = null;
    const video = this.video()?.nativeElement;
    const session = cam.session;
    if (cam.op !== this.op || !video || !session || session.closed) return;
    if (video.readyState < 2 || !video.videoWidth) return this.schedule(cam);
    const scale = Math.min(1, FRAME_SIDE / Math.max(video.videoWidth, video.videoHeight));
    let bitmap: ImageBitmap;
    try {
      bitmap = await createImageBitmap(video, {
        resizeWidth: Math.round(video.videoWidth * scale),
        resizeHeight: Math.round(video.videoHeight * scale),
      });
    } catch {
      return this.schedule(cam); // re-checks ownership itself
    }
    if (cam.op !== this.op) return bitmap.close();
    const r = await session.decode(bitmap, 3000);
    if (cam.op !== this.op) return;
    if (r === 'timeout' || r === 'cancelled') {
      cam.session = this.decoder.session(); // replace a stuck or crashed worker
      return this.schedule(cam);
    }
    const outcome = r.ok ? outcomeOf(r.text) : null;
    if (outcome?.ok) {
      this.stopCamera();
      this.report(outcome);
      return;
    }
    // A QR code that is not a TOTP setup: say so, keep scanning.
    if (outcome && outcome.reason !== 'notFound') this.cameraMsg.set(FAILURES[outcome.reason]);
    this.schedule(cam);
  }

  /** Stop the run's tracks, timer and worker, and detach the video. */
  private releaseCamera(cam: CameraRun): void {
    if (cam.loop) clearTimeout(cam.loop);
    cam.loop = null;
    cam.stream?.getTracks().forEach((t) => t.stop());
    cam.stream = null;
    cam.session?.close();
    cam.session = null;
    const video = this.video()?.nativeElement;
    if (video) {
      video.pause();
      video.srcObject = null;
    }
  }

  /** Release whatever the current operation owns (file decode or camera). */
  private release(): void {
    this.fileAbort?.abort();
    this.fileAbort = null;
    if (this.cam) {
      this.releaseCamera(this.cam);
      this.cam = null;
    }
    this.cameraMsg.set(null);
    if (this.cameraOpen()) {
      this.cameraOpen.set(false);
      const d = this.dialog().nativeElement;
      if (d.open) d.close();
    }
  }

  /** Cancel / Escape / pagehide / a successful scan: end the camera run. */
  stopCamera(): void {
    this.op++;
    this.release();
  }

  protected onHidden(): void {
    if (document.visibilityState === 'hidden') this.cancelAll();
  }

  /**
   * Cancel everything (lock, hide, destroy, or the user typing a setup by
   * hand): no pending result may reach the form afterwards.
   */
  cancelAll(): void {
    this.op++;
    this.release();
    this.status.set(null);
  }

  ngOnDestroy(): void {
    this.cancelAll();
  }
}
