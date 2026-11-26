/**
 * Secret clipboard (review M-2). Copied secrets (revealed fields, generated
 * passwords, the recovery code) are cleared after CLIPBOARD_CLEAR_SECONDS and
 * when the vault locks, but only if the clipboard still holds what Keymesh
 * copied:
 * * Where the browser lets the page read the clipboard WITHOUT a prompt
 *   (`clipboard-read` already granted), the current text is compared by
 *   SHA-256 with what was copied; anything else (the user copied something
 *   since) is left alone.
 * * Otherwise nothing is read (no permission prompt 30 s later) and the
 *   clipboard is overwritten with an empty string, best effort.
 * * Browsers refuse clipboard writes while the page is not focused; a failed
 *   overwrite is retried on the next focus or return to the page.
 * Only the SHA-256 of the copied value is kept here, never the value. What
 * other apps, clipboard history or sync did with it meanwhile is outside the
 * browser's reach (stated in the copy warning).
 */
import { DestroyRef, Injectable, InjectionToken, effect, inject, signal } from '@angular/core';
import { VaultService } from './vault.service';

export const CLIPBOARD_CLEAR_SECONDS = 30;

export interface ClipboardPort {
  available(): boolean;
  writeText(text: string): Promise<void>;
  readText(): Promise<string>;
  /** `clipboard-read` permission state, or undefined when the browser can't say. */
  readPermission(): Promise<PermissionState | undefined>;
}

export const CLIPBOARD = new InjectionToken<ClipboardPort>('keymesh.clipboard', {
  providedIn: 'root',
  factory: () => ({
    available: () => typeof navigator !== 'undefined' && !!navigator.clipboard,
    writeText: (t) => navigator.clipboard.writeText(t),
    readText: () => navigator.clipboard.readText(),
    async readPermission() {
      try {
        return (await navigator.permissions.query({ name: 'clipboard-read' as PermissionName })).state;
      } catch {
        return undefined;
      }
    },
  }),
});

export type ClearOutcome = 'cleared' | 'changed' | 'pending';

async function sha256(text: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('');
}

const OPEN = new Set(['unlocked', 'stale']);

@Injectable({ providedIn: 'root' })
export class SecretClipboard {
  private readonly port = inject(CLIPBOARD);
  private readonly vault = inject(VaultService);
  /** Seconds until the clipboard is cleared, or null when nothing is pending. */
  readonly countdown = signal<number | null>(null);
  /** Result of the last clear attempt (for the status line and tests). */
  readonly lastOutcome = signal<ClearOutcome | null>(null);

  /** SHA-256 (hex) of what Keymesh last copied and has not cleared yet. */
  private digest: string | null = null;
  /** The copy was made while the vault was open: a lock clears it too. */
  private copiedWhileOpen = false;
  private timer: ReturnType<typeof setInterval> | null = null;
  private retry = false;

  constructor() {
    let wasOpen = OPEN.has(this.vault.status());
    effect(() => {
      const open = OPEN.has(this.vault.status());
      if (wasOpen && !open && this.digest && this.copiedWhileOpen) void this.clear();
      wasOpen = open;
    });
    const onReturn = () => {
      if (this.retry) void this.clear();
    };
    const onVisible = () => {
      if (document.visibilityState === 'visible') onReturn();
    };
    window.addEventListener('focus', onReturn);
    document.addEventListener('visibilitychange', onVisible);
    inject(DestroyRef).onDestroy(() => {
      window.removeEventListener('focus', onReturn);
      document.removeEventListener('visibilitychange', onVisible);
      this.stopTimer();
    });
  }

  available(): boolean {
    return this.port.available();
  }

  /** Copy a secret and schedule its removal. Throws if the browser refuses the copy. */
  async copySecret(text: string): Promise<void> {
    await this.port.writeText(text);
    this.digest = await sha256(text);
    this.copiedWhileOpen = OPEN.has(this.vault.status());
    this.retry = false;
    this.lastOutcome.set(null);
    this.stopTimer();
    this.countdown.set(CLIPBOARD_CLEAR_SECONDS);
    this.timer = setInterval(() => {
      const left = (this.countdown() ?? 1) - 1;
      if (left > 0) {
        this.countdown.set(left);
      } else {
        void this.clear();
      }
    }, 1000);
  }

  /** "Clear now" (also used by the timer and on lock). */
  clearNow(): Promise<void> {
    return this.clear();
  }

  private async clear(): Promise<void> {
    this.stopTimer();
    this.countdown.set(null);
    const digest = this.digest;
    if (!digest) return;
    let outcome: ClearOutcome;
    try {
      if ((await this.port.readPermission()) === 'granted' && (await sha256(await this.port.readText())) !== digest) {
        outcome = 'changed';
      } else {
        await this.port.writeText('');
        outcome = 'cleared';
      }
    } catch {
      // Typically "Document is not focused": try again when the page is back.
      this.retry = true;
      this.lastOutcome.set('pending');
      return;
    }
    if (this.digest === digest) this.digest = null;
    this.retry = false;
    this.lastOutcome.set(outcome);
  }

  private stopTimer(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}
