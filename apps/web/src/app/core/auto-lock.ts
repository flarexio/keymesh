/**
 * Auto-lock (M5 C2; ADR 0003 §4.2). Deadlines that are CHECKED, not timers:
 * a hidden, frozen or bfcached page may not run timers at all, so every
 * return (visible, resume, pageshow, focus), every input and every protected
 * vault operation first asks `fresh()`, which locks if a deadline passed.
 *
 * * Idle: `lastInput + idle`. Input after the deadline locks; it never
 *   revives the session.
 * * Hidden: `hiddenAt + grace`; "immediately" (0) locks inside the
 *   `visibilitychange` handler itself. A passing check on return clears it.
 * * `pagehide` always locks (back/forward cache).
 * * Clocks: monotonic AND wall clock; either past the limit expires the
 *   session, and a wall clock going backwards by more than 2 s does too.
 *
 * What is honestly promised: when the page comes back after a deadline it is
 * locked before any secret is shown or used. While it was hidden or frozen,
 * decrypted data may still have been in the suspended page's memory.
 * Settings are non-secret and stored under their own key.
 */
import { Injectable, InjectionToken, inject, signal } from '@angular/core';
import { VaultService } from './vault.service';

export const AUTOLOCK_KEY = 'keymesh.autolock.v1';
export const IDLE_CHOICES = [0, 1, 2, 5, 10, 15, 30, 60] as const; // minutes; 0 = never
export const HIDE_CHOICES = [0, 30, 60, 300] as const; // seconds; 0 = immediately
const BACKWARD_TOLERANCE_MS = 2_000;

export interface AutoLockSettings {
  /** Minutes without input; 0 = never. */
  idleMinutes: number;
  /** Seconds hidden; 0 = immediately. */
  hideSeconds: number;
}

export type LockReason = 'idle' | 'hidden' | 'clock' | 'pagehide';

export interface LockClock {
  mono(): number;
  wall(): number;
}

export const LOCK_CLOCK = new InjectionToken<LockClock>('keymesh.lock-clock', {
  providedIn: 'root',
  factory: () => ({ mono: () => performance.now(), wall: () => Date.now() }),
});

export const AUTOLOCK_STORAGE = new InjectionToken<Storage | null>('keymesh.autolock-storage', {
  providedIn: 'root',
  factory: () => {
    try {
      const s = globalThis.localStorage;
      s.getItem(AUTOLOCK_KEY);
      return s;
    } catch {
      return null;
    }
  },
});

/** Touch-first devices default to locking as soon as the page is hidden. */
export const COARSE_POINTER = new InjectionToken<boolean>('keymesh.coarse-pointer', {
  providedIn: 'root',
  factory: () => typeof matchMedia === 'function' && matchMedia('(pointer: coarse)').matches,
});

export function defaultAutoLock(coarse: boolean): AutoLockSettings {
  return { idleMinutes: 5, hideSeconds: coarse ? 0 : 30 };
}

/** Tolerant parse: each field validated alone, defaults otherwise. */
export function parseAutoLock(raw: string | null, coarse: boolean): AutoLockSettings {
  const d = defaultAutoLock(coarse);
  if (!raw) return d;
  let o: Record<string, unknown>;
  try {
    const v = JSON.parse(raw) as unknown;
    if (typeof v !== 'object' || v === null || Array.isArray(v)) return d;
    o = v as Record<string, unknown>;
  } catch {
    return d;
  }
  const idle = (IDLE_CHOICES as readonly number[]).includes(o['idleMinutes'] as number) ? (o['idleMinutes'] as number) : d.idleMinutes;
  const hide = (HIDE_CHOICES as readonly number[]).includes(o['hideSeconds'] as number) ? (o['hideSeconds'] as number) : d.hideSeconds;
  return { idleMinutes: idle, hideSeconds: hide };
}

@Injectable({ providedIn: 'root' })
export class AutoLock {
  private readonly vault = inject(VaultService);
  private readonly clock = inject(LOCK_CLOCK);
  private readonly storage = inject(AUTOLOCK_STORAGE);
  private readonly coarse = inject(COARSE_POINTER);

  readonly settings = signal<AutoLockSettings>(this.read());
  /** Why the vault was last locked by this service (non-secret, for the UI). */
  readonly lastReason = signal<LockReason | null>(null);

  private lastInput = { mono: 0, wall: 0 };
  private hiddenAt: { mono: number; wall: number } | null = null;
  private lastWall = 0;
  private started = false;

  constructor() {
    this.vault.setFreshnessCheck(
      () => this.fresh(),
      () => this.unlockedNow(),
    );
    this.unlockedNow();
  }

  /** Attach the lifecycle listeners (once). The periodic check is best effort. */
  start(win: Window = window, doc: Document = document): void {
    if (this.started) return;
    this.started = true;
    doc.addEventListener('visibilitychange', () => (doc.visibilityState === 'hidden' ? this.onHidden() : this.onVisible()));
    doc.addEventListener('resume', () => this.onResume());
    win.addEventListener('pagehide', () => this.onPageHide());
    win.addEventListener('pageshow', () => this.onPageShow());
    win.addEventListener('focus', () => this.onFocus());
    // Capture phase: the check runs before any handler of the same event.
    for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const) {
      win.addEventListener(ev, () => this.onInput(), { capture: true, passive: true });
    }
    win.setInterval(() => this.fresh(), 5_000);
  }

  update(s: AutoLockSettings): void {
    const next = parseAutoLock(JSON.stringify(s), this.coarse);
    this.settings.set(next);
    try {
      this.storage?.setItem(AUTOLOCK_KEY, JSON.stringify(next));
    } catch {
      // keep it for this page only
    }
  }

  /** A session just opened: deadlines start now. */
  unlockedNow(): void {
    this.lastReason.set(null);
    const now = this.now();
    this.lastInput = now;
    this.hiddenAt = null;
    this.lastWall = now.wall;
  }

  /**
   * The one synchronous check. Returns false (after locking) when a deadline
   * passed. Nothing to protect while locked: always true then.
   */
  fresh(): boolean {
    if (!this.holdsSecrets()) return true;
    const now = this.now();
    const reason = this.expired(now);
    this.lastWall = Math.max(this.lastWall, now.wall);
    if (!reason) return true;
    this.lock(reason);
    return false;
  }

  onInput(): void {
    if (!this.holdsSecrets()) return;
    if (!this.fresh()) return;
    this.lastInput = this.now();
  }

  onHidden(): void {
    if (!this.holdsSecrets()) return;
    if (!this.fresh()) return;
    if (this.settings().hideSeconds === 0) {
      this.lock('hidden');
      return;
    }
    this.hiddenAt = this.now();
  }

  onVisible(): void {
    if (this.fresh()) this.hiddenAt = null;
  }

  onResume(): void {
    this.fresh();
  }

  onPageShow(): void {
    this.fresh();
  }

  onFocus(): void {
    this.fresh();
  }

  onPageHide(): void {
    if (this.holdsSecrets()) this.lock('pagehide');
    // Locked already: still cancel pending credential work (a KDF, a
    // passkey ceremony) so no late result can open the vault.
    else if (this.vault.status() !== 'loading') this.vault.lock();
  }

  /** Unlocked, or a stale tab that still shows decrypted data. */
  private holdsSecrets(): boolean {
    const st = this.vault.status();
    return st === 'unlocked' || st === 'stale';
  }

  private expired(now: { mono: number; wall: number }): LockReason | null {
    if (now.wall < this.lastWall - BACKWARD_TOLERANCE_MS) return 'clock';
    const s = this.settings();
    const past = (since: { mono: number; wall: number }, limitMs: number) =>
      now.mono - since.mono > limitMs || now.wall - since.wall > limitMs;
    if (this.hiddenAt && past(this.hiddenAt, s.hideSeconds * 1000)) return 'hidden';
    if (s.idleMinutes > 0 && past(this.lastInput, s.idleMinutes * 60_000)) return 'idle';
    return null;
  }

  private lock(reason: LockReason): void {
    this.lastReason.set(reason);
    this.hiddenAt = null;
    this.vault.lock();
  }

  private now() {
    return { mono: this.clock.mono(), wall: this.clock.wall() };
  }

  private read(): AutoLockSettings {
    try {
      return parseAutoLock(this.storage?.getItem(AUTOLOCK_KEY) ?? null, this.coarse);
    } catch {
      return defaultAutoLock(this.coarse);
    }
  }
}
