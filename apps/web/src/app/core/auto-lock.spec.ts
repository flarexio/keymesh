/**
 * Auto-lock (M5 C2, ADR 0003 §4.2): deadlines checked before access, not
 * timers. An injected clock; lifecycle "events" are the handlers called
 * directly, and no real timer is relied on (the periodic check is never run).
 */
import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { AUTOLOCK_STORAGE, AutoLock, LOCK_CLOCK, AUTOLOCK_KEY, COARSE_POINTER, IDLE_CHOICES, parseAutoLock } from './auto-lock';
import { VaultService } from './vault.service';
import { ToastService } from '../shared/feedback';

function setup(opts: { stored?: string; coarse?: boolean } = {}) {
  let mono = 1000;
  let wall = 1_700_000_000_000;
  const clock = { mono: () => mono, wall: () => wall };
  const status = signal<string>('unlocked');
  let check: (() => boolean) | null = null;
  const vault = {
    status,
    unlocked: () => status() === 'unlocked',
    lock: vi.fn(() => status.set('locked')),
    setFreshnessCheck: (f: () => boolean) => (check = f),
  };
  const store: Record<string, string> = opts.stored ? { [AUTOLOCK_KEY]: opts.stored } : {};
  const storage = {
    getItem: (k: string) => store[k] ?? null,
    setItem: (k: string, v: string) => void (store[k] = v),
  } as unknown as Storage;
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      { provide: VaultService, useValue: vault },
      { provide: LOCK_CLOCK, useValue: clock },
      { provide: AUTOLOCK_STORAGE, useValue: storage },
      { provide: COARSE_POINTER, useValue: opts.coarse ?? false },
    ],
  });
  const a = TestBed.inject(AutoLock);
  a.unlockedNow(); // a session just started
  const advance = (ms: number, wallMs = ms) => {
    mono += ms;
    wall += wallMs;
  };
  return { a, vault, status, advance, store, freshness: () => check!() };
}

describe('auto-lock (deadline based)', () => {
  it('defaults: 5 min idle; 30 s hidden on desktop, immediately on touch devices', () => {
    expect(setup().a.settings()).toEqual({ idleMinutes: 5, hideSeconds: 30 });
    expect(setup({ coarse: true }).a.settings()).toEqual({ idleMinutes: 5, hideSeconds: 0 });
  });

  it('1. elapsed hidden deadline, no timer fired: locked on return, before anything renders', () => {
    const t = setup();
    t.a.onHidden();
    t.advance(31_000);
    t.a.onVisible();
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
    expect(t.a.lastReason()).toBe('hidden');
  });

  it('2. resume and bfcache restore re-run the check (pageshow, resume, focus)', () => {
    for (const ev of ['onPageShow', 'onResume', 'onFocus'] as const) {
      const t = setup();
      t.a.onHidden();
      t.advance(60_000);
      t.a[ev]();
      expect(t.vault.lock, ev).toHaveBeenCalledTimes(1);
    }
  });

  it('3. protected operations after expiry lock and refuse, with no lifecycle event at all', () => {
    const t = setup();
    t.advance(5 * 60_000 + 1);
    expect(t.freshness()).toBe(false);
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
    expect(t.a.lastReason()).toBe('idle');
  });

  it('4. clocks: wall forward → locked; monotonic forward with the wall unchanged → locked; wall backwards → locked', () => {
    let t = setup();
    t.advance(0, 6 * 60_000);
    expect(t.freshness()).toBe(false);
    t = setup();
    t.advance(6 * 60_000, 0);
    expect(t.freshness()).toBe(false);
    t = setup();
    t.advance(1_000, -10_000);
    expect(t.freshness()).toBe(false);
    expect(t.a.lastReason()).toBe('clock');
    // Small jitter backwards is tolerated.
    t = setup();
    t.advance(1_000, -1_000);
    expect(t.freshness()).toBe(true);
  });

  it('6. "immediately" on hide locks synchronously inside the handler', () => {
    const t = setup({ coarse: true });
    t.a.onHidden();
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
  });

  it('pagehide while locked cancels pending work without claiming a lock reason', () => {
    const t = setup();
    t.status.set('locked');
    t.a.onPageHide();
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
    expect(t.a.lastReason()).toBeNull();
  });

  it('7. pagehide always locks; same-document activity does not', () => {
    const t = setup();
    t.advance(1_000);
    t.a.onInput();
    expect(t.vault.lock).not.toHaveBeenCalled();
    t.a.onPageHide();
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
  });

  it('8. early return and re-hide: no lock at the first deadline; a new deadline from the second hide', () => {
    const t = setup();
    t.a.onHidden();
    t.advance(5_000);
    t.a.onVisible(); // back before 30 s
    t.advance(26_000); // past the first hide's 30 s mark, while visible
    t.a.onInput();
    expect(t.vault.lock).not.toHaveBeenCalled();
    t.a.onHidden();
    t.advance(29_000);
    t.a.onVisible();
    expect(t.vault.lock).not.toHaveBeenCalled();
    t.a.onHidden();
    t.advance(31_000);
    t.a.onVisible();
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
  });

  it('9. first input after the idle deadline locks instead of extending the session', () => {
    const t = setup();
    t.advance(5 * 60_000 + 1);
    t.a.onInput();
    expect(t.vault.lock).toHaveBeenCalledTimes(1);
    // Input before the deadline extends it.
    const u = setup();
    u.advance(4 * 60_000);
    u.a.onInput();
    u.advance(4 * 60_000);
    expect(u.freshness()).toBe(true);
  });

  it('nothing to lock: a locked vault is never "locked again"; a new unlock starts fresh deadlines', () => {
    const t = setup();
    t.status.set('locked');
    t.advance(60 * 60_000);
    expect(t.freshness()).toBe(true);
    expect(t.vault.lock).not.toHaveBeenCalled();
    t.status.set('unlocked');
    t.a.unlockedNow();
    expect(t.freshness()).toBe(true);
  });

  it('there is no "never": the choices top out at 1 hour; settings persist under their own key, tolerant parse', () => {
    expect(IDLE_CHOICES).not.toContain(0);
    expect(Math.max(...IDLE_CHOICES)).toBe(60);
    expect(Math.min(...IDLE_CHOICES)).toBeGreaterThan(0);
    const t = setup();
    t.a.update({ idleMinutes: 60, hideSeconds: 60 });
    expect(JSON.parse(t.store[AUTOLOCK_KEY])).toEqual({ idleMinutes: 60, hideSeconds: 60 });
    t.advance(59 * 60_000);
    expect(t.freshness()).toBe(true);
    t.advance(60_001);
    expect(t.freshness()).toBe(false);
    expect(t.a.lastReason()).toBe('idle');
    expect(setup({ stored: '{"idleMinutes":15,"hideSeconds":0}' }).a.settings()).toEqual({ idleMinutes: 15, hideSeconds: 0 });
    // Out-of-range or corrupt values fall back to the defaults, field by field.
    expect(parseAutoLock('{"idleMinutes":999,"hideSeconds":30}', false)).toEqual({ idleMinutes: 5, hideSeconds: 30 });
    expect(parseAutoLock('not json', true)).toEqual({ idleMinutes: 5, hideSeconds: 0 });
    expect(parseAutoLock('{"idleMinutes":"5","hideSeconds":-1}', false)).toEqual({ idleMinutes: 5, hideSeconds: 30 });
  });

  it('a stored "never" (0) becomes 1 hour, is rewritten at once, and is announced once', () => {
    const t = setup({ stored: '{"idleMinutes":0,"hideSeconds":60}' });
    expect(t.a.settings()).toEqual({ idleMinutes: 60, hideSeconds: 60 });
    expect(JSON.parse(t.store[AUTOLOCK_KEY])).toEqual({ idleMinutes: 60, hideSeconds: 60 });
    expect(t.a.neverMigrated()).toBe(true);
    expect(TestBed.inject(ToastService).toasts().map((x) => x.key)).toEqual(['autolock.neverMigrated']);
    // It is enforced: hours without input lock.
    t.advance(60 * 60_000 + 1);
    expect(t.freshness()).toBe(false);
    // The next start reads 60 and says nothing.
    const u = setup({ stored: t.store[AUTOLOCK_KEY] });
    expect(u.a.settings().idleMinutes).toBe(60);
    expect(u.a.neverMigrated()).toBe(false);
    expect(TestBed.inject(ToastService).toasts()).toEqual([]);
    expect(parseAutoLock('{"idleMinutes":0,"hideSeconds":30}', false)).toEqual({ idleMinutes: 60, hideSeconds: 30 });
  });

  it('"never" cannot come back: update() with 0 is stored as 1 hour, and nothing ever writes 0', () => {
    const t = setup();
    t.a.update({ idleMinutes: 0, hideSeconds: 30 });
    expect(t.a.settings().idleMinutes).toBe(60);
    expect(JSON.parse(t.store[AUTOLOCK_KEY]).idleMinutes).toBe(60);
    t.advance(3 * 60 * 60_000);
    expect(t.freshness()).toBe(false);
    for (const v of [0, -1, null, '0', 0.5]) {
      expect(parseAutoLock(JSON.stringify({ idleMinutes: v, hideSeconds: 30 }), false).idleMinutes, String(v)).toBeGreaterThan(0);
    }
  });
});
