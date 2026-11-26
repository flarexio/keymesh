/**
 * Secret clipboard (review M-2): copied secrets are cleared after 30 s, and
 * when the vault locks, but only if the clipboard still holds what Keymesh
 * copied (checked by SHA-256 where the browser lets us read without a
 * prompt); otherwise a best-effort overwrite. A failed overwrite (page not
 * focused) is retried when the page is focused again. Synthetic values only.
 */
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { CLIPBOARD, CLIPBOARD_CLEAR_SECONDS, ClipboardPort, SecretClipboard } from './clipboard';
import { VaultService } from './vault.service';

function setup(opts: { read?: PermissionState | 'unsupported'; writeFails?: boolean } = {}) {
  const board = { text: 'unrelated earlier text' };
  let failWrites = opts.writeFails ?? false;
  const port: ClipboardPort & { writes: string[]; reads: number } = {
    writes: [],
    reads: 0,
    available: () => true,
    async writeText(t: string) {
      if (failWrites) throw new DOMException('Document is not focused.', 'NotAllowedError');
      this.writes.push(t);
      board.text = t;
    },
    async readText() {
      this.reads++;
      return board.text;
    },
    async readPermission() {
      return opts.read === 'unsupported' ? undefined : (opts.read ?? 'prompt');
    },
  };
  const status = signal('unlocked');
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      { provide: CLIPBOARD, useValue: port },
      { provide: VaultService, useValue: { status } },
    ],
  });
  const c = TestBed.inject(SecretClipboard);
  return { c, port, board, status, setWritesFail: (v: boolean) => (failWrites = v) };
}

/** Let promise chains (digest, clipboard calls) settle under fake timers. */
async function settle() {
  for (let i = 0; i < 10; i++) await Promise.resolve();
  await vi.advanceTimersByTimeAsync(0);
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.useRealTimers();
  TestBed.resetTestingModule();
});

describe('SecretClipboard', () => {
  it('copies, counts down from 30 s and clears what it copied (read allowed: compared first)', async () => {
    const { c, port, board } = setup({ read: 'granted' });
    expect(CLIPBOARD_CLEAR_SECONDS).toBe(30);
    await c.copySecret('SYNTH-secret-1');
    expect(board.text).toBe('SYNTH-secret-1');
    expect(c.countdown()).toBe(30);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(c.countdown()).toBe(20);
    await vi.advanceTimersByTimeAsync(20_000);
    await settle();
    expect(port.reads).toBe(1);
    expect(board.text).toBe('');
    expect(c.countdown()).toBeNull();
    expect(c.lastOutcome()).toBe('cleared');
  });

  it('read allowed and the user copied something else meanwhile: left alone', async () => {
    const { c, board } = setup({ read: 'granted' });
    await c.copySecret('SYNTH-secret-2');
    board.text = 'something the user copied later';
    await vi.advanceTimersByTimeAsync(30_000);
    await settle();
    expect(board.text).toBe('something the user copied later');
    expect(c.lastOutcome()).toBe('changed');
  });

  it('read not allowed without a prompt (prompt, denied or unsupported): never reads, overwrites best-effort', async () => {
    for (const read of ['prompt', 'denied', 'unsupported'] as const) {
      const { c, port, board } = setup({ read });
      await c.copySecret('SYNTH-secret-3');
      await vi.advanceTimersByTimeAsync(30_000);
      await settle();
      expect(port.reads, read).toBe(0);
      expect(board.text, read).toBe('');
      expect(c.lastOutcome(), read).toBe('cleared');
    }
  });

  it('a failed overwrite (page not focused) is retried when the page is focused again', async () => {
    const { c, board, setWritesFail } = setup({ read: 'prompt' });
    await c.copySecret('SYNTH-secret-4');
    setWritesFail(true);
    await vi.advanceTimersByTimeAsync(30_000);
    await settle();
    expect(board.text).toBe('SYNTH-secret-4');
    expect(c.lastOutcome()).toBe('pending');
    setWritesFail(false);
    window.dispatchEvent(new Event('focus'));
    await settle();
    expect(board.text).toBe('');
    expect(c.lastOutcome()).toBe('cleared');
  });

  it('locking the vault clears at once', async () => {
    const { c, board, status } = setup({ read: 'prompt' });
    await c.copySecret('SYNTH-secret-5');
    status.set('locked');
    TestBed.tick();
    await settle();
    expect(board.text).toBe('');
    expect(c.countdown()).toBeNull();
  });

  it('a copy made while locked (recovery code during setup) is not cleared by the later unlock', async () => {
    const { c, board, status } = setup({ read: 'prompt' });
    status.set('empty');
    TestBed.tick();
    await c.copySecret('SYNTH-recovery-code');
    status.set('unlocked');
    TestBed.tick();
    await settle();
    expect(board.text).toBe('SYNTH-recovery-code');
    expect(c.countdown()).toBe(30);
  });

  it('a second copy restarts the countdown; "clear now" clears at once', async () => {
    const { c, board } = setup({ read: 'prompt' });
    await c.copySecret('SYNTH-a');
    await vi.advanceTimersByTimeAsync(20_000);
    await c.copySecret('SYNTH-b');
    expect(c.countdown()).toBe(30);
    await vi.advanceTimersByTimeAsync(15_000);
    expect(board.text).toBe('SYNTH-b');
    await c.clearNow();
    await settle();
    expect(board.text).toBe('');
    expect(c.countdown()).toBeNull();
  });

  it('keeps only a digest of the copied value, never the value itself', async () => {
    const { c } = setup({ read: 'granted' });
    await c.copySecret('SYNTH-never-kept-in-the-service');
    // (The fake port records writes; the service's own state is what matters.)
    const own = JSON.stringify(c, (k, v) => (k === 'port' || k === 'vault' || typeof v === 'function' ? undefined : v));
    expect(own).not.toContain('SYNTH-never-kept');
  });
});
