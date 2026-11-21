import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { SwUpdate, VersionEvent, UnrecoverableStateEvent } from '@angular/service-worker';
import { Subject } from 'rxjs';
import { ConfirmService } from '../shared/feedback';
import { AppUpdate, MAX_UPDATE_RETRIES } from './app-update';
import { VaultService } from './vault.service';

function setup(opts: { enabled?: boolean; status?: string; confirming?: boolean; answer?: boolean; keyMode?: string | null } = {}) {
  const versionUpdates = new Subject<VersionEvent>();
  const unrecoverable = new Subject<UnrecoverableStateEvent>();
  const sw = {
    isEnabled: opts.enabled ?? true,
    versionUpdates,
    unrecoverable,
    activateUpdate: vi.fn(),
    checkForUpdate: vi.fn(async () => true),
  };
  const vault = {
    status: signal(opts.status ?? 'empty'),
    confirmingNewVault: signal(opts.confirming ?? false),
    keyMode: signal(opts.keyMode ?? null),
    lock: vi.fn(),
  };
  const confirm = { ask: vi.fn(async () => opts.answer ?? true) };
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      { provide: SwUpdate, useValue: sw },
      { provide: VaultService, useValue: vault },
      { provide: ConfirmService, useValue: confirm },
    ],
  });
  const update = TestBed.inject(AppUpdate);
  const reload = vi.fn();
  update.reload = reload;
  return { update, sw, vault, confirm, reload, versionUpdates, unrecoverable };
}

const ready = { type: 'VERSION_READY', currentVersion: { hash: 'a' }, latestVersion: { hash: 'b' } } as VersionEvent;

describe('installed-app updates', () => {
  it('offers a reload when a new version is ready; never activates or reloads by itself', () => {
    const t = setup();
    expect(t.update.ready()).toBe(false);
    t.versionUpdates.next({ type: 'VERSION_DETECTED', version: { hash: 'b' } } as VersionEvent);
    expect(t.update.ready()).toBe(false);
    t.versionUpdates.next(ready);
    expect(t.update.ready()).toBe(true);
    expect(t.sw.activateUpdate).not.toHaveBeenCalled();
    expect(t.reload).not.toHaveBeenCalled();
  });

  it('records failed downloads and unrecoverable states', () => {
    const t = setup();
    t.versionUpdates.next({ type: 'VERSION_INSTALLATION_FAILED', version: { hash: 'b' }, error: 'x' } as VersionEvent);
    expect(t.update.failed()).toBe(true);
    expect(t.update.ready()).toBe(false);
    t.unrecoverable.next({ type: 'UNRECOVERABLE_STATE', reason: 'missing chunk' });
    expect(t.update.broken()).toBe(true);
  });

  it('nothing to lose: reloads directly', async () => {
    const t = setup({ status: 'locked' });
    expect(await t.update.apply()).toBe(true);
    expect(t.confirm.ask).not.toHaveBeenCalled();
    expect(t.vault.lock).not.toHaveBeenCalled();
    expect(t.reload).toHaveBeenCalledTimes(1);
  });

  it('open vault: asks, then locks BEFORE reloading', async () => {
    const t = setup({ status: 'unlocked' });
    const order: string[] = [];
    t.vault.lock.mockImplementation(() => order.push('lock'));
    t.reload.mockImplementation(() => order.push('reload'));
    expect(await t.update.apply()).toBe(true);
    expect(t.confirm.ask).toHaveBeenCalledTimes(1);
    expect(order).toEqual(['lock', 'reload']);
  });

  it('declining keeps everything as it is', async () => {
    for (const s of [{ status: 'unlocked' }, { status: 'stale' }, { status: 'empty', confirming: true }]) {
      const t = setup({ ...s, answer: false });
      expect(await t.update.apply()).toBe(false);
      expect(t.vault.lock).not.toHaveBeenCalled();
      expect(t.reload).not.toHaveBeenCalled();
    }
  });

  it('ephemeral demo vault: always asks (even locked) and says the vault becomes unreadable', async () => {
    for (const status of ['unlocked', 'locked']) {
      const t = setup({ status, keyMode: 'ephemeral' });
      expect(await t.update.apply()).toBe(true);
      expect(t.confirm.ask).toHaveBeenCalledWith(
        expect.objectContaining({ body: 'update.confirmBodyEphemeral', danger: true }),
      );
    }
    // Password or fixture vaults keep the normal wording.
    const p = setup({ status: 'unlocked', keyMode: 'protected' });
    await p.update.apply();
    expect(p.confirm.ask).toHaveBeenCalledWith(expect.objectContaining({ body: 'update.confirmBody', danger: false }));
  });

  it('failed install: retries are bounded; success clears the failure', async () => {
    const t = setup();
    const failed = { type: 'VERSION_INSTALLATION_FAILED', version: { hash: 'b' }, error: 'hash mismatch' } as VersionEvent;
    t.versionUpdates.next(failed);
    expect(t.update.failed()).toBe(true);
    for (let i = 0; i < MAX_UPDATE_RETRIES + 2; i++) await t.update.retry();
    expect(t.sw.checkForUpdate).toHaveBeenCalledTimes(MAX_UPDATE_RETRIES);
    expect(t.update.canRetry).toBe(false);
    t.versionUpdates.next(ready);
    expect(t.update.failed()).toBe(false);
    expect(t.update.ready()).toBe(true);
    expect(t.reload).not.toHaveBeenCalled(); // never forced
  });

  it('failed install: coming back online retries once per event, within the bound', async () => {
    const t = setup();
    t.versionUpdates.next({ type: 'VERSION_INSTALLATION_FAILED', version: { hash: 'b' }, error: 'x' } as VersionEvent);
    dispatchEvent(new Event('online'));
    await Promise.resolve();
    expect(t.sw.checkForUpdate).toHaveBeenCalledTimes(1);
    // Not degraded: online events do nothing.
    const healthy = setup();
    dispatchEvent(new Event('online'));
    await Promise.resolve();
    expect(healthy.sw.checkForUpdate).not.toHaveBeenCalled();
  });

  it('degraded and offline: unloading asks first; online or healthy it does not', () => {
    const t = setup();
    const unload = () => {
      const e = new Event('beforeunload', { cancelable: true });
      dispatchEvent(e);
      return e.defaultPrevented;
    };
    t.update.isOnline = () => false;
    expect(unload()).toBe(false); // healthy
    t.versionUpdates.next({ type: 'VERSION_INSTALLATION_FAILED', version: { hash: 'b' }, error: 'x' } as VersionEvent);
    expect(unload()).toBe(true);
    t.update.isOnline = () => true;
    expect(unload()).toBe(false);
    TestBed.resetTestingModule(); // listeners removed with the injector
  });

  it('without a service worker (dev, unsupported) it stays inert', () => {
    const t = setup({ enabled: false });
    t.versionUpdates.next(ready);
    expect(t.update.ready()).toBe(false);
    expect(t.update.enabled).toBe(false);
  });
});
