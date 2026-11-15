import { DestroyRef, Injectable, inject, signal } from '@angular/core';
import { SwUpdate } from '@angular/service-worker';
import { ConfirmService } from '../shared/feedback';
import { VaultService } from './vault.service';

/**
 * Installed-app updates (Angular service worker).
 *
 * * A new version is downloaded in the background; `ready` then offers a
 *   reload. Nothing is activated or reloaded automatically: a reload would
 *   lose unsaved edits, generated previews or an unconfirmed recovery code.
 * * We never call `activateUpdate()` without reloading (Angular warns that
 *   lazy chunks of the old and new versions could then be mixed). The reload
 *   itself starts the page on the new version, as a whole.
 * * Before reloading, an open vault (or a new vault awaiting recovery-code
 *   confirmation) asks first, then locks, which cancels queued work through
 *   the vault epoch. Stored ciphertext is never touched.
 * * `broken` = the service worker cannot serve this version consistently
 *   (Angular "unrecoverable state"); only a reload helps. Local data is kept.
 * * `failed` = a new version failed to install (e.g. a broken deployment).
 *   Angular then degrades its worker to "existing clients only": this tab
 *   keeps working, but a NEW load (reload, reopen) is served from the
 *   network, so it fails while offline even though the old files are still
 *   cached. Recovery is a later successful update; we retry it a bounded
 *   number of times (button, or once when the browser comes back online).
 *   While degraded and offline we ask before the page is unloaded. A full
 *   browser restart also restarts the worker. No vault data is affected.
 */
/** Update retries per page: user clicks plus automatic ones on `online`. */
export const MAX_UPDATE_RETRIES = 3;

@Injectable({ providedIn: 'root' })
export class AppUpdate {
  private readonly sw = inject(SwUpdate);
  private readonly vault = inject(VaultService);
  private readonly confirm = inject(ConfirmService);
  /** A newer version is installed and waiting for a reload. */
  readonly ready = signal(false);
  /** The running version can no longer be served consistently. */
  readonly broken = signal(false);
  /** The last update failed to install: this tab works, new loads need the network. */
  readonly failed = signal(false);
  /** A retry is running. */
  readonly retrying = signal(false);
  /** Retries used on this page (bounded by MAX_UPDATE_RETRIES). */
  readonly retries = signal(0);
  /** Seam for tests; production reloads the page. */
  reload: () => void = () => location.reload();
  /** Seam for tests. */
  isOnline: () => boolean = () => navigator.onLine;

  constructor() {
    if (!this.sw.isEnabled) return;
    const subs = [
      this.sw.versionUpdates.subscribe((e) => {
        if (e.type === 'VERSION_READY') {
          this.ready.set(true);
          this.failed.set(false);
        }
        if (e.type === 'VERSION_INSTALLATION_FAILED') this.failed.set(true);
      }),
      this.sw.unrecoverable.subscribe(() => this.broken.set(true)),
    ];
    const onOnline = () => {
      if (this.failed() && !this.ready()) void this.retry();
    };
    // Degraded + offline: a reload or close now could not reopen Keymesh
    // until the network is back. Ask first (the browser shows its own text).
    const onUnload = (e: BeforeUnloadEvent) => {
      if (this.failed() && !this.ready() && !this.isOnline()) e.preventDefault();
    };
    addEventListener('online', onOnline);
    addEventListener('beforeunload', onUnload);
    inject(DestroyRef).onDestroy(() => {
      subs.forEach((s) => s.unsubscribe());
      removeEventListener('online', onOnline);
      removeEventListener('beforeunload', onUnload);
    });
  }

  get canRetry(): boolean {
    return this.retries() < MAX_UPDATE_RETRIES && !this.retrying();
  }

  /**
   * Ask the worker to check for (and install) the newest version again.
   * Success arrives as VERSION_READY (which also ends the degraded state);
   * another failure as VERSION_INSTALLATION_FAILED.
   */
  async retry(): Promise<void> {
    if (!this.canRetry) return;
    this.retries.update((n) => n + 1);
    this.retrying.set(true);
    try {
      await this.sw.checkForUpdate();
    } catch {
      // Reported through the version events; nothing else to do here.
    } finally {
      this.retrying.set(false);
    }
  }

  get enabled(): boolean {
    return this.sw.isEnabled;
  }

  /**
   * An ephemeral demo vault's key exists only in this page: a reload makes
   * that vault permanently unreadable, even while it is locked.
   */
  losesEphemeralVault(): boolean {
    return this.vault.keyMode() === 'ephemeral';
  }

  /** True when reloading now would discard something the user has not saved. */
  hasUnsavedState(): boolean {
    const s = this.vault.status();
    return s === 'unlocked' || s === 'stale' || this.vault.confirmingNewVault() || this.losesEphemeralVault();
  }

  /** User asked to switch to the new version (or to recover from `broken`). */
  async apply(): Promise<boolean> {
    if (this.hasUnsavedState()) {
      const ephemeral = this.losesEphemeralVault();
      const ok = await this.confirm.ask({
        title: 'update.confirmTitle',
        body: ephemeral ? 'update.confirmBodyEphemeral' : 'update.confirmBody',
        confirm: 'update.reloadNow',
        danger: ephemeral,
      });
      if (!ok) return false;
      this.vault.lock();
    }
    this.reload();
    return true;
  }
}
