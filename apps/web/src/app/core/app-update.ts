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
 */
@Injectable({ providedIn: 'root' })
export class AppUpdate {
  private readonly sw = inject(SwUpdate);
  private readonly vault = inject(VaultService);
  private readonly confirm = inject(ConfirmService);
  /** A newer version is installed and waiting for a reload. */
  readonly ready = signal(false);
  /** The running version can no longer be served consistently. */
  readonly broken = signal(false);
  /** Last update download failed (the current version keeps working). */
  readonly failed = signal(false);
  /** Seam for tests; production reloads the page. */
  reload: () => void = () => location.reload();

  constructor() {
    if (!this.sw.isEnabled) return;
    const subs = [
      this.sw.versionUpdates.subscribe((e) => {
        if (e.type === 'VERSION_READY') this.ready.set(true);
        if (e.type === 'VERSION_INSTALLATION_FAILED') this.failed.set(true);
      }),
      this.sw.unrecoverable.subscribe(() => this.broken.set(true)),
    ];
    inject(DestroyRef).onDestroy(() => subs.forEach((s) => s.unsubscribe()));
  }

  get enabled(): boolean {
    return this.sw.isEnabled;
  }

  /** True when reloading now would discard something the user has not saved. */
  hasUnsavedState(): boolean {
    const s = this.vault.status();
    return s === 'unlocked' || s === 'stale' || this.vault.confirmingNewVault();
  }

  /** User asked to switch to the new version (or to recover from `broken`). */
  async apply(): Promise<boolean> {
    if (this.hasUnsavedState()) {
      const ok = await this.confirm.ask({
        title: 'update.confirmTitle',
        body: 'update.confirmBody',
        confirm: 'update.reloadNow',
      });
      if (!ok) return false;
      this.vault.lock();
    }
    this.reload();
    return true;
  }
}
