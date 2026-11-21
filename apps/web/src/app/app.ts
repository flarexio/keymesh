import { Component, OnInit, effect, inject, signal } from '@angular/core';
import { AppRepair } from './core/app-repair';
import { I18n, MessageKey } from './core/i18n/i18n.service';
import { VaultService } from './core/vault.service';
import { DisplayPrefs } from './shared/display-prefs';
import { ConfirmDialog, ConfirmService, Toasts, ToastService } from './shared/feedback';
import { Icon } from './shared/icon';
import { Start } from './features/start';
import { VaultShell } from './features/vault-shell';
import { InstallApp, UpdateBanner } from './features/app-install';
import { BrandCatalog } from './shared/brand-catalog';
import { AutoLock, LockReason } from './core/auto-lock';
import { CredentialNotice } from './shared/credential-notice';

@Component({
  selector: 'app-root',
  imports: [Start, VaultShell, DisplayPrefs, ConfirmDialog, Toasts, Icon, UpdateBanner, InstallApp, CredentialNotice],
  template: `
    <a class="skip-link" href="#main">{{ i18n.t('app.skipToContent') }}</a>
    <div class="demo-strip" role="note" data-testid="demo-banner">
      <km-icon name="shieldAlert" />
      <p><strong>{{ i18n.t('demo.label') }}</strong> <span>{{ i18n.t('demo.detail') }}</span></p>
    </div>
    <km-update-banner />
    <header class="appbar">
      <div class="brand">
        <span class="brand-mark"><km-icon name="logo" /></span>
        <span class="brand-name">Keymesh</span>
        <span class="brand-tag">{{ i18n.t('app.tagline') }}</span>
      </div>
      <div class="appbar-tools">
        <km-install-app />
        <km-display-prefs />
        @if (open()) {
          <button type="button" class="btn btn-primary lock-btn" data-testid="lock" (click)="vault.lock()">
            <km-icon name="lock" /><span>{{ i18n.t('app.lock') }}</span>
          </button>
        }
      </div>
    </header>
    <main id="main" tabindex="-1" [class.main-vault]="open()">
      <km-credential-notice class="credential-notice-host" />
      @if (open()) {
        <km-vault-shell />
      } @else {
      @switch (vault.status()) {
        @case ('loading') {
          <div class="state-screen" aria-live="polite" aria-busy="true">
            <span class="spinner" aria-hidden="true"></span>
            <p>{{ i18n.t('app.loading') }}</p>
          </div>
        }
        @case ('failed') {
          <div class="state-screen">
            <section class="card state-card" role="alert">
              <span class="state-icon danger"><km-icon name="alert" /></span>
              <h2>{{ i18n.t('app.failedTitle') }}</h2>
              <p>{{ i18n.t('app.failedBody') }}</p>
              <div class="state-actions">
                <button type="button" class="btn btn-primary" (click)="reloadPage()">
                  <km-icon name="refresh" /><span>{{ i18n.t('app.reloadPage') }}</span>
                </button>
                <button type="button" class="btn" data-testid="repair-app" [disabled]="repairing()" (click)="repairApp()">
                  <km-icon name="download" /><span>{{ i18n.t(repairing() ? 'repair.working' : 'repair.button') }}</span>
                </button>
              </div>
              <p class="field-hint">{{ i18n.t('repair.hint') }}</p>
              @if (repairMsg(); as m) {
                <p class="qr-status error" role="status" data-testid="repair-status">{{ i18n.t(m) }}</p>
              }
            </section>
          </div>
        }
        @default {
          @if (autoLock.lastReason(); as why) {
            <div class="callout callout-info autolock-reason" role="status" data-testid="autolock-reason" [attr.data-reason]="why">
              <km-icon name="lock" /><p>{{ i18n.t(reasonKey[why]) }}</p>
            </div>
          }
          <km-start />
        }
      }
      }
    </main>
    <km-confirm-dialog />
    <km-toasts />
  `,
})
export class App implements OnInit {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  private readonly confirm = inject(ConfirmService);
  private readonly toast = inject(ToastService);

  protected readonly autoLock = inject(AutoLock);
  protected readonly reasonKey: Record<LockReason, MessageKey> = {
    idle: 'autolock.reason.idle',
    hidden: 'autolock.reason.hidden',
    clock: 'autolock.reason.clock',
    pagehide: 'autolock.reason.pagehide',
  };

  constructor() {
    this.autoLock.start();
    inject(BrandCatalog); // start loading login brand icons (lazy chunk)
    // Locking closes any pending confirmation and clears notifications.
    let wasOpen = false;
    effect(() => {
      const open = this.open();
      if (wasOpen && !open) {
        this.confirm.settle(false);
        this.toast.clear();
      }
      wasOpen = open;
    });
  }

  protected open(): boolean {
    const s = this.vault.status();
    return s === 'unlocked' || s === 'stale';
  }

  ngOnInit(): void {
    void this.vault.init();
  }

  protected reloadPage(): void {
    location.reload();
  }

  private readonly repair = inject(AppRepair);
  protected readonly repairing = signal(false);
  protected readonly repairMsg = signal<MessageKey | null>(null);

  /**
   * The app could not start (e.g. a damaged cached file). After the user
   * confirms, re-download this app's own files: only its service-worker
   * caches are removed (core/app-repair.ts); vault data is never touched.
   */
  protected async repairApp(): Promise<void> {
    this.repairMsg.set(null);
    const ok = await this.confirm.ask({
      title: 'repair.confirmTitle',
      body: 'repair.confirmBody',
      confirm: 'repair.confirm',
    });
    if (!ok) return;
    this.repairing.set(true);
    try {
      const result = await this.repair.repair();
      if (result === 'repaired') {
        location.reload();
        return;
      }
      this.repairMsg.set(result === 'offline' ? 'repair.offline' : 'repair.unavailable');
    } finally {
      this.repairing.set(false);
    }
  }
}
