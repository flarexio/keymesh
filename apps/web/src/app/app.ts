import { Component, OnInit, effect, inject } from '@angular/core';
import { I18n } from './core/i18n/i18n.service';
import { VaultService } from './core/vault.service';
import { DisplayPrefs } from './shared/display-prefs';
import { ConfirmDialog, ConfirmService, Toasts, ToastService } from './shared/feedback';
import { Icon } from './shared/icon';
import { Start } from './features/start';
import { VaultShell } from './features/vault-shell';

@Component({
  selector: 'app-root',
  imports: [Start, VaultShell, DisplayPrefs, ConfirmDialog, Toasts, Icon],
  template: `
    <a class="skip-link" href="#main">{{ i18n.t('app.skipToContent') }}</a>
    <div class="demo-strip" role="note" data-testid="demo-banner">
      <km-icon name="shieldAlert" />
      <p><strong>{{ i18n.t('demo.label') }}</strong> <span>{{ i18n.t('demo.detail') }}</span></p>
    </div>
    <header class="appbar">
      <div class="brand">
        <span class="brand-mark"><km-icon name="logo" /></span>
        <span class="brand-name">Keymesh</span>
        <span class="brand-tag">{{ i18n.t('app.tagline') }}</span>
      </div>
      <div class="appbar-tools">
        <km-display-prefs />
        @if (open()) {
          <button type="button" class="btn btn-primary lock-btn" data-testid="lock" (click)="vault.lock()">
            <km-icon name="lock" /><span>{{ i18n.t('app.lock') }}</span>
          </button>
        }
      </div>
    </header>
    <main id="main" tabindex="-1" [class.main-vault]="open()">
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
              <button type="button" class="btn btn-primary" (click)="reloadPage()">
                <km-icon name="refresh" /><span>{{ i18n.t('app.reloadPage') }}</span>
              </button>
            </section>
          </div>
        }
        @default {
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

  constructor() {
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
}
