import { Component, DestroyRef, inject, signal } from '@angular/core';
import { AppUpdate } from '../core/app-update';
import { I18n } from '../core/i18n/i18n.service';
import { Icon } from '../shared/icon';

/** Update notice: shown when a new version is ready, or the running one is broken. */
@Component({
  selector: 'km-update-banner',
  imports: [Icon],
  template: `
    @if (update.broken() || update.ready()) {
      <div class="update-strip" role="status" data-testid="update-banner"
        [attr.data-state]="update.broken() ? 'broken' : 'ready'">
        <km-icon [name]="update.broken() ? 'alert' : 'refresh'" />
        <p>{{ i18n.t(update.broken() ? 'update.broken' : 'update.ready') }}</p>
        <button type="button" class="btn btn-sm btn-primary" data-testid="update-reload" (click)="update.apply()">
          {{ i18n.t('update.reloadNow') }}
        </button>
      </div>
    }
  `,
})
export class UpdateBanner {
  protected readonly update = inject(AppUpdate);
  protected readonly i18n = inject(I18n);
}

/** The browser's install event (Chromium only; not in TypeScript's DOM lib). */
interface InstallPromptEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

/**
 * "Install app": only shown when it can actually do something.
 * * Chromium-based browsers fire `beforeinstallprompt`; we keep it and offer
 *   an Install button.
 * * Safari on iPhone/iPad has no install event. `navigator.standalone`
 *   exists only there; when it is false we show a short "Add to Home
 *   Screen" hint instead. No user-agent sniffing.
 * * Already installed (standalone display mode): nothing is shown.
 */
@Component({
  selector: 'km-install-app',
  imports: [Icon],
  template: `
    @if (prompt()) {
      <button type="button" class="btn btn-ghost btn-sm" data-testid="install-app" (click)="install()">
        <km-icon name="download" /><span>{{ i18n.t('install.button') }}</span>
      </button>
    } @else if (iosHint()) {
      <details class="install-hint" data-testid="install-hint">
        <summary class="btn btn-ghost btn-sm"><km-icon name="download" /><span>{{ i18n.t('install.button') }}</span></summary>
        <p>{{ i18n.t('install.ios') }}</p>
      </details>
    }
  `,
})
export class InstallApp {
  protected readonly i18n = inject(I18n);
  protected readonly prompt = signal<InstallPromptEvent | null>(null);
  protected readonly iosHint = signal(false);

  constructor() {
    const standalone = matchMedia('(display-mode: standalone)').matches;
    const nav = navigator as Navigator & { standalone?: boolean };
    this.iosHint.set(!standalone && nav.standalone === false);
    const onPrompt = (e: Event) => {
      e.preventDefault();
      this.prompt.set(e as InstallPromptEvent);
    };
    const onInstalled = () => this.prompt.set(null);
    addEventListener('beforeinstallprompt', onPrompt);
    addEventListener('appinstalled', onInstalled);
    inject(DestroyRef).onDestroy(() => {
      removeEventListener('beforeinstallprompt', onPrompt);
      removeEventListener('appinstalled', onInstalled);
    });
  }

  protected async install(): Promise<void> {
    const p = this.prompt();
    if (!p) return;
    this.prompt.set(null); // the event can be used once
    await p.prompt();
  }
}
