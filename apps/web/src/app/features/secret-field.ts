import { Component, OnDestroy, inject, input, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { ToastService } from '../shared/feedback';
import { Icon } from '../shared/icon';

let nextId = 0;

/**
 * One masked secret slot. The plaintext is fetched from the core only on an
 * explicit Reveal or Copy, rendered as text content (never an attribute), and
 * hidden again after 30 seconds or when the component is destroyed (e.g. on
 * lock).
 */
@Component({
  selector: 'km-secret-field',
  imports: [Icon],
  template: `
    <div class="secret-row" [class.revealed]="shown() !== null">
      <span class="secret-label" [id]="labelId">{{ label() }}</span>
      <span class="secret-value mono" [attr.aria-labelledby]="labelId" data-testid="secret-value">
        @if (shown() !== null) {
          {{ shown() }}
        } @else {
          <span class="mask" [attr.aria-label]="i18n.t('secret.hidden')">••••••••••••</span>
        }
      </span>
      <span class="secret-actions">
        <button type="button" class="btn btn-sm" (click)="toggle()" [attr.aria-pressed]="shown() !== null">
          <km-icon [name]="shown() !== null ? 'eyeOff' : 'eye'" /><span>{{ i18n.t(shown() !== null ? 'secret.hide' : 'secret.reveal') }}</span>
        </button>
        <button type="button" class="btn btn-sm" (click)="copy()">
          <km-icon name="copy" /><span>{{ i18n.t('secret.copy') }}</span>
        </button>
      </span>
    </div>
    @if (error(); as e) {
      <p class="field-error" role="alert">{{ i18n.t(e) }}</p>
    }
  `,
})
export class SecretField implements OnDestroy {
  private readonly vault = inject(VaultService);
  private readonly toast = inject(ToastService);
  protected readonly i18n = inject(I18n);
  readonly itemId = input.required<string>();
  readonly slot = input.required<string>();
  readonly label = input.required<string>();
  protected readonly shown = signal<string | null>(null);
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly labelId = `secret-label-${++nextId}`;
  private timer: ReturnType<typeof setTimeout> | null = null;

  protected toggle(): void {
    this.error.set(null);
    if (this.shown() !== null) {
      this.hide();
      return;
    }
    try {
      this.shown.set(this.vault.reveal(this.itemId(), this.slot()));
      this.timer = setTimeout(() => this.hide(), 30_000);
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  protected async copy(): Promise<void> {
    this.error.set(null);
    try {
      // Absent on non-secure origins (plain-HTTP LAN preview): check before revealing.
      if (!navigator.clipboard) {
        this.error.set('errors.clipboard');
        return;
      }
      await navigator.clipboard.writeText(this.vault.reveal(this.itemId(), this.slot()));
      this.toast.show('secret.copied');
    } catch (e) {
      this.error.set(e instanceof DOMException ? 'errors.clipboard' : errorKey(e));
    }
  }

  private hide(): void {
    this.shown.set(null);
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  ngOnDestroy(): void {
    this.hide();
  }
}
