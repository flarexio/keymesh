import { Component, inject, input, output, signal } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { ToastService } from './feedback';
import { Icon } from './icon';
import { SecretInput } from './secret-input';

/**
 * Shows a new recovery code once and asks for it back. The core verifies the
 * typed code; this component only collects it.
 */
@Component({
  selector: 'km-recovery-confirm',
  imports: [Icon, SecretInput],
  template: `
    <div class="recovery" data-testid="recovery-step">
      <p class="lead">{{ i18n.t(lead()) }}</p>
      <div class="recovery-code" data-testid="recovery-code" role="group" [attr.aria-label]="i18n.t('protected.recoveryCode')">
        @for (g of groups(); track $index) {
          <span>{{ g }}</span>
        }
      </div>
      <p class="hint">{{ i18n.t('protected.recovery.storeHint') }}</p>
      <div class="tool-actions">
        <button type="button" class="btn" data-testid="copy-recovery" (click)="copy()">
          <km-icon name="copy" /><span>{{ i18n.t('protected.recovery.copy') }}</span>
        </button>
      </div>
      <label class="check">
        <input type="checkbox" data-testid="recovery-saved" [checked]="saved()" (change)="saved.set($any($event.target).checked)" />
        {{ i18n.t('protected.recovery.saved') }}
      </label>
      @if (saved()) {
        <form class="form-stack" (submit)="submit($event)">
          <km-secret-input label="protected.recovery.confirmLabel" name="recoveryConfirm" testid="recovery-confirm-input" [mono]="true" [(value)]="typed" />
          <div class="form-actions">
            <button type="submit" class="btn btn-primary" data-testid="recovery-confirm" [disabled]="busy() || !typed().trim()">
              <km-icon name="check" /><span>{{ i18n.t(confirmLabel()) }}</span>
            </button>
            <button type="button" class="btn btn-ghost" data-testid="recovery-cancel" [disabled]="busy()" (click)="cancelled.emit()">{{ i18n.t('protected.recovery.cancel') }}</button>
          </div>
        </form>
      }
    </div>
  `,
})
export class RecoveryConfirm {
  protected readonly i18n = inject(I18n);
  private readonly toast = inject(ToastService);
  /** The code to show (14 groups of 4 separated by "-"). */
  readonly code = input.required<string>();
  readonly lead = input<MessageKey>('protected.recovery.lead');
  readonly confirmLabel = input<MessageKey>('protected.recovery.confirm');
  readonly busy = input(false);
  readonly confirmed = output<string>();
  readonly cancelled = output<void>();
  protected readonly saved = signal(false);
  protected readonly typed = signal('');

  protected groups(): string[] {
    return this.code().split('-');
  }

  protected async copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(this.code());
      this.toast.show('protected.recovery.copied');
    } catch {
      this.toast.show('errors.clipboard', 'error');
    }
  }

  protected submit(ev: Event): void {
    ev.preventDefault();
    if (this.busy()) return;
    this.confirmed.emit(this.typed());
  }
}
