import { Component, OnDestroy, effect, inject, input, signal } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { Icon } from './icon';
import { ToastService } from './feedback';

let nextId = 0;

/**
 * A freshly generated, not yet saved value: masked by default, explicit
 * Reveal/Copy, hidden again after 30 seconds or when the value changes.
 * Rendered as text content only (never an attribute).
 */
@Component({
  selector: 'km-generated-password',
  imports: [Icon],
  template: `
    <div class="secret-row generated" [class.revealed]="shown()" data-testid="generated-password">
      <span class="secret-label" [id]="labelId">{{ label() }}</span>
      <span class="secret-value mono" [attr.aria-labelledby]="labelId" data-testid="generated-value">
        @if (shown()) {
          {{ value() }}
        } @else {
          <span class="mask" [attr.aria-label]="i18n.t('secret.hidden')">••••••••••••</span>
        }
      </span>
      <span class="secret-actions">
        <button type="button" class="btn btn-sm" [attr.aria-pressed]="shown()" (click)="toggle()">
          <km-icon [name]="shown() ? 'eyeOff' : 'eye'" /><span>{{ i18n.t(shown() ? 'secret.hide' : 'secret.reveal') }}</span>
        </button>
        <button type="button" class="btn btn-sm" (click)="copy()"><km-icon name="copy" /><span>{{ i18n.t('secret.copy') }}</span></button>
      </span>
    </div>
    @if (error(); as e) {
      <p class="field-error" role="alert">{{ i18n.t(e) }}</p>
    }
  `,
})
export class GeneratedPassword implements OnDestroy {
  protected readonly i18n = inject(I18n);
  private readonly toast = inject(ToastService);
  readonly value = input.required<string>();
  readonly label = input.required<string>();
  protected readonly shown = signal(false);
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly labelId = `generated-${++nextId}`;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor() {
    effect(() => {
      this.value();
      this.hide();
      this.error.set(null);
    });
  }

  protected toggle(): void {
    if (this.shown()) return this.hide();
    this.shown.set(true);
    this.timer = setTimeout(() => this.hide(), 30_000);
  }

  protected async copy(): Promise<void> {
    this.error.set(null);
    // Absent on non-secure origins (plain-HTTP LAN preview).
    if (!navigator.clipboard) {
      this.error.set('errors.clipboard');
      return;
    }
    try {
      await navigator.clipboard.writeText(this.value());
      this.toast.show('secret.copied');
    } catch {
      this.error.set('errors.clipboard');
    }
  }

  private hide(): void {
    this.shown.set(false);
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  ngOnDestroy(): void {
    this.hide();
  }
}
