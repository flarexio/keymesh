import { Component, OnDestroy, inject, output, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { GeneratedPassword } from './generated-password';
import { Icon } from './icon';

/** Words in a suggested master password (≈ 90.5 bits; see `passphrase.rs`). */
export const MASTER_WORDS = 7;

/**
 * "Suggest a passphrase" for a new master password: the core draws seven
 * words from the EFF Long Wordlist with the OS CSPRNG. The value is masked
 * until revealed, and is only handed to the form after the user confirms
 * they stored it somewhere safe. Nothing is persisted or sent anywhere.
 */
@Component({
  selector: 'km-passphrase-suggest',
  imports: [Icon, GeneratedPassword],
  template: `
    <div class="suggest" data-testid="passphrase-suggest">
      @if (value(); as v) {
        <km-generated-password [value]="v" [label]="i18n.t('suggest.label')" />
        <p class="field-hint">{{ i18n.t('suggest.strength', { n: words }) }}</p>
        <label class="check">
          <input type="checkbox" data-testid="suggest-stored" [checked]="stored()" (change)="stored.set($any($event.target).checked)" />
          {{ i18n.t('suggest.stored') }}
        </label>
        <div class="tool-actions">
          <button type="button" class="btn btn-sm btn-primary" data-testid="suggest-use" [disabled]="!stored()" (click)="use()">
            <km-icon name="check" /><span>{{ i18n.t('suggest.use') }}</span>
          </button>
          <button type="button" class="btn btn-sm" (click)="suggest()"><km-icon name="dice" /><span>{{ i18n.t('suggest.again') }}</span></button>
          <button type="button" class="btn btn-sm btn-ghost" (click)="clear()">{{ i18n.t('common.cancel') }}</button>
        </div>
      } @else {
        <button type="button" class="btn btn-sm btn-ghost" data-testid="suggest-passphrase" (click)="suggest()">
          <km-icon name="dice" /><span>{{ i18n.t('suggest.button') }}</span>
        </button>
      }
      @if (error(); as e) {
        <p class="field-error" role="alert">{{ i18n.t(e) }}</p>
      }
    </div>
  `,
})
export class PassphraseSuggest implements OnDestroy {
  protected readonly i18n = inject(I18n);
  private readonly vault = inject(VaultService);
  readonly chosen = output<string>();
  protected readonly words = MASTER_WORDS;
  protected readonly value = signal<string | null>(null);
  protected readonly stored = signal(false);
  protected readonly error = signal<MessageKey | null>(null);

  protected suggest(): void {
    this.error.set(null);
    this.stored.set(false);
    try {
      this.value.set(this.vault.generatePassphrase({ words: MASTER_WORDS, separator: 'space' }));
    } catch (e) {
      this.value.set(null);
      this.error.set(errorKey(e));
    }
  }

  protected use(): void {
    const v = this.value();
    if (!v || !this.stored()) return;
    this.chosen.emit(v);
    this.clear();
  }

  protected clear(): void {
    this.value.set(null);
    this.stored.set(false);
  }

  ngOnDestroy(): void {
    this.clear();
  }
}
