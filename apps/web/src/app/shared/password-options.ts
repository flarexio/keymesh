import { Component, computed, inject, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import {
  DEFAULT_SYMBOLS,
  LENGTH_MAX,
  LENGTH_MIN,
  PasswordOptions,
  PasswordPreset,
  PasswordSettings,
  SYMBOL_TEXT_STORE_MAX,
  clientProblem,
} from '../core/password-options';
import { VaultService } from '../core/vault.service';
import { Icon } from './icon';

/** Why these settings can't be used, or null. Checked by the core without generating. */
export function passwordProblem(vault: VaultService, o: PasswordOptions): MessageKey | null {
  const local = clientProblem(o);
  if (local) return local;
  try {
    vault.checkPasswordOptions(o);
    return null;
  } catch (e) {
    return errorKey(e);
  }
}

type Flag = 'lowercase' | 'uppercase' | 'digits' | 'symbols' | 'excludeAmbiguous' | 'requireEachClass';

let nextId = 0;

/**
 * Password settings (shared by the generator page and the item forms).
 * Changing them never generates or saves anything by itself.
 */
@Component({
  selector: 'km-password-options',
  imports: [Icon],
  template: `
    <fieldset class="pw-options" data-testid="password-options">
      <legend class="visually-hidden">{{ i18n.t('pwopt.title') }}</legend>
      <div class="pw-options-top">
        <div class="field">
          <label class="field-label" [for]="uid + '-preset'">{{ i18n.t('pwopt.preset') }}</label>
          <select [id]="uid + '-preset'" name="pwPreset" (change)="setPreset($event)">
            @for (p of presets; track p.value) {
              <option [value]="p.value" [selected]="settings.preset() === p.value">{{ i18n.t(p.label) }}</option>
            }
          </select>
        </div>
        <div class="field">
          <label class="field-label" [for]="uid + '-length'">{{ i18n.t('pwopt.length') }}</label>
          <div class="length-row">
            <input type="range" name="pwLengthRange" [min]="min" [max]="max" step="1" [value]="slider()"
              [attr.aria-label]="i18n.t('pwopt.lengthSlider')" [attr.aria-describedby]="uid + '-length-hint'"
              (input)="fromSlider($event)" />
            <input [id]="uid + '-length'" name="pwLength" type="number" class="length-input" inputmode="numeric"
              [min]="min" [max]="max" step="1" [value]="lengthText()" (input)="fromNumber($event)"
              [attr.aria-invalid]="problem() === 'errors.pwLength'" [attr.aria-describedby]="uid + '-length-hint'" />
          </div>
          <p class="field-hint" [id]="uid + '-length-hint'">{{ i18n.t('pwopt.lengthHint') }}</p>
        </div>
      </div>

      <!-- Preset and length stay in view; types, symbols and fine options are here. Symbols stay on by default. -->
      <details class="more-options" data-testid="pw-more" [open]="moreOpen()" (toggle)="moreOpen.set($any($event.target).open)">
        <summary>
          <span>{{ i18n.t('pwopt.more') }}</span>
          <span class="more-summary" data-testid="pw-more-summary">{{ includedSummary() }}</span>
        </summary>
        <div class="more-options-body">
          <fieldset class="check-group">
            <legend class="field-label">{{ i18n.t('pwopt.include') }}</legend>
            <div class="check-grid">
              @for (c of classes; track c.flag) {
                <label class="check"><input type="checkbox" [name]="'pw-' + c.flag" [checked]="o()[c.flag]" (change)="toggle(c.flag, $event)" />
                  {{ i18n.t(c.label) }}</label>
              }
            </div>
          </fieldset>

          @if (o().symbols) {
            <div class="field">
              <label class="field-label" [for]="uid + '-symbols'">{{ i18n.t('pwopt.symbolSet') }}</label>
              <div class="input-group">
                <input [id]="uid + '-symbols'" name="pwSymbolSet" class="mono" autocomplete="off" spellcheck="false" autocapitalize="off" [maxLength]="symbolTextMax"
                  [value]="o().symbolSet" (input)="setSymbols($event)" [attr.aria-describedby]="uid + '-symbols-hint'"
                  [attr.aria-invalid]="symbolProblem()" />
                <button type="button" class="btn" [disabled]="o().symbolSet === defaultSymbols" (click)="settings.update({ symbolSet: defaultSymbols })">
                  {{ i18n.t('pwopt.symbolReset') }}
                </button>
              </div>
              <p class="field-hint" [id]="uid + '-symbols-hint'">{{ i18n.t('pwopt.symbolSetHint') }}</p>
            </div>
          }

          @for (c of extras; track c.flag) {
            <label class="check"><input type="checkbox" [name]="'pw-' + c.flag" [checked]="o()[c.flag]" (change)="toggle(c.flag, $event)" />
              {{ i18n.t(c.label) }}</label>
          }
        </div>
      </details>

      @if (problem(); as e) {
        <p class="field-error" role="alert" data-testid="password-options-error"><km-icon name="alert" />{{ i18n.t(e) }}</p>
      }
    </fieldset>
  `,
})
export class PasswordOptionsPanel {
  protected readonly settings = inject(PasswordSettings);
  protected readonly i18n = inject(I18n);
  private readonly vault = inject(VaultService);
  protected readonly uid = `pwopt-${++nextId}`;
  protected readonly min = LENGTH_MIN;
  protected readonly max = LENGTH_MAX;
  protected readonly defaultSymbols = DEFAULT_SYMBOLS;
  protected readonly symbolTextMax = SYMBOL_TEXT_STORE_MAX;
  protected readonly o = this.settings.options;
  protected readonly moreOpen = signal(false);
  /** What the user is typing in the number box (may be briefly invalid). */
  private readonly draft = signal<string | null>(null);
  protected readonly lengthText = computed(() => this.draft() ?? String(this.o().length));
  protected readonly slider = computed(() => {
    const n = this.o().length;
    return Number.isFinite(n) ? Math.min(LENGTH_MAX, Math.max(LENGTH_MIN, Math.round(n))) : LENGTH_MIN;
  });
  protected readonly problem = computed(() => passwordProblem(this.vault, this.o()));
  protected readonly symbolProblem = computed(() => {
    const p = this.problem();
    return p === 'errors.pwSymbolsEmpty' || p === 'errors.pwSymbolChars' || p === 'errors.pwSymbolsLong';
  });

  /** Included types, shown on the collapsed summary so hidden settings stay visible. */
  protected readonly includedSummary = computed(() => {
    const o = this.o();
    return this.classes
      .filter((c) => o[c.flag])
      .map((c) => this.i18n.t(`pwopt.short.${c.flag}` as MessageKey))
      .join(' · ');
  });

  protected readonly presets: { value: PasswordPreset; label: MessageKey }[] = [
    { value: 'default', label: 'pwopt.preset.default' },
    { value: 'strong', label: 'pwopt.preset.strong' },
    { value: 'custom', label: 'pwopt.preset.custom' },
  ];
  protected readonly classes: { flag: Flag; label: MessageKey }[] = [
    { flag: 'lowercase', label: 'pwopt.lowercase' },
    { flag: 'uppercase', label: 'pwopt.uppercase' },
    { flag: 'digits', label: 'pwopt.digits' },
    { flag: 'symbols', label: 'pwopt.symbols' },
  ];
  protected readonly extras: { flag: Flag; label: MessageKey }[] = [
    { flag: 'excludeAmbiguous', label: 'pwopt.excludeAmbiguous' },
    { flag: 'requireEachClass', label: 'pwopt.requireEach' },
  ];

  protected setPreset(ev: Event): void {
    this.draft.set(null);
    this.settings.setPreset((ev.target as HTMLSelectElement).value as PasswordPreset);
  }

  protected fromSlider(ev: Event): void {
    this.draft.set(null);
    this.settings.update({ length: Number((ev.target as HTMLInputElement).value) });
  }

  protected fromNumber(ev: Event): void {
    const text = (ev.target as HTMLInputElement).value;
    this.draft.set(text);
    this.settings.update({ length: text.trim() === '' ? NaN : Number(text) });
  }

  protected toggle(flag: Flag, ev: Event): void {
    this.settings.update({ [flag]: (ev.target as HTMLInputElement).checked });
  }

  protected setSymbols(ev: Event): void {
    this.settings.update({ symbolSet: (ev.target as HTMLInputElement).value });
  }
}
