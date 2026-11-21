import { Component, inject, input, model } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { Icon } from './icon';

let nextId = 0;

/**
 * Labelled password / recovery-code input with a show/hide toggle. Paste and
 * password managers work (NIST SP 800-63B-4); nothing is stored or logged.
 */
@Component({
  selector: 'km-secret-input',
  imports: [Icon],
  template: `
    <div class="field">
      <label class="field-label" [for]="id">{{ i18n.t(label()) }}</label>
      <div class="input-group">
        <input [id]="id" [attr.name]="name()" [type]="shown ? 'text' : 'password'" [attr.autocomplete]="autocomplete()"
          [class.mono]="mono()" spellcheck="false" autocapitalize="off" [attr.data-testid]="testid()"
          [attr.aria-describedby]="hint() ? id + '-hint' : null" [attr.aria-invalid]="invalid() || null"
          [value]="value()" (input)="value.set($any($event.target).value)" />
        <button type="button" class="btn" [attr.aria-pressed]="shown" [attr.aria-controls]="id" (click)="shown = !shown">
          <km-icon [name]="shown ? 'eyeOff' : 'eye'" /><span>{{ i18n.t(shown ? 'protected.hide' : 'protected.show') }}</span>
        </button>
      </div>
      @if (hint(); as h) {
        <p class="field-hint" [id]="id + '-hint'">{{ i18n.t(h) }}</p>
      }
    </div>
  `,
})
export class SecretInput {
  protected readonly i18n = inject(I18n);
  readonly label = input.required<MessageKey>();
  readonly name = input.required<string>();
  readonly autocomplete = input<'new-password' | 'current-password' | 'off'>('off');
  readonly testid = input<string | null>(null);
  readonly hint = input<MessageKey | null>(null);
  readonly mono = input(false);
  readonly invalid = input(false);
  readonly value = model('');
  protected readonly id = `km-secret-${nextId++}`;
  protected shown = false;
}
