import { Component, OnDestroy, inject, input, signal } from '@angular/core';
import { I18n } from '../core/i18n/i18n.service';
import { Icon } from './icon';

/**
 * Printable emergency kit for a password vault.
 *
 * Honest by construction:
 * * the master password is never printed, only a blank line to write it by
 *   hand;
 * * the recovery code is printed only if the user ticks the box;
 * * it says what opening the vault needs: the encrypted vault (this
 *   browser's storage or a backup file) plus the password OR the recovery
 *   code (alternatives, not two factors).
 *
 * The sheet exists in the page only while the print dialog is open; it is
 * built from what is already on screen, nothing is fetched, stored or cached.
 * Printers, spoolers and "Save as PDF" can keep copies outside Keymesh; the
 * caveat says so.
 */
@Component({
  selector: 'km-emergency-kit',
  imports: [Icon],
  template: `
    <details class="kit" data-testid="emergency-kit">
      <summary class="btn btn-sm btn-ghost"><km-icon name="download" /><span>{{ i18n.t('kit.open') }}</span></summary>
      <p class="field-hint">{{ i18n.t('kit.lead') }}</p>
      <label class="check">
        <input type="checkbox" data-testid="kit-include-code" [checked]="includeCode()" (change)="includeCode.set($any($event.target).checked)" />
        {{ i18n.t('kit.includeCode') }}
      </label>
      <p class="field-hint" role="note">{{ i18n.t('kit.caveat') }}</p>
      <button type="button" class="btn btn-sm" data-testid="kit-print" (click)="print()">
        <km-icon name="download" /><span>{{ i18n.t('kit.print') }}</span>
      </button>
    </details>
    @if (printing()) {
      <div class="kit-sheet" data-testid="kit-sheet" aria-hidden="true">
        <h1>{{ i18n.t('kit.sheetTitle') }}</h1>
        <p>{{ i18n.t('kit.sheetWhere', { origin: origin }) }}</p>
        @if (vaultId(); as id) {
          <p>{{ i18n.t('kit.sheetVault') }} <code>{{ id }}</code></p>
        }
        <p>{{ i18n.t('kit.sheetDate', { date: date }) }}</p>
        <h2>{{ i18n.t('kit.sheetNeedTitle') }}</h2>
        <ol>
          <li>{{ i18n.t('kit.sheetNeedData') }}</li>
          <li>{{ i18n.t('kit.sheetNeedCredential') }}</li>
        </ol>
        <h2>{{ i18n.t('kit.sheetPassword') }}</h2>
        <p class="kit-blank" data-testid="kit-password-blank">&nbsp;</p>
        <h2>{{ i18n.t('kit.sheetCode') }}</h2>
        @if (includeCode()) {
          <p class="kit-code" data-testid="kit-code">{{ code() }}</p>
        } @else {
          <p class="kit-blank" data-testid="kit-code-blank">&nbsp;</p>
        }
        <p class="kit-note">{{ i18n.t('kit.sheetKeepApart') }}</p>
        <p class="kit-note">{{ i18n.t('kit.sheetExperimental') }}</p>
      </div>
    }
  `,
})
export class EmergencyKit implements OnDestroy {
  protected readonly i18n = inject(I18n);
  readonly code = input.required<string>();
  readonly vaultId = input<string | null>(null);
  protected readonly includeCode = signal(false);
  protected readonly printing = signal(false);
  protected readonly origin = location.origin;
  protected date = '';
  private readonly done = () => this.finish();

  /** Show the sheet only for the print dialog, then remove it again. */
  protected print(): void {
    this.date = this.i18n.dateTime(Date.now());
    this.printing.set(true);
    document.body.classList.add('kit-printing');
    addEventListener('afterprint', this.done, { once: true });
    // Let Angular render the sheet before the dialog snapshots the page.
    setTimeout(() => {
      try {
        print();
      } finally {
        // Browsers whose print() returns before printing fire afterprint;
        // the others return here after the dialog closed.
        setTimeout(this.done, 0);
      }
    }, 0);
  }

  private finish(): void {
    removeEventListener('afterprint', this.done);
    document.body.classList.remove('kit-printing');
    this.printing.set(false);
  }

  ngOnDestroy(): void {
    this.finish();
  }
}
