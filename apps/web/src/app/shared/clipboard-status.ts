import { Component, computed, effect, inject } from '@angular/core';
import { SecretClipboard } from '../core/clipboard';
import { I18n } from '../core/i18n/i18n.service';
import { Icon } from './icon';

/**
 * Status of a copied secret (review M-2): a visible countdown with "Clear
 * now" while it waits, and a short note when it was cleared. The number that
 * ticks is not announced every second: the live region below changes only
 * when a copy starts and when it ends.
 */
@Component({
  selector: 'km-clipboard-status',
  imports: [Icon],
  template: `
    @if (clip.countdown(); as n) {
      <div class="toast clipboard-status" data-testid="clipboard-status" [attr.data-seconds]="n">
        <km-icon name="copy" />
        <span aria-hidden="true">{{ i18n.t('clipboard.clearsIn', { n }) }}</span>
        <button type="button" class="btn btn-sm btn-ghost" data-testid="clipboard-clear-now" (click)="clip.clearNow()">
          {{ i18n.t('clipboard.clearNow') }}
        </button>
      </div>
    } @else if (clip.lastOutcome() === 'pending') {
      <div class="toast clipboard-status" data-testid="clipboard-status" data-state="pending">
        <km-icon name="info" /><span>{{ i18n.t('clipboard.pending') }}</span>
      </div>
    }
    <span class="visually-hidden" role="status" aria-live="polite" data-testid="clipboard-live">{{ announce() }}</span>
  `,
})
export class ClipboardStatus {
  protected readonly clip = inject(SecretClipboard);
  protected readonly i18n = inject(I18n);
  /** Stable while counting, so screen readers hear start and end only. */
  protected readonly announce = computed(() => {
    if (this.clip.countdown() !== null) return this.i18n.t('clipboard.copied', { n: 30 });
    switch (this.clip.lastOutcome()) {
      case 'cleared':
        return this.i18n.t('clipboard.cleared');
      case 'changed':
        return this.i18n.t('clipboard.changed');
      default:
        return '';
    }
  });
}
