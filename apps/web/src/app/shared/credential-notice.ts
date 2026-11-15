import { Component, inject } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { CredentialNoticeCode, VaultService } from '../core/vault.service';
import { Icon } from './icon';

const KEYS: Record<CredentialNoticeCode, MessageKey> = {
  rotatedWhileLocked: 'notice.rotatedWhileLocked',
  rotationUncertain: 'notice.rotationUncertain',
  quickUnlockSavedWhileLocked: 'notice.quickUnlockSavedWhileLocked',
  quickUnlockOrphan: 'notice.quickUnlockOrphan',
  quickUnlockUncertain: 'notice.quickUnlockUncertain',
};

/**
 * Outcome of a credential operation that outlived the view which started it
 * (a lock destroys that view). App-level, so it is visible locked AND
 * unlocked. Non-secret: a code, plus a passkey's label and creation time.
 */
@Component({
  selector: 'km-credential-notice',
  imports: [Icon],
  template: `
    @if (vault.credentialNotice(); as n) {
      <div class="callout callout-warn notice" role="alert" data-testid="credential-notice" [attr.data-code]="n.code">
        <km-icon name="alert" />
        <div class="notice-body">
          <p><strong>{{ i18n.t(n.code.startsWith('quick') ? 'notice.titlePasskey' : 'notice.title') }}</strong></p>
          <p>{{ i18n.t(keys[n.code]) }}</p>
          @if (n.passkey; as p) {
            <p class="field-hint" data-testid="credential-notice-passkey">
              {{ i18n.t('notice.passkeyMeta', { label: p.label, time: i18n.dateTime(p.at) }) }}
            </p>
          }
          <button type="button" class="btn btn-sm" data-testid="credential-notice-ack" (click)="vault.acknowledgeNotice()">{{ i18n.t('notice.ack') }}</button>
        </div>
      </div>
    }
  `,
})
export class CredentialNotice {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  protected readonly keys = KEYS;
}
