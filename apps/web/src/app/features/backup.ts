import { Component, OnDestroy, computed, inject, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { Icon } from '../shared/icon';
import { RecoveryConfirm } from '../shared/recovery-confirm';
import { SecretInput } from '../shared/secret-input';
import { PassphraseSuggest } from '../shared/passphrase-suggest';
import { ProtectedRestore } from './protected-restore';

/**
 * Encrypted backup of the stored envelope and verified restore. A restore
 * file must open (demo: with the current DEVELOPMENT key provider; password
 * vault: with the backup's password or recovery code) before anything is
 * written; otherwise the stored vault is untouched. Password vaults also get
 * password and recovery-code changes here.
 */
@Component({
  selector: 'km-backup',
  imports: [Icon, RecoveryConfirm, SecretInput, ProtectedRestore, PassphraseSuggest],
  template: `
    <div class="page">
      <header class="page-head">
        <h2 id="backup-title">{{ i18n.t('backup.title') }}</h2>
        <p class="lead">{{ i18n.t('backup.lead') }}</p>
      </header>
      <div class="card-grid card-grid-2">
        <section class="card tool-card" aria-labelledby="backup-download">
          <h3 id="backup-download" class="card-title"><km-icon name="download" />{{ i18n.t('backup.download.title') }}</h3>
          @if (vault.isProtected()) {
            <p>{{ i18n.t('backup.protected.body') }}</p>
          } @else {
            <p>{{ i18n.t('backup.download.body', { key: keyLabel() }) }}</p>
          }
          <div class="tool-actions">
            <button type="button" class="btn btn-primary" data-testid="backup-download" (click)="download()">
              <km-icon name="download" /><span>{{ i18n.t('backup.download.button') }}</span>
            </button>
          </div>
        </section>
        <section class="card tool-card" aria-labelledby="backup-restore">
          <h3 id="backup-restore" class="card-title"><km-icon name="upload" />{{ i18n.t('backup.restore.title') }}</h3>
          <p>{{ i18n.t('backup.restore.body', { mib: maxMiB() }) }}</p>
          @if (vault.isProtected()) {
            <km-protected-restore (restored)="message.set('backup.restored')" />
          } @else {
            <label class="file-drop">
              <km-icon name="upload" />
              <span>{{ i18n.t('backup.chooseFile') }}</span>
              <input type="file" class="visually-hidden-input" data-testid="restore-input" (change)="restore($event)" />
            </label>
          }
        </section>
      </div>
      @if (vault.isProtected()) {
        <header class="page-head">
          <h2 id="security-title">{{ i18n.t('security.title') }}</h2>
        </header>
        <div class="card-grid card-grid-2" data-testid="security-section">
          <section class="card tool-card" aria-labelledby="change-pw">
            <h3 id="change-pw" class="card-title"><km-icon name="key" />{{ i18n.t('security.change.title') }}</h3>
            <form class="form-stack" (submit)="changePassword($event)">
              <km-secret-input label="security.current" name="currentPassword" autocomplete="current-password" testid="change-current" [(value)]="current" />
              <km-secret-input label="protected.newPassword" name="newPassword" autocomplete="new-password" testid="change-new"
                hint="protected.passwordHint" [(value)]="next" />
              <km-secret-input label="protected.passwordConfirm" name="newPasswordConfirm" autocomplete="new-password" testid="change-confirm" [(value)]="again" />
              <km-passphrase-suggest (chosen)="next.set($event); again.set($event)" />
              <div class="form-actions">
                <button type="submit" class="btn btn-primary" data-testid="change-password" [disabled]="busy()">
                  <km-icon name="key" /><span>{{ i18n.t(busy() ? 'protected.working' : 'security.change.button') }}</span>
                </button>
              </div>
            </form>
          </section>
          <section class="card tool-card" aria-labelledby="new-recovery">
            <h3 id="new-recovery" class="card-title"><km-icon name="shield" />{{ i18n.t('security.recovery.title') }}</h3>
            @if (newCode(); as code) {
              <km-recovery-confirm [code]="code" [vaultId]="vault.protectedStored()?.vault_id ?? null" lead="security.recovery.body" confirmLabel="security.recovery.button" [busy]="busy()"
                (confirmed)="finishRecovery($event)" (cancelled)="cancelRecovery()" />
            } @else {
              <p>{{ i18n.t('security.recovery.body') }}</p>
              <form class="form-stack" (submit)="beginRecovery($event)">
                <km-secret-input label="security.current" name="recoveryCurrentPassword" autocomplete="current-password" testid="recovery-current" [(value)]="recoveryCurrent" />
                <div class="form-actions">
                  <button type="submit" class="btn" data-testid="begin-recovery-change" [disabled]="busy()">
                    <km-icon name="refresh" /><span>{{ i18n.t(busy() ? 'protected.working' : 'security.recovery.button') }}</span>
                  </button>
                </div>
              </form>
            }
          </section>
        </div>
        <div class="callout callout-warn" role="note" data-testid="rotation-note"><km-icon name="info" /><p>{{ i18n.t('security.rotation') }}</p></div>
        <section class="card tool-card" aria-labelledby="rotate-title" data-testid="rotate-section">
          <h3 id="rotate-title" class="card-title"><km-icon name="refresh" />{{ i18n.t('security.rotate.title') }}</h3>
          @if (rotateCode(); as code) {
            <km-recovery-confirm [code]="code" [vaultId]="vault.protectedStored()?.vault_id ?? null" lead="security.rotate.codeLead" confirmLabel="security.rotate.finish" [busy]="busy()"
              (confirmed)="finishRotation($event)" (cancelled)="cancelRotation()" />
          } @else {
            <p>{{ i18n.t('security.rotate.body') }}</p>
            <ul class="hint-list">
              <li>{{ i18n.t('security.rotate.backups') }}</li>
              <li>{{ i18n.t('security.rotate.copies') }}</li>
              <li>{{ i18n.t('security.rotate.services') }}</li>
            </ul>
            <form class="form-stack" (submit)="beginRotation($event)">
              <km-secret-input label="security.current" name="rotateCurrent" autocomplete="current-password" testid="rotate-current" [(value)]="rotCurrent" />
              <km-secret-input label="protected.newPassword" name="rotateNew" autocomplete="new-password" testid="rotate-new"
                hint="security.rotate.newHint" [(value)]="rotNext" />
              <km-secret-input label="protected.passwordConfirm" name="rotateConfirm" autocomplete="new-password" testid="rotate-confirm" [(value)]="rotAgain" />
              <km-passphrase-suggest (chosen)="rotNext.set($event); rotAgain.set($event)" />
              <div class="form-actions">
                <button type="submit" class="btn btn-primary" data-testid="begin-rotation" [disabled]="busy()">
                  <km-icon name="refresh" /><span>{{ i18n.t(busy() ? 'protected.working' : 'security.rotate.button') }}</span>
                </button>
              </div>
            </form>
          }
        </section>
      }
      @if (message(); as m) {
        <div class="callout callout-success" role="status" data-testid="backup-status"><km-icon name="check" /><p>{{ i18n.t(m) }}</p></div>
      }
      @if (error(); as e) {
        <div class="callout callout-danger" role="alert" data-testid="backup-error"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
      }
    </div>
  `,
})
export class Backup implements OnDestroy {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  protected readonly message = signal<MessageKey | null>(null);
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly maxMiB = computed(() => Math.floor(this.vault.maxBytes() / (1024 * 1024)));
  protected readonly keyLabel = computed(() =>
    this.i18n.t(this.vault.keyMode() === 'synthetic-fixture' ? 'backup.keyFixture' : 'backup.keyEphemeral'),
  );

  protected async download(): Promise<void> {
    this.error.set(null);
    this.message.set(null);
    try {
      const bytes = await this.vault.backupBytes();
      const blob = new Blob([bytes.slice().buffer], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = this.vault.isProtected()
        ? `keymesh-backup-rev${this.vault.revision()}.keymesh`
        : `keymesh-demo-backup-rev${this.vault.revision()}.keymesh`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      this.message.set('backup.downloaded');
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  protected async restore(ev: Event): Promise<void> {
    const el = ev.target as HTMLInputElement;
    const file = el.files?.[0];
    el.value = '';
    if (!file) return;
    this.error.set(null);
    this.message.set(null);
    try {
      await this.vault.restore(file);
      this.message.set('backup.restored');
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  // --- password vault --------------------------------------------------------

  protected readonly current = signal('');
  protected readonly next = signal('');
  protected readonly again = signal('');
  protected readonly recoveryCurrent = signal('');
  protected readonly newCode = signal<string | null>(null);
  protected readonly rotCurrent = signal('');
  protected readonly rotNext = signal('');
  protected readonly rotAgain = signal('');
  protected readonly rotateCode = signal<string | null>(null);
  private readonly working = signal(false);
  protected readonly busy = computed(() => this.working() || this.vault.credentialBusy());

  private async act(fn: () => Promise<void>): Promise<void> {
    if (this.busy()) return;
    this.error.set(null);
    this.message.set(null);
    this.working.set(true);
    try {
      await fn();
    } catch (e) {
      this.error.set(errorKey(e));
    } finally {
      this.working.set(false);
    }
  }

  protected changePassword(ev: Event): void {
    ev.preventDefault();
    try {
      this.vault.checkNewPassword(this.next());
    } catch (e) {
      this.error.set(errorKey(e));
      return;
    }
    if (this.next() !== this.again()) {
      this.error.set('protected.mismatch');
      return;
    }
    void this.act(async () => {
      await this.vault.changePassword(this.current(), this.next());
      this.current.set('');
      this.next.set('');
      this.again.set('');
      this.message.set('security.changed');
    });
  }

  protected beginRecovery(ev: Event): void {
    ev.preventDefault();
    void this.act(async () => {
      this.newCode.set(await this.vault.beginRecoveryChange(this.recoveryCurrent()));
      this.recoveryCurrent.set('');
    });
  }

  protected finishRecovery(code: string): void {
    void this.act(async () => {
      await this.vault.finishRecoveryChange(code);
      this.newCode.set(null);
      this.message.set('security.recovery.done');
    });
  }

  protected cancelRecovery(): void {
    this.vault.cancelRecoveryChange();
    this.newCode.set(null);
  }

  protected beginRotation(ev: Event): void {
    ev.preventDefault();
    try {
      this.vault.checkNewPassword(this.rotNext());
    } catch (e) {
      this.error.set(errorKey(e));
      return;
    }
    if (this.rotNext() !== this.rotAgain()) {
      this.error.set('protected.mismatch');
      return;
    }
    void this.act(async () => {
      const code = await this.vault.beginRotation(this.rotCurrent(), this.rotNext());
      this.rotCurrent.set('');
      this.rotNext.set('');
      this.rotAgain.set('');
      this.rotateCode.set(code);
    });
  }

  protected finishRotation(code: string): void {
    void this.act(async () => {
      try {
        await this.vault.finishRotation(code);
      } catch (e) {
        // A mistyped code keeps the rotation pending; anything else ends it.
        if (errorKey(e) !== 'errors.recoveryMismatch' && errorKey(e) !== 'errors.recoveryInvalid') this.rotateCode.set(null);
        throw e;
      }
      this.rotateCode.set(null);
      this.message.set('security.rotate.done');
    });
  }

  protected cancelRotation(): void {
    this.vault.cancelRotation();
    this.rotateCode.set(null);
  }

  ngOnDestroy(): void {
    if (this.newCode()) this.vault.cancelRecoveryChange();
    if (this.rotateCode()) this.vault.cancelRotation();
  }
}
