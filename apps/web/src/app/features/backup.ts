import { Component, OnDestroy, computed, inject, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { Icon } from '../shared/icon';
import { RecoveryConfirm } from '../shared/recovery-confirm';
import { SecretInput } from '../shared/secret-input';
import { PassphraseSuggest } from '../shared/passphrase-suggest';
import { ProtectedRestore } from './protected-restore';
import { AutoLock, HIDE_CHOICES, IDLE_CHOICES } from '../core/auto-lock';
import { FaviconPref } from '../core/favicon-pref';

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
        <section class="card tool-card" aria-labelledby="qu-title" data-testid="quick-unlock-section">
          <h3 id="qu-title" class="card-title"><km-icon name="key" />{{ i18n.t('qu.title') }}</h3>
          <p>{{ i18n.t('qu.lead') }}</p>
          @if (passkeys(); as list) {
            @if (list.length === 0) {
              <p class="field-hint" data-testid="qu-none">{{ i18n.t('qu.none') }}</p>
            }
            <ul class="value-list" data-testid="qu-list">
              @for (k of list; track k.slot_id) {
                <li data-testid="qu-item" [attr.data-be]="k.be">
                  <span class="value-label">{{ k.label || 'Keymesh' }}</span>
                  <span class="value-text field-hint">{{ i18n.t(k.be ? 'qu.be1' : 'qu.be0') }}</span>
                  <button type="button" class="btn btn-sm btn-danger-ghost" data-testid="qu-remove" [disabled]="busy() || !quCurrent()" (click)="removePasskey(k.slot_id)">{{ i18n.t('qu.remove') }}</button>
                </li>
              }
            </ul>
          }
          <form class="form-stack" (submit)="addPasskey($event)">
            <km-secret-input label="security.current" name="quCurrent" autocomplete="current-password" testid="qu-current" [(value)]="quCurrent" />
            <div class="field">
              <label class="field-label" for="qu-label">{{ i18n.t('qu.label') }}</label>
              <input id="qu-label" data-testid="qu-label" maxlength="64" [value]="quLabel()" (input)="quLabel.set($any($event.target).value)" />
            </div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary" data-testid="qu-add" [disabled]="busy() || !vault.quickUnlockSupported()">
                <km-icon name="plus" /><span>{{ i18n.t(busy() ? 'qu.adding' : 'qu.add') }}</span>
              </button>
            </div>
          </form>
          <p class="field-hint">{{ i18n.t('qu.removeHint') }}</p>
          <p class="field-hint" data-testid="qu-pin-blocked">{{ i18n.t('qu.pinBlocked') }}</p>
          <p class="hint experimental"><km-icon name="shieldAlert" /> {{ i18n.t('qu.experimental') }}</p>
        </section>
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
              @if (passkeys().length) {
                <label class="check">
                  <input type="checkbox" data-testid="rotate-revoke-quick-unlock" [checked]="rotRevoke()" (change)="rotRevoke.set($any($event.target).checked)" />
                  {{ i18n.t('qu.revokeLabel', { names: passkeyNames() }) }}
                </label>
              }
              <div class="form-actions">
                <button type="submit" class="btn btn-primary" data-testid="begin-rotation" [disabled]="busy()">
                  <km-icon name="refresh" /><span>{{ i18n.t(busy() ? 'protected.working' : 'security.rotate.button') }}</span>
                </button>
              </div>
            </form>
          }
        </section>
      }
      <section class="card tool-card autolock-card" aria-labelledby="autolock-title" data-testid="autolock-section">
        <h3 id="autolock-title" class="card-title"><km-icon name="lock" />{{ i18n.t('autolock.title') }}</h3>
        <p class="field-hint">{{ i18n.t('autolock.lead') }}</p>
        <div class="field-grid">
          <div class="field">
            <label class="field-label" for="autolock-idle">{{ i18n.t('autolock.idle') }}</label>
            <select id="autolock-idle" data-testid="autolock-idle" (change)="setIdle($event)">
              @for (m of idleChoices; track m) {
                <option [value]="m" [selected]="m === autoLock.settings().idleMinutes">{{ m === 0 ? i18n.t('autolock.never') : i18n.t('autolock.minutes', { n: m }) }}</option>
              }
            </select>
          </div>
          <div class="field">
            <label class="field-label" for="autolock-hide">{{ i18n.t('autolock.hidden') }}</label>
            <select id="autolock-hide" data-testid="autolock-hide" (change)="setHide($event)">
              @for (sec of hideChoices; track sec) {
                <option [value]="sec" [selected]="sec === autoLock.settings().hideSeconds">{{ sec === 0 ? i18n.t('autolock.immediately') : sec < 60 ? i18n.t('autolock.seconds', { n: sec }) : i18n.t('autolock.minutes', { n: sec / 60 }) }}</option>
              }
            </select>
          </div>
        </div>
        @if (autoLock.settings().idleMinutes === 0) {
          <p class="field-hint field-error" role="note" data-testid="autolock-never-warning">{{ i18n.t('autolock.neverWarning') }}</p>
        }
        <p class="field-hint">{{ i18n.t('autolock.limits') }}</p>
      </section>
      <section class="card tool-card autolock-card" aria-labelledby="favicon-title" data-testid="favicon-section">
        <h3 id="favicon-title" class="card-title"><km-icon name="login" />{{ i18n.t('favicon.title') }}</h3>
        <p class="field-hint">{{ i18n.t('favicon.lead') }}</p>
        <label class="check">
          <input type="checkbox" data-testid="favicon-optin" [checked]="favicon.enabled()" (change)="favicon.set($any($event.target).checked)" />
          {{ i18n.t('favicon.optin') }}
        </label>
        <p class="field-hint">{{ i18n.t('favicon.limits') }}</p>
      </section>
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
  protected readonly autoLock = inject(AutoLock);
  protected readonly favicon = inject(FaviconPref);
  protected readonly idleChoices = IDLE_CHOICES;
  protected readonly hideChoices = HIDE_CHOICES;
  protected setIdle(ev: Event): void {
    this.autoLock.update({ ...this.autoLock.settings(), idleMinutes: Number((ev.target as HTMLSelectElement).value) });
  }
  protected setHide(ev: Event): void {
    this.autoLock.update({ ...this.autoLock.settings(), hideSeconds: Number((ev.target as HTMLSelectElement).value) });
  }
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
  protected readonly rotRevoke = signal(false);
  protected readonly quCurrent = signal('');
  protected readonly quLabel = signal('');
  /** Passkeys of the open vault; re-read whenever the vault changes. */
  protected readonly passkeys = computed(() => {
    this.vault.version();
    this.vault.revision();
    try {
      return this.vault.quickUnlockSlots();
    } catch {
      return [];
    }
  });
  protected readonly passkeyNames = computed(() => this.passkeys().map((k) => k.label || 'Keymesh').join(', '));

  protected addPasskey(ev: Event): void {
    ev.preventDefault();
    void this.act(async () => {
      await this.vault.enrollQuickUnlock(this.quCurrent(), this.quLabel().trim());
      this.quCurrent.set('');
      this.quLabel.set('');
      this.message.set('qu.added');
    });
  }

  protected removePasskey(slotId: string): void {
    void this.act(async () => {
      await this.vault.removeQuickUnlock(this.quCurrent(), slotId);
      this.quCurrent.set('');
      this.message.set('qu.removed');
    });
  }
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
      const code = await this.vault.beginRotation(this.rotCurrent(), this.rotNext(), this.rotRevoke());
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
