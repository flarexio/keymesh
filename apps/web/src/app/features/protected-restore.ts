import { Component, computed, inject, output, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { Icon } from '../shared/icon';
import { SecretInput } from '../shared/secret-input';

/**
 * Restore a password-vault backup with its own password (stored unchanged)
 * or with its recovery code plus a new password. The file must open before
 * anything is written; see `VaultService.restoreProtected`.
 */
@Component({
  selector: 'km-protected-restore',
  imports: [Icon, SecretInput],
  template: `
    <label class="file-drop">
      <km-icon name="upload" />
      <span>{{ file() ? i18n.t('protected.restore.file', { name: file()!.name }) : i18n.t('backup.chooseFile') }}</span>
      <input type="file" class="visually-hidden-input" data-testid="protected-restore-input" (change)="pick($event)" />
    </label>
    @if (file()) {
      <form class="form-stack" (submit)="restore($event)" data-testid="protected-restore-form">
        <div class="segmented" role="group" [attr.aria-label]="i18n.t('protected.restore.method')">
          <button type="button" data-testid="restore-with-password" [attr.aria-pressed]="method() === 'password'" (click)="method.set('password')">{{ i18n.t('protected.restore.withPassword') }}</button>
          <button type="button" data-testid="restore-with-recovery" [attr.aria-pressed]="method() === 'recovery'" (click)="method.set('recovery')">{{ i18n.t('protected.restore.withRecovery') }}</button>
        </div>
        @if (method() === 'password') {
          <km-secret-input label="protected.password" name="backupPassword" autocomplete="current-password" testid="restore-password" [(value)]="password" />
        } @else {
          <km-secret-input label="protected.recoveryCode" name="backupCode" testid="restore-code" [mono]="true" [(value)]="code" />
          <km-secret-input label="protected.newPassword" name="restoreNewPassword" autocomplete="new-password" testid="restore-new-password"
            hint="protected.passwordHint" [(value)]="newPassword" />
        }
        <div class="form-actions">
          <button type="submit" class="btn btn-primary" data-testid="protected-restore" [disabled]="busy()">
            <km-icon name="upload" /><span>{{ i18n.t(busy() ? 'protected.working' : 'protected.restore.button') }}</span>
          </button>
        </div>
      </form>
    }
    @if (error(); as e) {
      <div class="callout callout-danger" role="alert" data-testid="protected-restore-error">
        <km-icon name="alert" />
        <p>{{ i18n.t(e) }}</p>
      </div>
    }
  `,
})
export class ProtectedRestore {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  readonly restored = output<void>();
  protected readonly file = signal<File | null>(null);
  protected readonly method = signal<'password' | 'recovery'>('password');
  protected readonly password = signal('');
  protected readonly code = signal('');
  protected readonly newPassword = signal('');
  protected readonly error = signal<MessageKey | null>(null);
  private readonly working = signal(false);
  protected readonly busy = computed(() => this.working() || this.vault.credentialBusy());

  protected pick(ev: Event): void {
    const el = ev.target as HTMLInputElement;
    const f = el.files?.[0] ?? null;
    el.value = '';
    this.error.set(null);
    this.file.set(f);
  }

  protected async restore(ev: Event): Promise<void> {
    ev.preventDefault();
    const f = this.file();
    if (!f || this.busy()) return;
    this.error.set(null);
    let credential: { password: string } | { recoveryCode: string; newPassword: string };
    if (this.method() === 'password') {
      credential = { password: this.password() };
    } else {
      try {
        this.vault.checkNewPassword(this.newPassword());
      } catch (e) {
        this.error.set(errorKey(e));
        return;
      }
      credential = { recoveryCode: this.code(), newPassword: this.newPassword() };
    }
    this.working.set(true);
    try {
      await this.vault.restoreProtected(f, credential);
      this.file.set(null);
      this.password.set('');
      this.code.set('');
      this.newPassword.set('');
      this.restored.emit();
    } catch (e) {
      this.error.set(errorKey(e));
    } finally {
      this.working.set(false);
    }
  }
}
