import { NgTemplateOutlet } from '@angular/common';
import { Component, ElementRef, Injector, afterNextRender, computed, effect, inject, input, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { ConfirmService } from '../shared/feedback';
import { Icon } from '../shared/icon';
import { RecoveryConfirm } from '../shared/recovery-confirm';
import { SecretInput } from '../shared/secret-input';
import { PassphraseSuggest } from '../shared/passphrase-suggest';
import { ProtectedRestore } from './protected-restore';

type View = 'create' | 'unlock' | 'reset';

/**
 * Password vault on the start screen: create (password → recovery code →
 * confirmation), unlock, reset with the recovery code, restore a backup and
 * delete. Refused on non-secure origins, where only the demo is offered.
 */
@Component({
  selector: 'km-protected-start',
  imports: [Icon, RecoveryConfirm, SecretInput, ProtectedRestore, PassphraseSuggest, NgTemplateOutlet],
  template: `
    <section class="card start-card" id="protected-card" tabindex="-1" aria-labelledby="protected-title" data-testid="protected-section">
      @if (!vault.secure) {
        <span class="state-icon"><km-icon name="shieldAlert" /></span>
        <h2 id="protected-title">{{ i18n.t('protected.insecure.title') }}</h2>
        <p class="lead" data-testid="insecure-notice">{{ i18n.t('protected.insecure.body') }}</p>
      } @else if (vault.confirmingNewVault()) {
        <span class="state-icon"><km-icon name="key" /></span>
        <h2 id="protected-title">{{ i18n.t('protected.recovery.title') }}</h2>
        <km-recovery-confirm [code]="newCode()" [vaultId]="vault.newVaultId()" [busy]="busy()" (confirmed)="confirmNew($event)" (cancelled)="cancelNew()" />
      } @else if (vault.protectedStored()) {
        @if (view() === 'reset') {
          <span class="state-icon"><km-icon name="key" /></span>
          <h2 id="protected-title">{{ i18n.t('protected.reset.title') }}</h2>
          <p class="lead">{{ i18n.t('protected.reset.lead') }}</p>
          <form class="form-stack" (submit)="reset($event)">
            <km-secret-input label="protected.recoveryCode" name="recoveryCode" testid="reset-code" [mono]="true" [(value)]="code" />
            <km-secret-input label="protected.newPassword" name="newPassword" autocomplete="new-password" testid="reset-password"
              hint="protected.passwordHint" [(value)]="password" />
            <km-secret-input label="protected.passwordConfirm" name="newPasswordConfirm" autocomplete="new-password" testid="reset-password-confirm" [(value)]="confirm" />
            <km-passphrase-suggest (chosen)="password.set($event); confirm.set($event)" />
            <div class="form-actions">
              <button type="submit" class="btn btn-primary" data-testid="reset-submit" [disabled]="busy()">
                <km-icon name="key" /><span>{{ i18n.t(busy() ? 'protected.working' : 'protected.reset.button') }}</span>
              </button>
              <button type="button" class="btn btn-ghost" [disabled]="busy()" (click)="show('unlock')">{{ i18n.t('protected.back') }}</button>
            </div>
          </form>
        } @else {
          <span class="state-icon"><km-icon name="lock" /></span>
          <h2 id="protected-title">{{ i18n.t('protected.unlock.title') }}</h2>
          <p class="lead" data-testid="unlock-lead">{{ i18n.t(passkeyHere() ? 'protected.unlock.leadPasskey' : 'protected.unlock.lead') }}</p>
          @if (vault.protectedReloaded()) {
            <div class="callout callout-warn" role="status" data-testid="protected-reloaded">
              <km-icon name="info" />
              <p>{{ i18n.t('protected.reloaded') }}</p>
            </div>
          }
          <ng-template #unlockForm>
            <form class="form-stack" (submit)="unlock($event)">
              <km-secret-input label="protected.password" name="password" autocomplete="current-password" testid="unlock-password" [(value)]="password" />
              <div class="form-actions">
                <button type="submit" class="btn btn-lg" [class.btn-primary]="!passkeyHere()" data-testid="unlock-protected" [disabled]="busy() || !password()" [attr.aria-busy]="busy()">
                  <km-icon name="unlock" /><span>{{ i18n.t(busy() ? 'protected.unlocking' : 'protected.unlock.button') }}</span>
                </button>
                <button type="button" class="btn btn-link btn-sm" data-testid="forgot-password" [disabled]="busy()" (click)="show('reset')">{{ i18n.t('protected.forgot') }}</button>
              </div>
            </form>
          </ng-template>
          @if (passkeyHere()) {
            <!-- Passkey first: the master password is one click away (and opens by itself if the passkey fails). -->
            <div class="passkey-hero" data-testid="passkey-hero">
              <button type="button" class="btn btn-primary btn-lg passkey-hero-btn" data-testid="unlock-passkey" [disabled]="busy()"
                [attr.aria-busy]="busy()" aria-describedby="passkey-hero-hint" (click)="unlockPasskey()">
                <span class="passkey-hero-icon" aria-hidden="true"><km-icon name="fingerprint" /></span>
                <span>{{ i18n.t(passkeyRunning() ? 'protected.unlocking' : 'qu.unlock') }}</span>
              </button>
              <p class="hint" id="passkey-hero-hint">{{ i18n.t('qu.unlockHint') }}</p>
            </div>
            <div class="use-password">
              <button type="button" class="btn use-password-toggle" data-testid="use-password" [class.attention]="pwAttention()"
                [attr.aria-expanded]="pwOpen()" aria-controls="unlock-password-panel" (click)="togglePassword()">
                <km-icon name="lock" /><span>{{ i18n.t('protected.usePassword') }}</span><km-icon name="chevronDown" class="chevron" />
              </button>
              <div id="unlock-password-panel" class="collapse-panel" data-testid="password-panel" [class.open]="pwOpen()" [attr.inert]="pwOpen() ? null : ''">
                <div class="collapse-inner">
                  <ng-container [ngTemplateOutlet]="unlockForm" />
                </div>
              </div>
            </div>
          } @else {
            <ng-container [ngTemplateOutlet]="unlockForm" />
          }
          @if (inlineDelete()) {
            <div class="danger-zone">
              <p class="hint">{{ i18n.t('protected.delete.hint') }}</p>
              <button type="button" data-testid="delete-protected" class="btn btn-danger-ghost" [disabled]="busy()" (click)="remove()">
                <km-icon name="trash" /><span>{{ i18n.t('protected.delete.button') }}</span>
              </button>
            </div>
          }
        }
      } @else {
        <span class="state-icon"><km-icon name="shield" /></span>
        <h2 id="protected-title">{{ i18n.t('protected.create.title') }}</h2>
        <p class="lead">{{ i18n.t('protected.create.lead') }}</p>
        <form class="form-stack" (submit)="create($event)">
          <km-secret-input label="protected.password" name="newPassword" autocomplete="new-password" testid="create-password"
            hint="protected.passwordHint" [(value)]="password" />
          <km-secret-input label="protected.passwordConfirm" name="newPasswordConfirm" autocomplete="new-password" testid="create-password-confirm" [(value)]="confirm" />
          <km-passphrase-suggest (chosen)="password.set($event); confirm.set($event)" />
          <div class="form-actions">
            <button type="submit" class="btn btn-primary btn-lg" data-testid="create-protected" [disabled]="busy()" [attr.aria-busy]="busy()">
              <km-icon name="plus" /><span>{{ i18n.t(busy() ? 'protected.working' : 'protected.create.button') }}</span>
            </button>
          </div>
        </form>
        <div class="divider"><span>{{ i18n.t('common.or') }}</span></div>
        <h3 class="section-label">{{ i18n.t('protected.restore.title') }}</h3>
        <p class="hint">{{ i18n.t('protected.restore.lead') }}</p>
        <km-protected-restore />
      }
      @if (vault.secure) {
        <p class="hint experimental" data-testid="protected-experimental"><km-icon name="shieldAlert" /> {{ i18n.t('protected.experimental') }}</p>
      }
      @if (error(); as e) {
        <div class="callout callout-danger" role="alert" data-testid="protected-error">
          <km-icon name="alert" />
          <p>{{ i18n.t(e) }}</p>
        </div>
      }
    </section>
  `,
})
export class ProtectedStart {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  private readonly confirmDialog = inject(ConfirmService);
  private readonly host: ElementRef<HTMLElement> = inject(ElementRef);
  private readonly injector = inject(Injector);
  /** false: the start screen offers delete under "More options" instead. */
  readonly inlineDelete = input(true);
  /** The element this component focused itself (so it never takes focus the user moved). */
  private autoFocused: HTMLElement | null = null;

  constructor() {
    // Lock screen: focus the passkey button if there is one, else the password
    // field. Focus only; WebAuthn starts only from the user's click.
    effect(() => {
      const onLockScreen =
        this.vault.secure && !!this.vault.protectedStored() && !this.vault.confirmingNewVault() && this.view() === 'unlock';
      const passkey = this.passkeyHere();
      if (!onLockScreen) {
        this.autoFocused = null;
        return;
      }
      setTimeout(() => this.focusUnlock(passkey), 0);
    });
  }

  private focusUnlock(passkey: boolean): void {
    const target = this.host.nativeElement.querySelector<HTMLElement>(
      passkey ? '[data-testid=unlock-passkey]' : '[data-testid=unlock-password]',
    );
    const active = document.activeElement;
    const free = !active || active === document.body || (active === this.autoFocused && !this.password());
    if (!target || !free || active === target) return;
    target.focus();
    this.autoFocused = target;
  }
  protected readonly passkeyHere = computed(
    () => this.vault.quickUnlockSupported() && this.vault.storedQuickUnlock().some((x) => x.rp_id === location.hostname),
  );

  /** Passkey-first lock screen: the master-password section is open. */
  protected readonly pwOpen = signal(false);
  /** Set after a failed or cancelled passkey: the password option is highlighted. */
  protected readonly pwAttention = signal(false);

  protected readonly passkeyRunning = signal(false);

  protected async unlockPasskey(): Promise<void> {
    if (this.busy()) return;
    this.pwAttention.set(false);
    this.passkeyRunning.set(true);
    try {
      await this.act(() => this.vault.unlockWithQuickUnlock());
    } finally {
      this.passkeyRunning.set(false);
    }
    // Never stuck: after a failure or cancel, offer the master password.
    if (this.error() && this.view() === 'unlock' && this.passkeyHere()) {
      this.pwAttention.set(true);
      this.openPassword();
    }
  }

  protected togglePassword(): void {
    if (this.pwOpen()) {
      this.pwOpen.set(false);
      this.pwAttention.set(false);
    } else {
      this.openPassword();
    }
  }

  /** Expand the password section and move focus into the field once it is rendered (no longer inert). */
  private openPassword(): void {
    this.pwOpen.set(true);
    afterNextRender(
      () => {
        if (!this.pwOpen()) return;
        this.host.nativeElement.querySelector<HTMLElement>('#unlock-password-panel:not([inert]) [data-testid=unlock-password]')?.focus();
      },
      { injector: this.injector },
    );
  }
  protected readonly view = signal<View>('unlock');
  protected readonly password = signal('');
  protected readonly confirm = signal('');
  protected readonly code = signal('');
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly working = signal(false);
  readonly busy = computed(() => this.working() || this.vault.credentialBusy());

  protected newCode(): string {
    try {
      return this.vault.newVaultRecoveryCode();
    } catch {
      return '';
    }
  }

  protected show(v: View): void {
    this.error.set(null);
    this.clear();
    this.view.set(v);
  }

  private clear(): void {
    this.password.set('');
    this.confirm.set('');
    this.code.set('');
  }

  private async act(p: () => Promise<void>, clearAfter = true): Promise<void> {
    if (this.busy()) return;
    this.error.set(null);
    this.working.set(true);
    try {
      await p();
      if (clearAfter) this.clear();
    } catch (e) {
      this.error.set(errorKey(e));
    } finally {
      this.working.set(false);
    }
  }

  /** Both new-password fields must match; the core checks the rules. */
  private newPasswordProblem(pw: string, again: string): MessageKey | null {
    try {
      this.vault.checkNewPassword(pw);
    } catch (e) {
      return errorKey(e);
    }
    return pw === again ? null : 'protected.mismatch';
  }

  protected create(ev: Event): void {
    ev.preventDefault();
    const problem = this.newPasswordProblem(this.password(), this.confirm());
    if (problem) {
      this.error.set(problem);
      return;
    }
    void this.act(() => this.vault.createProtected(this.password()));
  }

  protected confirmNew(code: string): void {
    void this.act(() => this.vault.confirmNewVault(code));
  }

  protected cancelNew(): void {
    this.error.set(null);
    this.vault.cancelNewVault();
  }

  protected unlock(ev: Event): void {
    ev.preventDefault();
    void this.act(() => this.vault.unlockWithPassword(this.password()));
  }

  protected reset(ev: Event): void {
    ev.preventDefault();
    const problem = this.newPasswordProblem(this.password(), this.confirm());
    if (problem) {
      this.error.set(problem);
      return;
    }
    void this.act(() => this.vault.resetPassword(this.code(), this.password()));
  }

  /** Delete the stored password vault, after the confirm dialog. */
  async remove(): Promise<void> {
    const ok = await this.confirmDialog.ask({
      title: 'protected.delete.title',
      body: 'protected.delete.body',
      confirm: 'protected.delete.confirm',
      danger: true,
    });
    if (ok) await this.act(() => this.vault.discardProtected());
  }
}
