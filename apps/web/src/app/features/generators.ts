import { Component, inject, output, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { ToastService } from '../shared/feedback';
import { Icon } from '../shared/icon';

type TitleField = 'pw' | 'secret' | 'key';

const DEFAULT_TITLES: Record<TitleField, MessageKey> = {
  pw: 'gen.pw.defaultTitle',
  secret: 'gen.secret.defaultTitle',
  key: 'gen.key.defaultTitle',
};

/**
 * Generators run in the Rust core (OS CSPRNG via `crypto.getRandomValues`).
 * "Save" actions generate the value *inside* WASM and store it directly as an
 * encrypted item; the preview is only for copying elsewhere.
 *
 * Default titles follow the language until the user edits them; edited
 * values are never replaced by a language switch.
 */
@Component({
  selector: 'km-generators',
  imports: [Icon],
  template: `
    <div class="page">
      <header class="page-head">
        <h2 id="gen-title">{{ i18n.t('gen.title') }}</h2>
        <p class="lead">{{ i18n.t('gen.lead') }}</p>
      </header>
      <div class="card-grid">
        <section class="card tool-card" aria-labelledby="gen-pw">
          <h3 id="gen-pw" class="card-title"><km-icon name="key" />{{ i18n.t('gen.pw.title') }}</h3>
          <div class="field">
            <label class="field-label" for="gen-profile">{{ i18n.t('gen.pw.profile') }}</label>
            <select id="gen-profile" [value]="profile()" (change)="profile.set(value($event))">
              <option value="default">{{ i18n.t('gen.pw.default') }}</option>
              <option value="strong">{{ i18n.t('gen.pw.strong') }}</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label" for="gen-pw-title">{{ i18n.t('gen.savedTitle') }}</label>
            <input id="gen-pw-title" [value]="title('pw')" (input)="setTitle('pw', $event)" />
          </div>
          <div class="tool-actions">
            <button type="button" class="btn" (click)="previewPassword()">{{ i18n.t('gen.preview') }}</button>
            <button type="button" class="btn btn-primary" (click)="savePassword()"><km-icon name="plus" /><span>{{ i18n.t('gen.saveAsSecret') }}</span></button>
          </div>
          @if (shown()['pw']; as v) {
            <p class="mono preview" data-testid="password-preview">{{ v }}</p>
          }
        </section>

        <section class="card tool-card" aria-labelledby="gen-secret">
          <h3 id="gen-secret" class="card-title"><km-icon name="dice" />{{ i18n.t('gen.secret.title') }}</h3>
          <div class="field-grid">
            <div class="field">
              <label class="field-label" for="gen-bytes">{{ i18n.t('gen.secret.bytes') }}</label>
              <input id="gen-bytes" type="number" min="16" max="1024" inputmode="numeric" [value]="bytes()"
                (input)="bytes.set(value($event))" [attr.aria-invalid]="!bytesValid()" aria-describedby="gen-bytes-hint" />
            </div>
            <div class="field">
              <label class="field-label" for="gen-enc">{{ i18n.t('gen.secret.encoding') }}</label>
              <select id="gen-enc" [value]="encoding()" (change)="encoding.set(value($event))">
                <option value="hex">hex</option>
                <option value="base64url">base64url</option>
                <option value="base32">base32</option>
              </select>
            </div>
          </div>
          <p id="gen-bytes-hint" class="field-hint" [class.field-error]="!bytesValid()">{{ i18n.t('gen.secret.bytesHint') }}</p>
          <div class="field">
            <label class="field-label" for="gen-secret-title">{{ i18n.t('gen.savedTitle') }}</label>
            <input id="gen-secret-title" [value]="title('secret')" (input)="setTitle('secret', $event)" />
          </div>
          <p class="field-hint">{{ i18n.t('gen.secret.notProvider') }}</p>
          <div class="tool-actions">
            <button type="button" class="btn" [disabled]="!bytesValid()" (click)="previewSecret()">{{ i18n.t('gen.preview') }}</button>
            <button type="button" class="btn btn-primary" [disabled]="!bytesValid()" (click)="saveSecret()"><km-icon name="plus" /><span>{{ i18n.t('gen.saveAsSecret') }}</span></button>
          </div>
          @if (shown()['secret']; as v) {
            <p class="mono preview">{{ v }}</p>
          }
        </section>

        <section class="card tool-card" aria-labelledby="gen-key">
          <h3 id="gen-key" class="card-title"><km-icon name="signature" />{{ i18n.t('gen.key.title') }}</h3>
          <div class="field">
            <label class="field-label" for="gen-key-title">{{ i18n.t('field.title') }}</label>
            <input id="gen-key-title" [value]="title('key')" (input)="setTitle('key', $event)" />
          </div>
          <div class="field">
            <label class="field-label" for="gen-key-comment">{{ i18n.t('field.comment') }}</label>
            <input id="gen-key-comment" [value]="comment()" (input)="comment.set(value($event))" />
          </div>
          <p class="field-hint">{{ i18n.t('gen.key.hint') }}</p>
          <div class="tool-actions">
            <button type="button" class="btn btn-primary" (click)="saveKey()"><km-icon name="plus" /><span>{{ i18n.t('gen.key.save') }}</span></button>
          </div>
        </section>

        <section class="card tool-card muted-card" aria-labelledby="gen-pass">
          <h3 id="gen-pass" class="card-title"><km-icon name="note" />{{ i18n.t('gen.passphrase.title') }}</h3>
          <p class="field-hint">{{ i18n.t('gen.passphrase.pending') }}</p>
          <div class="tool-actions">
            <button type="button" class="btn" disabled>{{ i18n.t('gen.passphrase.button') }}</button>
          </div>
        </section>
      </div>
      @if (error(); as e) {
        <div class="callout callout-danger" role="alert"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
      }
    </div>
  `,
})
export class Generators {
  private readonly vault = inject(VaultService);
  private readonly toast = inject(ToastService);
  protected readonly i18n = inject(I18n);
  readonly created = output<string>();
  protected readonly shown = signal<Record<string, string>>({});
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly profile = signal('default');
  protected readonly bytes = signal('32');
  protected readonly encoding = signal('hex');
  protected readonly comment = signal('');
  /** User-edited titles; absent = localized default. */
  private readonly titles = signal<Partial<Record<TitleField, string>>>({});

  protected value(ev: Event): string {
    return (ev.target as HTMLInputElement).value;
  }

  protected title(f: TitleField): string {
    return this.titles()[f] ?? this.i18n.t(DEFAULT_TITLES[f]);
  }

  protected setTitle(f: TitleField, ev: Event): void {
    const v = this.value(ev);
    this.titles.update((t) => ({ ...t, [f]: v }));
  }

  protected bytesValid(): boolean {
    const n = Number(this.bytes());
    return Number.isInteger(n) && n >= 16 && n <= 1024;
  }

  private report(e: unknown): void {
    this.error.set(errorKey(e));
  }

  protected previewPassword(): void {
    this.error.set(null);
    try {
      const v = this.vault.generatePassword(this.profile() === 'strong' ? 'strong' : 'default');
      this.shown.update((s) => ({ ...s, pw: v }));
    } catch (e) {
      this.report(e);
    }
  }

  protected previewSecret(): void {
    this.error.set(null);
    try {
      const v = this.vault.generateRandomSecret(Number(this.bytes()), this.encoding());
      this.shown.update((s) => ({ ...s, secret: v }));
    } catch (e) {
      this.report(e);
    }
  }

  private async done(p: Promise<string>, what: MessageKey): Promise<void> {
    this.error.set(null);
    try {
      const id = await p;
      this.toast.show(what);
      this.created.emit(id);
    } catch (e) {
      this.report(e);
    }
  }

  protected savePassword(): Promise<void> {
    return this.done(this.vault.generatePasswordItem(this.title('pw'), this.profile(), ''), 'gen.pw.saved');
  }

  protected saveSecret(): Promise<void> {
    return this.done(
      this.vault.generateSecretItem(this.title('secret'), Number(this.bytes()), this.encoding(), ''),
      'gen.secret.saved',
    );
  }

  protected saveKey(): Promise<void> {
    return this.done(this.vault.generateEd25519(this.title('key'), this.comment()), 'gen.key.saved');
  }
}
