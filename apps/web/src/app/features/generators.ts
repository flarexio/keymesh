import { Component, OnDestroy, computed, inject, output, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { GeneratedDraft } from '../core/generated-draft';
import { PasswordSettings, sameOptions } from '../core/password-options';
import { VaultService } from '../core/vault.service';
import type { PassphraseOptions } from '../core/types';
import { Ed25519Verify } from './ed25519-tools';
import { ToastService } from '../shared/feedback';
import { GeneratedPassword } from '../shared/generated-password';
import { Icon } from '../shared/icon';
import { PasswordOptionsPanel, passwordProblem } from '../shared/password-options';

type TitleField = 'pw' | 'phrase' | 'secret' | 'key';

const DEFAULT_TITLES: Record<TitleField, MessageKey> = {
  pw: 'gen.pw.defaultTitle',
  phrase: 'gen.passphrase.defaultTitle',
  secret: 'gen.secret.defaultTitle',
  key: 'gen.key.defaultTitle',
};

type SecretParams = { bytes: string; encoding: string };
type PhraseParams = PassphraseOptions;

/**
 * Generators run in the Rust core (OS CSPRNG via `crypto.getRandomValues`).
 *
 * Password and random secret: Generate shows a masked preview that the core
 * also keeps; Save stores exactly that preview (the core refuses any other
 * value) and consumes it, so a double click or a second tab cannot save it
 * twice. A preview made with other settings than the current ones is shown
 * as outdated and cannot be saved. Previews are dropped when this view is
 * left or the vault locks. The Ed25519 key is generated and stored in one
 * step; only its public key is ever shown.
 *
 * Default titles follow the language until the user edits them; edited
 * values are never replaced by a language switch.
 */
@Component({
  selector: 'km-generators',
  imports: [Icon, PasswordOptionsPanel, GeneratedPassword, Ed25519Verify],
  template: `
    <div class="page">
      <header class="page-head">
        <h2 id="gen-title">{{ i18n.t('gen.title') }}</h2>
        <p class="lead">{{ i18n.t('gen.lead') }}</p>
      </header>
      <div class="card-grid">
        <section class="card tool-card tool-card-wide" aria-labelledby="gen-pw">
          <h3 id="gen-pw" class="card-title"><km-icon name="key" />{{ i18n.t('gen.pw.title') }}</h3>
          <km-password-options />
          <div class="field">
            <label class="field-label" for="gen-pw-title">{{ i18n.t('gen.savedTitle') }}</label>
            <input id="gen-pw-title" [value]="title('pw')" (input)="setTitle('pw', $event)" />
          </div>
          @if (pwDraft.current(); as v) {
            <km-generated-password [value]="v" [label]="i18n.t('gen.pw.result')" />
          } @else if (pwDraft.outdated()) {
            <div class="callout callout-info" data-testid="generated-outdated"><km-icon name="info" /><p>{{ i18n.t('gen.outdated') }}</p></div>
          }
          <div class="tool-actions">
            <button type="button" class="btn" data-testid="generate-password" [disabled]="!!pwProblem() || busy()" (click)="previewPassword()">
              <km-icon name="dice" /><span>{{ i18n.t('gen.preview') }}</span>
            </button>
            <button type="button" class="btn btn-primary" data-testid="save-password" [disabled]="!pwDraft.current() || busy()"
              (click)="savePassword()" aria-describedby="gen-pw-save-hint">
              <km-icon name="plus" /><span>{{ i18n.t(saving() === 'password' ? 'gen.saving' : 'gen.save') }}</span>
            </button>
          </div>
          <p id="gen-pw-save-hint" class="field-hint" data-testid="save-password-hint">
            {{ i18n.t(pwDraft.current() ? 'gen.pw.saveHint' : 'gen.pw.none') }}
          </p>
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
          @if (secretDraft.current(); as v) {
            <km-generated-password [value]="v" [label]="i18n.t('gen.secret.result')" />
          } @else if (secretDraft.outdated()) {
            <div class="callout callout-info"><km-icon name="info" /><p>{{ i18n.t('gen.outdated') }}</p></div>
          }
          <div class="tool-actions">
            <button type="button" class="btn" data-testid="generate-secret" [disabled]="!bytesValid() || busy()" (click)="previewSecret()">
              <km-icon name="dice" /><span>{{ i18n.t('gen.preview') }}</span>
            </button>
            <button type="button" class="btn btn-primary" data-testid="save-secret" [disabled]="!secretDraft.current() || busy()"
              (click)="saveSecret()" aria-describedby="gen-secret-save-hint">
              <km-icon name="plus" /><span>{{ i18n.t(saving() === 'secret' ? 'gen.saving' : 'gen.save') }}</span>
            </button>
          </div>
          <p id="gen-secret-save-hint" class="field-hint">
            {{ i18n.t(secretDraft.current() ? 'gen.secret.saveHint' : 'gen.secret.none') }}
          </p>
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
            <button type="button" class="btn btn-primary" [disabled]="busy()" (click)="saveKey()"><km-icon name="plus" /><span>{{ i18n.t('gen.key.save') }}</span></button>
          </div>
        </section>

        <section class="card tool-card" aria-labelledby="gen-pass" data-testid="passphrase-card">
          <h3 id="gen-pass" class="card-title"><km-icon name="note" />{{ i18n.t('gen.passphrase.title') }}</h3>
          <div class="field-grid">
            <div class="field">
              <label class="field-label" for="gen-words">{{ i18n.t('gen.passphrase.words') }}</label>
              <select id="gen-words" data-testid="passphrase-words" [value]="words()" (change)="words.set(value($event))">
                @for (n of wordChoices; track n) {
                  <option [value]="n">{{ n }}</option>
                }
              </select>
            </div>
            <div class="field">
              <label class="field-label" for="gen-sep">{{ i18n.t('gen.passphrase.separator') }}</label>
              <select id="gen-sep" data-testid="passphrase-separator" [value]="separator()" (change)="separator.set($any(value($event)))">
                <option value="space">{{ i18n.t('gen.passphrase.sepSpace') }}</option>
                <option value="period">{{ i18n.t('gen.passphrase.sepPeriod') }}</option>
              </select>
            </div>
          </div>
          @if (phraseSummary(); as sum) {
            <p class="field-hint" data-testid="passphrase-strength" [class.field-error]="!sum.master_ok">
              {{ i18n.t(sum.master_ok ? 'gen.passphrase.strength' : 'gen.passphrase.weak', { bits: sum.entropy_bits.toFixed(1), n: sum.list_size }) }}
            </p>
          }
          <div class="field">
            <label class="field-label" for="gen-phrase-title">{{ i18n.t('gen.savedTitle') }}</label>
            <input id="gen-phrase-title" [value]="title('phrase')" (input)="setTitle('phrase', $event)" />
          </div>
          @if (phraseDraft.current(); as v) {
            <km-generated-password [value]="v" [label]="i18n.t('gen.passphrase.result')" />
          } @else if (phraseDraft.outdated()) {
            <div class="callout callout-info"><km-icon name="info" /><p>{{ i18n.t('gen.outdated') }}</p></div>
          }
          <div class="tool-actions">
            <button type="button" class="btn" data-testid="generate-passphrase" [disabled]="busy()" (click)="previewPhrase()">
              <km-icon name="dice" /><span>{{ i18n.t('gen.preview') }}</span>
            </button>
            <button type="button" class="btn btn-primary" data-testid="save-passphrase" [disabled]="!phraseDraft.current() || busy()" (click)="savePhrase()">
              <km-icon name="plus" /><span>{{ i18n.t(saving() === 'passphrase' ? 'gen.saving' : 'gen.save') }}</span>
            </button>
          </div>
          <p class="field-hint">{{ i18n.t('gen.passphrase.source') }}</p>
        </section>

        <km-ed25519-verify class="card tool-card verify-card" />
      </div>
      @if (error(); as e) {
        <div class="callout callout-danger" role="alert"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
      }
    </div>
  `,
})
export class Generators implements OnDestroy {
  protected readonly vault = inject(VaultService);
  private readonly toast = inject(ToastService);
  protected readonly i18n = inject(I18n);
  readonly created = output<string>();
  protected readonly error = signal<MessageKey | null>(null);
  private readonly pw = inject(PasswordSettings);
  protected readonly pwProblem = computed(() => passwordProblem(this.vault, this.pw.options()));
  protected readonly bytes = signal('32');
  protected readonly encoding = signal('hex');
  protected readonly comment = signal('');
  protected readonly pwDraft = new GeneratedDraft(this.pw.options, sameOptions);
  protected readonly secretDraft = new GeneratedDraft<SecretParams>(
    () => ({ bytes: this.bytes(), encoding: this.encoding() }),
    (a, b) => a.bytes === b.bytes && a.encoding === b.encoding,
  );
  protected readonly wordChoices = [4, 5, 6, 7, 8, 9, 10, 11, 12];
  protected readonly words = signal('6');
  protected readonly separator = signal<PhraseParams['separator']>('space');
  private readonly phraseOptions = computed<PhraseParams>(() => ({ words: Number(this.words()), separator: this.separator() }));
  protected readonly phraseDraft = new GeneratedDraft<PhraseParams>(this.phraseOptions, (a, b) => a.words === b.words && a.separator === b.separator);
  protected readonly phraseSummary = computed(() => {
    if (!this.vault.coreReady()) return null;
    try {
      return this.vault.passphraseSummary(this.phraseOptions());
    } catch {
      return null;
    }
  });
  /** Which save is in flight; blocks every other action until it settles. */
  protected readonly saving = signal<'password' | 'passphrase' | 'secret' | 'key' | null>(null);
  /** Only an open, current vault can generate or save. */
  protected readonly busy = computed(() => this.saving() !== null || !this.vault.unlocked());
  private destroyed = false;
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

  protected previewPassword(): void {
    this.error.set(null);
    // Drop the previous value first, so a failure never leaves it on screen.
    this.pwDraft.clear();
    const options = this.pw.options();
    try {
      this.pwDraft.set(this.vault.previewPassword(options), options);
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  protected previewSecret(): void {
    this.error.set(null);
    this.secretDraft.clear();
    const params = { bytes: this.bytes(), encoding: this.encoding() };
    try {
      this.secretDraft.set(this.vault.previewSecret(Number(params.bytes), params.encoding), params);
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  protected previewPhrase(): void {
    this.error.set(null);
    this.phraseDraft.clear();
    const options = this.phraseOptions();
    try {
      this.phraseDraft.set(this.vault.previewPassphrase(options), options);
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  protected savePhrase(): Promise<void> {
    return this.saveDraft('passphrase', this.phraseDraft as GeneratedDraft<unknown>, 'phrase', 'gen.passphrase.saved');
  }

  /** Success is reported only after the encrypted write was committed. */
  private async save(what: 'password' | 'passphrase' | 'secret' | 'key', run: () => Promise<string>, ok: MessageKey): Promise<void> {
    if (this.saving() !== null) return; // double click
    this.saving.set(what);
    this.error.set(null);
    try {
      const id = await run();
      if (this.destroyed) return;
      this.toast.show(ok);
      this.created.emit(id);
    } catch (e) {
      if (this.destroyed) return;
      this.error.set(errorKey(e));
    } finally {
      this.saving.set(null);
    }
  }

  private saveDraft(kind: 'password' | 'passphrase' | 'secret', draft: GeneratedDraft<unknown>, f: TitleField, ok: MessageKey) {
    const shown = draft.current();
    if (shown === null) return Promise.resolve();
    return this.save(
      kind,
      async () => {
        try {
          const id = await this.vault.savePreview(kind, shown, this.title(f));
          draft.clear();
          return id;
        } catch (e) {
          // The core no longer holds it (saved elsewhere, replaced): don't offer it again.
          if (errorKey(e) === 'errors.previewGone') draft.clear();
          throw e;
        }
      },
      ok,
    );
  }

  protected savePassword(): Promise<void> {
    return this.saveDraft('password', this.pwDraft as GeneratedDraft<unknown>, 'pw', 'gen.pw.saved');
  }

  protected saveSecret(): Promise<void> {
    return this.saveDraft('secret', this.secretDraft as GeneratedDraft<unknown>, 'secret', 'gen.secret.saved');
  }

  protected saveKey(): Promise<void> {
    return this.save('key', () => this.vault.generateEd25519(this.title('key'), this.comment()), 'gen.key.saved');
  }

  ngOnDestroy(): void {
    this.destroyed = true;
    this.pwDraft.clear();
    this.phraseDraft.clear();
    this.secretDraft.clear();
    this.vault.discardPreviews();
  }
}
