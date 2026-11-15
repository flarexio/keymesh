import { NgTemplateOutlet } from '@angular/common';
import { Component, OnDestroy, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { CustomRow, FormModel, buildInput, emptyModel, modelFromView } from '../core/forms';
import { GeneratedDraft } from '../core/generated-draft';
import { PasswordSettings, sameOptions } from '../core/password-options';
import { ItemKind, Summary } from '../core/types';
import { GeneratedPassword } from '../shared/generated-password';
import { Icon, KIND_ICONS } from '../shared/icon';
import { PasswordOptionsPanel, passwordProblem } from '../shared/password-options';
import { QrImport, TotpFromQr } from './qr-import';

type TextKey = {
  [K in keyof FormModel]: FormModel[K] extends string ? K : never;
}[keyof FormModel];

/** Client-side checks with localized messages (the core re-validates). */
type Invalid = Partial<Record<'title' | 'secret' | 'totpSetup', MessageKey>>;

let nextForm = 0;

@Component({
  selector: 'km-item-form',
  imports: [Icon, NgTemplateOutlet, PasswordOptionsPanel, GeneratedPassword, QrImport],
  template: `
    <form class="item-form" novalidate (submit)="save($event)" [attr.aria-label]="formLabel()">
      <header class="form-head">
        <span class="kind-tile kind-tile-lg" [attr.data-kind]="kind()"><km-icon [name]="icon()" /></span>
        <div>
          <p class="eyebrow">{{ i18n.t(editing() ? 'form.editEyebrow' : 'form.newEyebrow') }}</p>
          <h2 [id]="uid + '-heading'">{{ i18n.t(kindKey()) }}</h2>
        </div>
      </header>
      @if (editing()) {
        <div class="callout callout-info"><km-icon name="info" /><p>{{ i18n.t('form.keepHint') }}</p></div>
      }

      <section class="form-section">
        <div class="field">
          <label class="field-label" [for]="uid + '-title'">{{ i18n.t('field.title') }}</label>
          <input [id]="uid + '-title'" name="title" required autocomplete="off" [value]="m().title" (input)="set('title', $event)"
            [attr.aria-invalid]="!!shownErrors().title" [attr.aria-describedby]="shownErrors().title ? uid + '-title-err' : null" />
          @if (shownErrors().title; as e) {
            <p class="field-error" [id]="uid + '-title-err'"><km-icon name="alert" />{{ i18n.t(e) }}</p>
          }
        </div>

        @switch (kind()) {
          @case ('login') {
            <div class="field">
              <label class="field-label" [for]="uid + '-username'">{{ i18n.t('field.username') }}</label>
              <input [id]="uid + '-username'" name="username" autocomplete="off" [value]="m().username" (input)="set('username', $event)" />
            </div>
            <div class="field">
              <label class="field-label" [for]="uid + '-password'">{{ i18n.t('field.password') }}</label>
              <div class="input-group">
                <input [id]="uid + '-password'" name="password" autocomplete="new-password" class="mono" [type]="showPw() ? 'text' : 'password'"
                  [placeholder]="editing() ? i18n.t('form.unchanged') : ''" [value]="m().password" (input)="set('password', $event)" />
                <button type="button" class="btn" [attr.aria-pressed]="showPw()" (click)="showPw.set(!showPw())">
                  <km-icon [name]="showPw() ? 'eyeOff' : 'eye'" /><span>{{ i18n.t(showPw() ? 'secret.hide' : 'form.show') }}</span>
                </button>
<button type="button" class="btn" data-testid="open-generator" [attr.aria-expanded]="genOpen()" [attr.aria-controls]="uid + '-gen'"
                  (click)="toggleGenerator()"><km-icon name="dice" /><span>{{ i18n.t('form.generate') }}</span></button>
              </div>
            </div>
            <ng-container *ngTemplateOutlet="generator" />
            @if (editing()) {
              <label class="check"><input type="checkbox" (change)="clear('password', $event)" /> {{ i18n.t('form.removePassword') }}</label>
            }
            <div class="field">
              <label class="field-label" [for]="uid + '-urls'">{{ i18n.t('field.urls') }}</label>
              <textarea [id]="uid + '-urls'" name="urls" rows="2" [attr.aria-describedby]="uid + '-urls-hint'" [value]="m().urls" (input)="set('urls', $event)"></textarea>
              <p class="field-hint" [id]="uid + '-urls-hint'">{{ i18n.t('form.onePerLine') }}</p>
            </div>
            <div class="field">
              <label class="field-label" [for]="uid + '-totp'">{{ i18n.t('field.linkedTotp') }}</label>
              <select [id]="uid + '-totp'" name="totpItem" (change)="set('totpItem', $event)">
                <option value="" [selected]="m().totpItem === ''">{{ i18n.t('form.none') }}</option>
                @for (t of totpItems(); track t.id) {
                  <option [value]="t.id" [selected]="m().totpItem === t.id">{{ t.title }}</option>
                }
              </select>
            </div>
            <div class="field">
              <label class="field-label" [for]="uid + '-rc'">{{ i18n.t('field.recoveryCodes') }}</label>
              <textarea [id]="uid + '-rc'" name="recoveryCodes" rows="2" class="mono" [attr.aria-describedby]="uid + '-rc-hint'"
                [placeholder]="editing() ? i18n.t('form.unchanged') : ''" [value]="m().recoveryCodes" (input)="set('recoveryCodes', $event)"></textarea>
              <p class="field-hint" [id]="uid + '-rc-hint'">{{ i18n.t('form.onePerLine') }}</p>
            </div>
          }
          @case ('secret') {
            <div class="field">
              <label class="field-label" [for]="uid + '-secret'">{{ i18n.t('field.secretCredential') }}</label>
              <div class="input-group">
                <input [id]="uid + '-secret'" name="secret" type="password" autocomplete="off" class="mono" [required]="!editing()"
                  [attr.aria-invalid]="!!shownErrors().secret" [attr.aria-describedby]="shownErrors().secret ? uid + '-secret-err' : null"
                  [placeholder]="editing() ? i18n.t('form.unchanged') : ''" [value]="m().secret" (input)="set('secret', $event)" />
                <button type="button" class="btn" data-testid="open-generator" [attr.aria-expanded]="genOpen()" [attr.aria-controls]="uid + '-gen'"
                  (click)="toggleGenerator()"><km-icon name="dice" /><span>{{ i18n.t('form.generate') }}</span></button>
              </div>
              @if (shownErrors().secret; as e) {
                <p class="field-error" [id]="uid + '-secret-err'"><km-icon name="alert" />{{ i18n.t(e) }}</p>
              }
            </div>
            <ng-container *ngTemplateOutlet="generator" />
            <div class="field">
              <label class="field-label" [for]="uid + '-service'">{{ i18n.t('field.service') }}</label>
              <input [id]="uid + '-service'" name="service" [value]="m().service" (input)="set('service', $event)" />
            </div>
            <div class="field">
              <label class="field-label" [for]="uid + '-username'">{{ i18n.t('field.username') }}</label>
              <input [id]="uid + '-username'" name="username" autocomplete="off" [value]="m().username" (input)="set('username', $event)" />
            </div>
          }
          @case ('contact') {
            <div class="field-grid">
              <div class="field">
                <label class="field-label" [for]="uid + '-fullName'">{{ i18n.t('field.fullName') }}</label>
                <input [id]="uid + '-fullName'" name="fullName" [value]="m().fullName" (input)="set('fullName', $event)" />
              </div>
              <div class="field">
                <label class="field-label" [for]="uid + '-org'">{{ i18n.t('field.organization') }}</label>
                <input [id]="uid + '-org'" name="organization" [value]="m().organization" (input)="set('organization', $event)" />
              </div>
            </div>
            <p class="field-hint" [id]="uid + '-labeled-hint'">{{ i18n.t('form.labeledHint') }} <code>work | ada&#64;example.test</code></p>
            @for (f of contactLists; track f.key) {
              <div class="field">
                <label class="field-label" [for]="uid + '-' + f.key">{{ i18n.t(f.label) }}</label>
                <textarea [id]="uid + '-' + f.key" [name]="f.key" rows="2" [attr.aria-describedby]="uid + '-labeled-hint'"
                  [value]="m()[f.key]" (input)="set(f.key, $event)"></textarea>
              </div>
            }
          }
          @case ('crypto_wallet') {
            <div class="callout callout-info"><km-icon name="info" /><p>{{ i18n.t('form.walletPassive') }}</p></div>
            <div class="field-grid">
              <div class="field">
                <label class="field-label" [for]="uid + '-ws'">{{ i18n.t('field.walletSoftware') }}</label>
                <input [id]="uid + '-ws'" name="walletSoftware" [value]="m().walletSoftware" (input)="set('walletSoftware', $event)" />
              </div>
              <div class="field">
                <label class="field-label" [for]="uid + '-net'">{{ i18n.t('field.network') }}</label>
                <input [id]="uid + '-net'" name="network" [value]="m().network" (input)="set('network', $event)" />
              </div>
            </div>
            <div class="field">
              <label class="field-label" [for]="uid + '-addr'">{{ i18n.t('field.walletAddresses') }}</label>
              <textarea [id]="uid + '-addr'" name="walletAddresses" rows="2" class="mono" [attr.aria-describedby]="uid + '-addr-hint'"
                [value]="m().walletAddresses" (input)="set('walletAddresses', $event)"></textarea>
              <p class="field-hint" [id]="uid + '-addr-hint'">{{ i18n.t('form.onePerLine') }}</p>
            </div>
            <div class="field">
              <label class="field-label" [for]="uid + '-dp'">{{ i18n.t('field.derivationPath') }}</label>
              <input [id]="uid + '-dp'" name="derivationPath" class="mono" [value]="m().derivationPath" (input)="set('derivationPath', $event)" />
            </div>
            @for (f of walletSecrets; track f.key) {
              <div class="field">
                <label class="field-label" [for]="uid + '-' + f.key">{{ i18n.t(f.label) }}</label>
                <input [id]="uid + '-' + f.key" [name]="f.key" type="password" autocomplete="off" class="mono"
                  [placeholder]="editing() ? i18n.t('form.unchanged') : ''" [value]="m()[f.key]" (input)="set(f.key, $event)" />
              </div>
            }
          }
          @case ('secure_note') {
            <div class="field">
              <label class="field-label" [for]="uid + '-body'">{{ i18n.t('field.note') }}</label>
              <textarea [id]="uid + '-body'" name="body" rows="7" [placeholder]="editing() ? i18n.t('form.noteUnchanged') : ''"
                [value]="m().body" (input)="set('body', $event)"></textarea>
            </div>
          }
          @case ('totp') {
            @if (!editing()) {
              <div class="field">
                <label class="field-label" [for]="uid + '-setup'">{{ i18n.t('field.totpSetup') }}</label>
                <input [id]="uid + '-setup'" name="totpSetup" type="password" autocomplete="off" class="mono" required
                  [attr.aria-invalid]="!!shownErrors().totpSetup"
                  [attr.aria-describedby]="(shownErrors().totpSetup ? uid + '-setup-err ' : '') + uid + '-setup-hint'"
                  [value]="m().totpSetup" (input)="set('totpSetup', $event)" />
                @if (shownErrors().totpSetup; as e) {
                  <p class="field-error" [id]="uid + '-setup-err'"><km-icon name="alert" />{{ i18n.t(e) }}</p>
                }
                <p class="field-hint" [id]="uid + '-setup-hint'">{{ i18n.t('form.totpSetupHint') }}</p>
              </div>
              <km-qr-import (found)="fromQr($event)" />
            }
            <div class="field-grid">
              <div class="field">
                <label class="field-label" [for]="uid + '-issuer'">{{ i18n.t('field.issuer') }}</label>
                <input [id]="uid + '-issuer'" name="issuer" [value]="m().issuer" (input)="set('issuer', $event)" />
              </div>
              <div class="field">
                <label class="field-label" [for]="uid + '-acct'">{{ i18n.t('field.account') }}</label>
                <input [id]="uid + '-acct'" name="accountName" [value]="m().accountName" (input)="set('accountName', $event)" />
              </div>
            </div>
          }
          @case ('ed25519_key') {
            @if (!editing()) {
              <div class="callout callout-info"><km-icon name="info" /><p>{{ i18n.t('form.ed25519Hint') }}</p></div>
            }
            <div class="field">
              <label class="field-label" [for]="uid + '-comment'">{{ i18n.t('field.comment') }}</label>
              <input [id]="uid + '-comment'" name="comment" [value]="m().comment" (input)="set('comment', $event)" />
            </div>
          }
        }
      </section>

      @if ((kind() !== 'totp' && kind() !== 'ed25519_key') || editing()) {
        <section class="form-section">
          <h3 class="section-label">{{ i18n.t('form.organize') }}</h3>
          <div class="field">
            <label class="field-label" [for]="uid + '-tags'">{{ i18n.t('field.tags') }}</label>
            <input [id]="uid + '-tags'" name="tags" [attr.aria-describedby]="uid + '-tags-hint'" [value]="m().tags" (input)="set('tags', $event)" />
            <p class="field-hint" [id]="uid + '-tags-hint'">{{ i18n.t('form.tagsHint') }}</p>
          </div>
          @if (kind() !== 'secure_note') {
            <div class="field">
              <label class="field-label" [for]="uid + '-notes'">{{ i18n.t('field.notes') }}</label>
              <textarea [id]="uid + '-notes'" name="notes" rows="2" [placeholder]="editing() ? i18n.t('form.unchanged') : ''"
                [value]="m().notes" (input)="set('notes', $event)"></textarea>
            </div>
            @if (editing()) {
              <label class="check"><input type="checkbox" (change)="clear('notes', $event)" /> {{ i18n.t('form.removeNotes') }}</label>
            }
          }
        </section>
        <fieldset class="form-section custom-fields">
          <legend class="section-label">{{ i18n.t('field.customFields') }}</legend>
          @for (row of m().custom; track $index; let i = $index) {
            <div class="custom-row">
              <div class="field">
                <label class="field-label" [for]="uid + '-cl' + i">{{ i18n.t('form.customLabel') }}</label>
                <input [id]="uid + '-cl' + i" [value]="row.label" (input)="setCustom(i, 'label', $event)" />
              </div>
              <div class="field">
                <label class="field-label" [for]="uid + '-cv' + i">{{ i18n.t('form.customValue') }}</label>
                <input [id]="uid + '-cv' + i" [type]="row.concealed ? 'password' : 'text'" autocomplete="off"
                  [placeholder]="row.existing !== null && row.concealed ? i18n.t('form.unchanged') : ''"
                  [value]="row.value" (input)="setCustom(i, 'value', $event)" />
              </div>
              <label class="check"><input type="checkbox" [checked]="row.concealed" (change)="setConcealed(i, $event)" /> {{ i18n.t('form.concealed') }}</label>
              <button type="button" class="btn btn-ghost btn-icon" (click)="removeCustom(i)"
                [attr.aria-label]="i18n.t('form.removeCustom', { n: i + 1 })" [attr.title]="i18n.t('form.removeCustom', { n: i + 1 })">
                <km-icon name="trash" />
              </button>
            </div>
          }
          <button type="button" class="btn btn-sm" (click)="addCustom()"><km-icon name="plus" /><span>{{ i18n.t('form.addCustom') }}</span></button>
        </fieldset>
      }

      @if (error(); as e) {
        <div class="callout callout-danger" role="alert" data-testid="form-error"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
      }
      <div class="form-actions">
        <button type="button" class="btn" (click)="cancelled.emit()">{{ i18n.t('common.cancel') }}</button>
        <button type="submit" class="btn btn-primary" [disabled]="busy()">
          <km-icon name="check" /><span>{{ i18n.t(editing() ? 'form.saveChanges' : 'form.create') }}</span>
        </button>
      </div>
    </form>
    <ng-template #generator>
    @if (genOpen()) {
      <div class="gen-panel" [id]="uid + '-gen'" role="group" [attr.aria-label]="i18n.t('form.generateFor')"
        data-testid="form-generator" (keydown.enter)="keepEnter($event)">
        <p class="field-hint">{{ i18n.t('form.generatorHint') }}</p>
        <km-password-options />
        @if (candidate.current(); as c) {
          <km-generated-password [value]="c" [label]="i18n.t('gen.pw.result')" />
        } @else if (candidate.outdated()) {
          <div class="callout callout-info" data-testid="generated-outdated"><km-icon name="info" /><p>{{ i18n.t('gen.outdated') }}</p></div>
        }
        @if (genError(); as e) {
          <p class="field-error" role="alert"><km-icon name="alert" />{{ i18n.t(e) }}</p>
        }
        <div class="tool-actions">
          <button type="button" class="btn" data-testid="form-generate" [disabled]="!!genProblem()" (click)="generateCandidate()">
            <km-icon name="dice" /><span>{{ i18n.t('gen.preview') }}</span>
          </button>
          <button type="button" class="btn btn-primary" data-testid="form-use-password" [disabled]="!candidate.current()" (click)="useCandidate()">
            <km-icon name="check" /><span>{{ i18n.t('form.usePassword') }}</span>
          </button>
          <button type="button" class="btn btn-ghost" data-testid="form-generator-cancel" (click)="closeGenerator()">{{ i18n.t('common.cancel') }}</button>
        </div>
      </div>
    }
    </ng-template>
  `,
})
export class ItemForm implements OnInit, OnDestroy {
  private readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  readonly kind = input.required<ItemKind>();
  /** Item id when editing; null to create. */
  readonly editId = input<string | null>(null);
  readonly saved = output<string>();
  readonly cancelled = output<void>();

  protected readonly uid = `item-form-${++nextForm}`;
  protected readonly m = signal<FormModel>(emptyModel());
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly busy = signal(false);
  protected readonly showPw = signal(false);
  private readonly pwSettings = inject(PasswordSettings);
  /**
   * Inline generator: only "Use this password" changes the field, and only
   * with the value on screen, generated with the current settings.
   */
  protected readonly genOpen = signal(false);
  protected readonly candidate = new GeneratedDraft(this.pwSettings.options, sameOptions);
  protected readonly genError = signal<MessageKey | null>(null);
  protected readonly genProblem = computed(() => passwordProblem(this.vault, this.pwSettings.options()));
  /** Field errors appear after the first submit attempt, then update live. */
  private readonly submitted = signal(false);
  protected readonly editing = computed(() => this.editId() !== null);
  protected readonly icon = computed(() => KIND_ICONS[this.kind()]);
  protected readonly kindKey = computed((): MessageKey => `kind.${this.kind()}`);
  protected readonly formLabel = computed(() =>
    this.i18n.t('form.label', {
      action: this.i18n.t(this.editing() ? 'form.editEyebrow' : 'form.newEyebrow'),
      kind: this.i18n.t(this.kindKey()),
    }),
  );
  protected readonly totpItems = signal<Summary[]>([]);
  protected readonly contactLists: { key: TextKey; label: MessageKey }[] = [
    { key: 'emails', label: 'field.emails' },
    { key: 'phones', label: 'field.phones' },
    { key: 'addresses', label: 'field.addresses' },
    { key: 'websites', label: 'field.websites' },
  ];
  protected readonly walletSecrets: { key: TextKey; label: MessageKey }[] = [
    { key: 'recoveryPhrase', label: 'field.recoveryPhrase' },
    { key: 'walletPassword', label: 'field.walletPassword' },
    { key: 'privateKey', label: 'field.privateKey' },
  ];

  private readonly invalid = computed<Invalid>(() => {
    const m = this.m();
    const out: Invalid = {};
    if (!m.title.trim()) out.title = 'validation.titleRequired';
    if (this.kind() === 'secret' && !this.editing() && !m.secret) out.secret = 'validation.secretRequired';
    if (this.kind() === 'totp' && !this.editing() && !m.totpSetup.trim()) out.totpSetup = 'validation.totpRequired';
    return out;
  });
  protected readonly shownErrors = computed<Invalid>(() => (this.submitted() ? this.invalid() : {}));

  ngOnInit(): void {
    const id = this.editId();
    if (id) this.m.set(modelFromView(this.vault.get(id)));
    if (this.kind() === 'login') this.totpItems.set(this.vault.summaries('totp'));
  }

  /**
   * A TOTP setup read from a QR code: fills the (masked) setup field and
   * pre-fills only empty title/issuer/account fields, which stay editable.
   * Nothing is saved until the user submits; the core validates the URI then.
   */
  protected fromQr(t: TotpFromQr): void {
    this.m.update((m) => ({
      ...m,
      totpSetup: t.uri,
      issuer: m.issuer.trim() ? m.issuer : (t.issuer ?? ''),
      accountName: m.accountName.trim() ? m.accountName : (t.account ?? ''),
      title: m.title.trim() ? m.title : (t.issuer ?? t.account ?? ''),
    }));
  }

  protected set(key: TextKey, ev: Event): void {
    const value = (ev.target as HTMLInputElement).value;
    this.m.update((m) => ({ ...m, [key]: value }));
  }

  protected clear(field: string, ev: Event): void {
    const on = (ev.target as HTMLInputElement).checked;
    this.m.update((m) => ({ ...m, clear: { ...m.clear, [field]: on } }));
  }

  protected setCustom(i: number, key: 'label' | 'value', ev: Event): void {
    const value = (ev.target as HTMLInputElement).value;
    this.m.update((m) => ({
      ...m,
      custom: m.custom.map((r, n) => (n === i ? { ...r, [key]: value } : r)),
    }));
  }

  protected setConcealed(i: number, ev: Event): void {
    const on = (ev.target as HTMLInputElement).checked;
    this.m.update((m) => ({
      ...m,
      custom: m.custom.map((r, n) => (n === i ? { ...r, concealed: on } : r)),
    }));
  }

  protected addCustom(): void {
    const row: CustomRow = { label: '', concealed: false, value: '', existing: null };
    this.m.update((m) => ({ ...m, custom: [...m.custom, row] }));
  }

  protected removeCustom(i: number): void {
    this.m.update((m) => ({ ...m, custom: m.custom.filter((_, n) => n !== i) }));
  }

  protected toggleGenerator(): void {
    if (this.genOpen()) this.closeGenerator();
    else this.genOpen.set(true);
  }

  protected closeGenerator(): void {
    this.genOpen.set(false);
    this.candidate.clear();
    this.genError.set(null);
  }

  protected generateCandidate(): void {
    this.genError.set(null);
    this.candidate.clear();
    const options = this.pwSettings.options();
    try {
      this.candidate.set(this.vault.generatePasswordWith(options), options);
    } catch (e) {
      this.genError.set(errorKey(e));
    }
  }

  protected useCandidate(): void {
    const value = this.candidate.current();
    if (value === null) return;
    const field = this.kind() === 'secret' ? 'secret' : 'password';
    this.m.update((m) => ({ ...m, [field]: value }));
    this.closeGenerator();
  }

  ngOnDestroy(): void {
    this.candidate.clear();
  }

  /** Enter in a settings field must not submit (and save) the item form. */
  protected keepEnter(ev: Event): void {
    if ((ev.target as HTMLElement).tagName === 'INPUT') ev.preventDefault();
  }

  protected async save(ev: Event): Promise<void> {
    ev.preventDefault();
    this.error.set(null);
    this.submitted.set(true);
    const invalid = Object.keys(this.invalid());
    if (invalid.length) {
      const target = (ev.target as HTMLFormElement).querySelector<HTMLElement>('[aria-invalid=true]');
      setTimeout(() => (target ?? (ev.target as HTMLFormElement).querySelector<HTMLElement>('[aria-invalid=true]'))?.focus(), 0);
      return;
    }
    this.busy.set(true);
    const m = this.m();
    try {
      const id = this.editId();
      if (id) {
        await this.vault.updateItem(id, buildInput(this.kind(), m, true));
        this.saved.emit(id);
      } else if (this.kind() === 'totp') {
        this.saved.emit(
          await this.vault.createTotp(m.title.trim(), m.totpSetup, m.issuer.trim(), m.accountName.trim()),
        );
      } else if (this.kind() === 'ed25519_key') {
        this.saved.emit(await this.vault.generateEd25519(m.title.trim(), m.comment.trim()));
      } else {
        this.saved.emit(await this.vault.createItem(buildInput(this.kind(), m, false)));
      }
    } catch (e) {
      this.error.set(errorKey(e));
    } finally {
      this.busy.set(false);
    }
  }
}
