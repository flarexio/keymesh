import { Component, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { VaultService } from '../core/vault.service';
import { CustomRow, FormModel, buildInput, emptyModel, modelFromView } from '../core/forms';
import { ItemKind, KIND_LABELS, Summary } from '../core/types';

type TextKey = {
  [K in keyof FormModel]: FormModel[K] extends string ? K : never;
}[keyof FormModel];

@Component({
  selector: 'km-item-form',
  template: `
    <form class="item-form" (submit)="save($event)" [attr.aria-label]="heading()">
      <h2>{{ heading() }}</h2>
      @if (editing()) {
        <p class="hint">Protected fields left empty keep their stored value.</p>
      }

      <label>Title <input name="title" required [value]="m().title" (input)="set('title', $event)" /></label>

      @switch (kind()) {
        @case ('login') {
          <label>Username <input name="username" autocomplete="off" [value]="m().username" (input)="set('username', $event)" /></label>
          <div class="field-with-action">
            <label>Password
              <input name="password" autocomplete="new-password" [type]="showPw() ? 'text' : 'password'"
                [placeholder]="editing() ? 'unchanged' : ''" [value]="m().password" (input)="set('password', $event)" />
            </label>
            <button type="button" (click)="showPw.set(!showPw())">{{ showPw() ? 'Hide' : 'Show' }}</button>
            <button type="button" (click)="generate()">Generate</button>
          </div>
          @if (editing()) { <label class="check"><input type="checkbox" (change)="clear('password', $event)" /> Remove stored password</label> }
          <label>URLs (one per line) <textarea name="urls" rows="2" [value]="m().urls" (input)="set('urls', $event)"></textarea></label>
          <label>Linked TOTP item
            <select name="totpItem" (change)="set('totpItem', $event)">
              <option value="" [selected]="m().totpItem === ''">None</option>
              @for (t of totpItems(); track t.id) {
                <option [value]="t.id" [selected]="m().totpItem === t.id">{{ t.title }}</option>
              }
            </select>
          </label>
          <label>Recovery codes (one per line)
            <textarea name="recoveryCodes" rows="2" [placeholder]="editing() ? 'unchanged' : ''"
              [value]="m().recoveryCodes" (input)="set('recoveryCodes', $event)"></textarea>
          </label>
        }
        @case ('secret') {
          <label>Secret / API credential
            <input name="secret" type="password" autocomplete="off" [required]="!editing()"
              [placeholder]="editing() ? 'unchanged' : ''" [value]="m().secret" (input)="set('secret', $event)" />
          </label>
          <label>Service <input name="service" [value]="m().service" (input)="set('service', $event)" /></label>
          <label>Username <input name="username" [value]="m().username" (input)="set('username', $event)" /></label>
        }
        @case ('contact') {
          <label>Full name <input name="fullName" [value]="m().fullName" (input)="set('fullName', $event)" /></label>
          <label>Organization <input name="organization" [value]="m().organization" (input)="set('organization', $event)" /></label>
          <p class="hint">One entry per line. Optional label: <code>work | ada&#64;example.test</code></p>
          <label>Emails <textarea name="emails" rows="2" [value]="m().emails" (input)="set('emails', $event)"></textarea></label>
          <label>Phones <textarea name="phones" rows="2" [value]="m().phones" (input)="set('phones', $event)"></textarea></label>
          <label>Addresses <textarea name="addresses" rows="2" [value]="m().addresses" (input)="set('addresses', $event)"></textarea></label>
          <label>Websites <textarea name="websites" rows="2" [value]="m().websites" (input)="set('websites', $event)"></textarea></label>
        }
        @case ('crypto_wallet') {
          <p class="hint">Passive encrypted storage only — no transactions, signing or chain access.</p>
          <label>Wallet software <input name="walletSoftware" [value]="m().walletSoftware" (input)="set('walletSoftware', $event)" /></label>
          <label>Network <input name="network" [value]="m().network" (input)="set('network', $event)" /></label>
          <label>Addresses (one per line) <textarea name="walletAddresses" rows="2" [value]="m().walletAddresses" (input)="set('walletAddresses', $event)"></textarea></label>
          <label>Derivation path <input name="derivationPath" [value]="m().derivationPath" (input)="set('derivationPath', $event)" /></label>
          <label>Recovery phrase
            <input name="recoveryPhrase" type="password" autocomplete="off" [placeholder]="editing() ? 'unchanged' : ''"
              [value]="m().recoveryPhrase" (input)="set('recoveryPhrase', $event)" />
          </label>
          <label>Wallet password
            <input name="walletPassword" type="password" autocomplete="off" [placeholder]="editing() ? 'unchanged' : ''"
              [value]="m().walletPassword" (input)="set('walletPassword', $event)" />
          </label>
          <label>Private key
            <input name="privateKey" type="password" autocomplete="off" [placeholder]="editing() ? 'unchanged' : ''"
              [value]="m().privateKey" (input)="set('privateKey', $event)" />
          </label>
        }
        @case ('secure_note') {
          <label>Note
            <textarea name="body" rows="6" [placeholder]="editing() ? 'unchanged — type to replace' : ''"
              [value]="m().body" (input)="set('body', $event)"></textarea>
          </label>
        }
        @case ('totp') {
          @if (!editing()) {
            <label>otpauth:// URI or Base32 secret
              <input name="totpSetup" type="password" autocomplete="off" required
                [value]="m().totpSetup" (input)="set('totpSetup', $event)" />
            </label>
            <p class="hint">QR code / camera scanning is not available in this demo.</p>
          }
          <label>Issuer <input name="issuer" [value]="m().issuer" (input)="set('issuer', $event)" /></label>
          <label>Account <input name="accountName" [value]="m().accountName" (input)="set('accountName', $event)" /></label>
        }
        @case ('ed25519_key') {
          @if (!editing()) {
            <p class="hint">A new key pair is generated inside the WASM core when you save. Only the public key is ever shown.</p>
          }
          <label>Comment <input name="comment" [value]="m().comment" (input)="set('comment', $event)" /></label>
        }
      }

      @if (kind() !== 'totp' && kind() !== 'ed25519_key' || editing()) {
        <label>Tags (comma separated) <input name="tags" [value]="m().tags" (input)="set('tags', $event)" /></label>
        @if (kind() !== 'secure_note') {
          <label>Notes
            <textarea name="notes" rows="2" [placeholder]="editing() ? 'unchanged' : ''" [value]="m().notes" (input)="set('notes', $event)"></textarea>
          </label>
          @if (editing()) { <label class="check"><input type="checkbox" (change)="clear('notes', $event)" /> Remove stored notes</label> }
        }
        <fieldset>
          <legend>Custom fields</legend>
          @for (row of m().custom; track $index; let i = $index) {
            <div class="custom-row">
              <label>Label <input [value]="row.label" (input)="setCustom(i, 'label', $event)" /></label>
              <label>Value
                <input [type]="row.concealed ? 'password' : 'text'" autocomplete="off"
                  [placeholder]="row.existing !== null && row.concealed ? 'unchanged' : ''"
                  [value]="row.value" (input)="setCustom(i, 'value', $event)" />
              </label>
              <label class="check"><input type="checkbox" [checked]="row.concealed" (change)="setConcealed(i, $event)" /> Concealed</label>
              <button type="button" (click)="removeCustom(i)" [attr.aria-label]="'Remove custom field ' + (i + 1)">Remove</button>
            </div>
          }
          <button type="button" (click)="addCustom()">Add custom field</button>
        </fieldset>
      }

      @if (error()) {
        <p role="alert" class="error">{{ error() }}</p>
      }
      <div class="actions">
        <button type="submit" class="primary" [disabled]="busy()">{{ editing() ? 'Save changes' : 'Create' }}</button>
        <button type="button" (click)="cancelled.emit()">Cancel</button>
      </div>
    </form>
  `,
})
export class ItemForm implements OnInit {
  private readonly vault = inject(VaultService);
  readonly kind = input.required<ItemKind>();
  /** Item id when editing; null to create. */
  readonly editId = input<string | null>(null);
  readonly saved = output<string>();
  readonly cancelled = output<void>();

  protected readonly m = signal<FormModel>(emptyModel());
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly showPw = signal(false);
  protected readonly editing = computed(() => this.editId() !== null);
  protected readonly heading = computed(
    () => `${this.editing() ? 'Edit' : 'New'} ${KIND_LABELS[this.kind()]}`,
  );
  protected readonly totpItems = signal<Summary[]>([]);

  ngOnInit(): void {
    const id = this.editId();
    if (id) this.m.set(modelFromView(this.vault.get(id)));
    if (this.kind() === 'login') this.totpItems.set(this.vault.summaries('totp'));
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

  protected generate(): void {
    try {
      const pw = this.vault.generatePassword('default');
      this.m.update((m) => ({ ...m, password: pw }));
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Generation failed');
    }
  }

  protected async save(ev: Event): Promise<void> {
    ev.preventDefault();
    this.error.set(null);
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
      this.error.set(e instanceof Error ? e.message : 'Save failed');
    } finally {
      this.busy.set(false);
    }
  }
}
