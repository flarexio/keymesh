import { Component, computed, inject, input, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import type { MessageEncoding, SignatureOut, Verdict } from '../core/types';
import { VaultService } from '../core/vault.service';
import { ToastService } from '../shared/feedback';
import { Icon } from '../shared/icon';

/** Exact bytes of a message, as the core sees them (count + hex). */
function usePreview(vault: VaultService, message: () => string, encoding: () => MessageEncoding) {
  return computed(() => {
    if (!vault.coreReady()) return null;
    try {
      return { ok: true as const, ...vault.messagePreview(message(), encoding()) };
    } catch {
      return { ok: false as const };
    }
  });
}

async function copyText(toast: ToastService, text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast.show('secret.copied');
  } catch {
    toast.show('errors.clipboard', 'error');
  }
}

/**
 * Public-key display (hex, raw Base58) and local signing for one stored
 * Ed25519 key. Signing is an explicit action on exactly the bytes shown; the
 * private key stays in the core. No network, no transactions.
 */
@Component({
  selector: 'km-ed25519-sign',
  imports: [Icon],
  template: `
    <section class="detail-section tool-stack" data-testid="ed25519-tools" [attr.aria-label]="i18n.t('sign.region')">
      <h3 class="section-label"><km-icon name="signature" />{{ i18n.t('sign.publicKey') }}</h3>
      <div class="key-row">
        <span class="key-label">{{ i18n.t('sign.base58') }}</span>
        <code class="mono key-value" data-testid="pubkey-base58">{{ base58() }}</code>
        <button type="button" class="btn btn-sm" data-testid="copy-base58" (click)="copy(base58())"><km-icon name="copy" /><span>{{ i18n.t('secret.copy') }}</span></button>
      </div>
      <p class="field-hint">{{ i18n.t('sign.base58Hint') }}</p>

      <h3 class="section-label">{{ i18n.t('sign.title') }}</h3>
      <div class="callout callout-warn" role="note"><km-icon name="alert" /><p>{{ i18n.t('sign.warning') }}</p></div>
      <fieldset class="radio-row" [attr.aria-label]="i18n.t('sign.encoding')">
        <label><input type="radio" name="sign-enc" value="utf8" data-testid="sign-enc-utf8" [checked]="encoding() === 'utf8'" (change)="setEncoding('utf8')" />{{ i18n.t('sign.encUtf8') }}</label>
        <label><input type="radio" name="sign-enc" value="hex" data-testid="sign-enc-hex" [checked]="encoding() === 'hex'" (change)="setEncoding('hex')" />{{ i18n.t('sign.encHex') }}</label>
      </fieldset>
      <div class="field">
        <label class="field-label" for="sign-message">{{ i18n.t('sign.message') }}</label>
        <textarea id="sign-message" rows="3" class="mono" data-testid="sign-message" spellcheck="false" autocomplete="off"
          [value]="message()" (input)="setMessage($any($event.target).value)"></textarea>
      </div>
      @if (preview(); as p) {
        @if (p.ok) {
          <p class="field-hint" data-testid="sign-preview">
            {{ i18n.t('sign.bytes', { n: p.bytes }) }}
            <code class="mono bytes-hex">{{ p.hex }}{{ p.truncated ? '…' : '' }}</code>
          </p>
        } @else {
          <p class="field-hint field-error" data-testid="sign-preview-error">{{ i18n.t(encoding() === 'hex' ? 'sign.badHex' : 'sign.tooLong') }}</p>
        }
      }
      <div class="tool-actions">
        <button type="button" class="btn btn-primary" data-testid="sign-button" [disabled]="!preview()?.ok || !vault.unlocked()" (click)="sign()">
          <km-icon name="signature" /><span>{{ i18n.t('sign.button') }}</span>
        </button>
      </div>
      @if (result(); as r) {
        <dl class="fields" data-testid="signature-result">
          <div class="field-row">
            <dt>{{ i18n.t('sign.sigHex') }}</dt>
            <dd class="mono break" data-testid="signature-hex">{{ r.hex }}</dd>
          </div>
          <div class="field-row">
            <dt>{{ i18n.t('sign.sigBase58') }}</dt>
            <dd class="mono break" data-testid="signature-base58">{{ r.base58 }}</dd>
          </div>
        </dl>
        <div class="tool-actions">
          <button type="button" class="btn btn-sm" data-testid="copy-signature" (click)="copy(r.hex)"><km-icon name="copy" /><span>{{ i18n.t('sign.copyHex') }}</span></button>
          <button type="button" class="btn btn-sm" (click)="copy(r.base58)"><km-icon name="copy" /><span>{{ i18n.t('sign.copyBase58') }}</span></button>
        </div>
      }
      @if (error(); as e) {
        <p class="field-error" role="alert">{{ i18n.t(e) }}</p>
      }
    </section>
  `,
})
export class Ed25519Sign {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  private readonly toast = inject(ToastService);
  readonly itemId = input.required<string>();
  readonly base58 = input.required<string>();
  protected readonly message = signal('');
  protected readonly encoding = signal<MessageEncoding>('utf8');
  protected readonly preview = usePreview(this.vault, this.message, this.encoding);
  /** Signature for exactly the current message; cleared when it changes. */
  protected readonly result = signal<SignatureOut | null>(null);
  protected readonly error = signal<MessageKey | null>(null);

  protected setMessage(v: string): void {
    this.message.set(v);
    this.result.set(null);
  }

  protected setEncoding(e: MessageEncoding): void {
    this.encoding.set(e);
    this.result.set(null);
  }

  protected sign(): void {
    this.error.set(null);
    this.result.set(null);
    try {
      this.result.set(this.vault.signEd25519(this.itemId(), this.message(), this.encoding()));
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  protected copy(text: string): Promise<void> {
    return copyText(this.toast, text);
  }
}

const VERDICT: Record<Verdict, { key: MessageKey; tone: string }> = {
  valid: { key: 'verify.valid', tone: 'callout-success' },
  invalid: { key: 'verify.invalid', tone: 'callout-danger' },
  bad_public_key: { key: 'verify.badKey', tone: 'callout-warn' },
  bad_signature: { key: 'verify.badSignature', tone: 'callout-warn' },
  bad_message: { key: 'verify.badMessage', tone: 'callout-warn' },
};

/** Strict Ed25519 verification of any public key, message and signature. */
@Component({
  selector: 'km-ed25519-verify',
  imports: [Icon],
  template: `
    <section class="tool-stack" aria-labelledby="verify-title" data-testid="verify-card">
      <h3 id="verify-title" class="card-title"><km-icon name="check" />{{ i18n.t('verify.title') }}</h3>
      <p class="field-hint">{{ i18n.t('verify.lead') }}</p>
      <div class="field">
        <label class="field-label" for="verify-key">{{ i18n.t('verify.publicKey') }}</label>
        <input id="verify-key" class="mono" data-testid="verify-key" spellcheck="false" autocomplete="off" [value]="key()" (input)="set(key, $event)" />
      </div>
      <fieldset class="radio-row" [attr.aria-label]="i18n.t('sign.encoding')">
        <label><input type="radio" name="verify-enc" value="utf8" [checked]="encoding() === 'utf8'" (change)="encoding.set('utf8'); verdict.set(null)" />{{ i18n.t('sign.encUtf8') }}</label>
        <label><input type="radio" name="verify-enc" value="hex" data-testid="verify-enc-hex" [checked]="encoding() === 'hex'" (change)="encoding.set('hex'); verdict.set(null)" />{{ i18n.t('sign.encHex') }}</label>
      </fieldset>
      <div class="field">
        <label class="field-label" for="verify-message">{{ i18n.t('sign.message') }}</label>
        <textarea id="verify-message" rows="3" class="mono" data-testid="verify-message" spellcheck="false" autocomplete="off"
          [value]="message()" (input)="set(message, $event)"></textarea>
      </div>
      @if (preview(); as p) {
        @if (p.ok) {
          <p class="field-hint" data-testid="verify-preview">{{ i18n.t('sign.bytes', { n: p.bytes }) }}
            <code class="mono bytes-hex">{{ p.hex }}{{ p.truncated ? '…' : '' }}</code></p>
        }
      }
      <div class="field">
        <label class="field-label" for="verify-sig">{{ i18n.t('verify.signature') }}</label>
        <input id="verify-sig" class="mono" data-testid="verify-signature" spellcheck="false" autocomplete="off" [value]="signature()" (input)="set(signature, $event)" />
      </div>
      <div class="tool-actions">
        <button type="button" class="btn btn-primary" data-testid="verify-button" [disabled]="!vault.coreReady()" (click)="verify()">
          <km-icon name="check" /><span>{{ i18n.t('verify.button') }}</span>
        </button>
      </div>
      @if (verdict(); as v) {
        <div class="callout" [class]="'callout ' + verdictInfo(v).tone" role="status" data-testid="verify-result" [attr.data-verdict]="v">
          <km-icon [name]="v === 'valid' ? 'check' : 'alert'" /><p>{{ i18n.t(verdictInfo(v).key) }}</p>
        </div>
      }
    </section>
  `,
})
export class Ed25519Verify {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  protected readonly key = signal('');
  protected readonly message = signal('');
  protected readonly signature = signal('');
  protected readonly encoding = signal<MessageEncoding>('utf8');
  protected readonly preview = usePreview(this.vault, this.message, this.encoding);
  protected readonly verdict = signal<Verdict | null>(null);

  protected set(target: ReturnType<typeof signal<string>>, ev: Event): void {
    target.set((ev.target as HTMLInputElement).value);
    this.verdict.set(null);
  }

  protected verdictInfo(v: Verdict) {
    return VERDICT[v];
  }

  protected verify(): void {
    this.verdict.set(this.vault.verifyEd25519(this.key(), this.message(), this.encoding(), this.signature()));
  }
}
