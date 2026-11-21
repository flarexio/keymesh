import { Component, inject, output, signal } from '@angular/core';
import { VaultService } from '../core/vault.service';

/**
 * Generators run in the Rust core (OS CSPRNG via `crypto.getRandomValues`).
 * "Save" actions generate the value *inside* WASM and store it directly as an
 * encrypted item; the preview is only for copying elsewhere.
 */
@Component({
  selector: 'km-generators',
  template: `
    <section class="panel" aria-labelledby="gen-title">
      <h2 id="gen-title">Generators</h2>

      <fieldset>
        <legend>Password</legend>
        <label>Profile
          <select #profile>
            <option value="default">Default (24 characters)</option>
            <option value="strong">Strong (32 characters)</option>
          </select>
        </label>
        <label>Title for saved item <input #pwTitle value="Generated password" /></label>
        <div class="actions">
          <button type="button" (click)="preview('pw', profile.value)">Preview</button>
          <button type="button" class="primary" (click)="savePassword(pwTitle.value, profile.value)">Generate &amp; save as Secret</button>
        </div>
        @if (shown()['pw']; as v) {
          <p class="mono preview" data-testid="password-preview">{{ v }}</p>
        }
      </fieldset>

      <fieldset>
        <legend>Random secret (256-bit default)</legend>
        <label>Bytes <input #bytes type="number" min="16" max="1024" value="32" /></label>
        <label>Encoding
          <select #enc>
            <option value="hex">hex</option>
            <option value="base64url">base64url</option>
            <option value="base32">base32</option>
          </select>
        </label>
        <label>Title for saved item <input #secTitle value="Generated secret" /></label>
        <p class="hint">A local random value, not a provider-issued API credential.</p>
        <div class="actions">
          <button type="button" (click)="previewSecret(+bytes.value, enc.value)">Preview</button>
          <button type="button" class="primary" (click)="saveSecret(secTitle.value, +bytes.value, enc.value)">Generate &amp; save as Secret</button>
        </div>
        @if (shown()['secret']; as v) {
          <p class="mono preview">{{ v }}</p>
        }
      </fieldset>

      <fieldset>
        <legend>Ed25519 key pair</legend>
        <label>Title <input #keyTitle value="Generated Ed25519 key" /></label>
        <label>Comment <input #keyComment value="" /></label>
        <button type="button" class="primary" (click)="saveKey(keyTitle.value, keyComment.value)">Generate &amp; save key</button>
      </fieldset>

      <fieldset>
        <legend>Passphrase</legend>
        <p class="hint">Pending: no reviewed, versioned wordlist is bundled yet.</p>
        <button type="button" disabled>Generate passphrase</button>
      </fieldset>

      @if (message()) {
        <p role="status">{{ message() }}</p>
      }
    </section>
  `,
})
export class Generators {
  private readonly vault = inject(VaultService);
  readonly created = output<string>();
  protected readonly shown = signal<Record<string, string>>({});
  protected readonly message = signal<string | null>(null);

  private report(e: unknown): void {
    this.message.set(e instanceof Error ? e.message : 'Generation failed');
  }

  protected preview(key: string, profile: string): void {
    try {
      const v = this.vault.generatePassword(profile === 'strong' ? 'strong' : 'default');
      this.shown.set({ ...this.shown(), [key]: v });
    } catch (e) {
      this.report(e);
    }
  }

  protected previewSecret(bytes: number, enc: string): void {
    try {
      this.shown.set({ ...this.shown(), secret: this.vault.generateRandomSecret(bytes, enc) });
    } catch (e) {
      this.report(e);
    }
  }

  private async done(p: Promise<string>, what: string): Promise<void> {
    try {
      const id = await p;
      this.message.set(`${what} generated and saved.`);
      this.created.emit(id);
    } catch (e) {
      this.report(e);
    }
  }

  protected savePassword(title: string, profile: string): Promise<void> {
    return this.done(this.vault.generatePasswordItem(title, profile, ''), 'Password');
  }

  protected saveSecret(title: string, bytes: number, enc: string): Promise<void> {
    return this.done(this.vault.generateSecretItem(title, bytes, enc, ''), 'Secret');
  }

  protected saveKey(title: string, comment: string): Promise<void> {
    return this.done(this.vault.generateEd25519(title, comment), 'Ed25519 key');
  }
}
