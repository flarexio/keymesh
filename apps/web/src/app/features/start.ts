import { Component, inject, signal } from '@angular/core';
import { KeyMode, VaultService } from '../core/vault.service';

@Component({
  selector: 'km-start',
  template: `
    <section class="panel start" aria-labelledby="start-title">
      @switch (vault.status()) {
        @case ('locked') {
          <h2 id="start-title">Vault locked</h2>
          <p>Decrypted data was removed from memory. The development key provider still holds its key in WASM memory.</p>
          <button type="button" class="primary" (click)="act(vault.openStored())">Unlock demo session</button>
        }
        @case ('stored') {
          <h2 id="start-title">Stored demo vault found</h2>
          <p class="mono small">Revision {{ vault.stored()?.revision }} · key id {{ vault.stored()?.kek_id }}</p>
          @if (vault.storedNeedsLostKey()) {
            <p role="alert" class="error">
              This vault was encrypted with an ephemeral demo key that existed only in the memory of an
              earlier page session. That key is gone, so this ciphertext can no longer be decrypted. There is
              no recovery in this demo.
            </p>
          } @else if (vault.canOpenStored()) {
            <button type="button" class="primary" (click)="act(vault.openStored())">
              Open with synthetic fixture key (test harness)
            </button>
          }
          <button type="button" class="danger" (click)="discard()">Discard stored demo vault</button>
        }
        @default {
          <h2 id="start-title">Start a synthetic demo vault</h2>
          <p>Choose a <strong>development-only</strong> key provider. Both keep the key in WASM memory only; neither is a real unlock or recovery mechanism.</p>
          <fieldset>
            <legend>Demo key provider</legend>
            <label class="check">
              <input type="radio" name="mode" value="ephemeral" [checked]="mode() === 'ephemeral'" (change)="mode.set('ephemeral')" />
              Ephemeral random key — lost on reload; the stored ciphertext then becomes inaccessible.
            </label>
            <label class="check">
              <input type="radio" name="mode" value="synthetic-fixture" [checked]="mode() === 'synthetic-fixture'" (change)="mode.set('synthetic-fixture')" />
              Synthetic fixture key — a <strong>public</strong> test key, so anyone can decrypt. Reopens after reload.
            </label>
          </fieldset>
          <button type="button" class="primary" (click)="act(vault.startNew(mode()))">Start demo vault</button>
        }
      }
      @if (error()) {
        <p role="alert" class="error">{{ error() }}</p>
      }
    </section>
  `,
})
export class Start {
  protected readonly vault = inject(VaultService);
  protected readonly mode = signal<KeyMode>('ephemeral');
  protected readonly error = signal<string | null>(null);

  protected async act(p: Promise<void>): Promise<void> {
    this.error.set(null);
    try {
      await p;
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Operation failed');
    }
  }

  protected discard(): Promise<void> | void {
    if (!confirm('Permanently discard the stored synthetic demo vault?')) return;
    return this.act(this.vault.discard());
  }
}
