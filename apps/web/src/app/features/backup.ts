import { Component, computed, inject, signal } from '@angular/core';
import { VaultService } from '../core/vault.service';

/**
 * Encrypted backup of the stored envelope and verified restore. A restore
 * file must decrypt with the current DEVELOPMENT key provider before anything
 * is written; otherwise the stored vault is untouched.
 */
@Component({
  selector: 'km-backup',
  template: `
    <section class="panel" aria-labelledby="backup-title">
      <h2 id="backup-title">Encrypted backup</h2>
      <p>
        Downloads the encrypted vault envelope exactly as stored. It contains no plaintext and can
        only be restored with the same demo key provider ({{ keyLabel() }}).
      </p>
      <button type="button" class="primary" (click)="download()">Download encrypted backup</button>

      <h3>Restore (synthetic demo harness)</h3>
      <p class="hint">
        Restore replaces the stored demo vault only after the file decrypts with the current demo key.
        Maximum size {{ maxMiB() }} MiB.
      </p>
      <label>Backup file <input type="file" data-testid="restore-input" (change)="restore($event)" /></label>

      @if (message()) {
        <p role="status" data-testid="backup-status">{{ message() }}</p>
      }
      @if (error()) {
        <p role="alert" class="error" data-testid="backup-error">{{ error() }}</p>
      }
    </section>
  `,
})
export class Backup {
  private readonly vault = inject(VaultService);
  protected readonly message = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly maxMiB = computed(() => Math.floor(this.vault.maxBytes() / (1024 * 1024)));
  protected readonly keyLabel = computed(() =>
    this.vault.keyMode() === 'synthetic-fixture'
      ? 'synthetic fixture key'
      : 'ephemeral key of this page session',
  );

  protected async download(): Promise<void> {
    this.error.set(null);
    try {
      const bytes = await this.vault.backupBytes();
      const blob = new Blob([bytes.slice().buffer], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `keymesh-demo-backup-rev${this.vault.revision()}.keymesh`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      this.message.set('Encrypted backup downloaded.');
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Backup failed');
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
      this.message.set('Backup restored.');
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Restore failed');
    }
  }
}
