import { Component, computed, inject, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { Icon } from '../shared/icon';

/**
 * Encrypted backup of the stored envelope and verified restore. A restore
 * file must decrypt with the current DEVELOPMENT key provider before anything
 * is written; otherwise the stored vault is untouched.
 */
@Component({
  selector: 'km-backup',
  imports: [Icon],
  template: `
    <div class="page">
      <header class="page-head">
        <h2 id="backup-title">{{ i18n.t('backup.title') }}</h2>
        <p class="lead">{{ i18n.t('backup.lead') }}</p>
      </header>
      <div class="card-grid card-grid-2">
        <section class="card tool-card" aria-labelledby="backup-download">
          <h3 id="backup-download" class="card-title"><km-icon name="download" />{{ i18n.t('backup.download.title') }}</h3>
          <p>{{ i18n.t('backup.download.body', { key: keyLabel() }) }}</p>
          <div class="tool-actions">
            <button type="button" class="btn btn-primary" data-testid="backup-download" (click)="download()">
              <km-icon name="download" /><span>{{ i18n.t('backup.download.button') }}</span>
            </button>
          </div>
        </section>
        <section class="card tool-card" aria-labelledby="backup-restore">
          <h3 id="backup-restore" class="card-title"><km-icon name="upload" />{{ i18n.t('backup.restore.title') }}</h3>
          <p>{{ i18n.t('backup.restore.body', { mib: maxMiB() }) }}</p>
          <label class="file-drop">
            <km-icon name="upload" />
            <span>{{ i18n.t('backup.chooseFile') }}</span>
            <input type="file" class="visually-hidden-input" data-testid="restore-input" (change)="restore($event)" />
          </label>
        </section>
      </div>
      @if (message(); as m) {
        <div class="callout callout-success" role="status" data-testid="backup-status"><km-icon name="check" /><p>{{ i18n.t(m) }}</p></div>
      }
      @if (error(); as e) {
        <div class="callout callout-danger" role="alert" data-testid="backup-error"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
      }
    </div>
  `,
})
export class Backup {
  private readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  protected readonly message = signal<MessageKey | null>(null);
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly maxMiB = computed(() => Math.floor(this.vault.maxBytes() / (1024 * 1024)));
  protected readonly keyLabel = computed(() =>
    this.i18n.t(this.vault.keyMode() === 'synthetic-fixture' ? 'backup.keyFixture' : 'backup.keyEphemeral'),
  );

  protected async download(): Promise<void> {
    this.error.set(null);
    this.message.set(null);
    try {
      const bytes = await this.vault.backupBytes();
      const blob = new Blob([bytes.slice().buffer], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `keymesh-demo-backup-rev${this.vault.revision()}.keymesh`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      this.message.set('backup.downloaded');
    } catch (e) {
      this.error.set(errorKey(e));
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
      this.message.set('backup.restored');
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }
}
