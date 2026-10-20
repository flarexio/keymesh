import { Component, OnInit, inject } from '@angular/core';
import { VaultService } from './core/vault.service';
import { Start } from './features/start';
import { VaultShell } from './features/vault-shell';

@Component({
  selector: 'app-root',
  imports: [Start, VaultShell],
  template: `
    <div class="banner" role="note" data-testid="demo-banner">
      SYNTHETIC DEMO — NOT PRODUCTION. Development-only key provider held in memory. Do not enter real
      secrets.
    </div>
    <header class="app-head">
      <h1>Keymesh <span class="muted small">vault demo</span></h1>
      @if (vault.status() === 'unlocked' || vault.status() === 'stale') {
        <div class="head-meta">
          <span class="muted small" data-testid="key-mode">key: {{ vault.keyMode() }} · rev {{ vault.revision() }}</span>
          <button type="button" class="primary" data-testid="lock" (click)="vault.lock()">Lock</button>
        </div>
      }
    </header>
    <main>
      @if (vault.status() === 'loading') {
        <p aria-live="polite">Loading the Rust/WASM core…</p>
      } @else if (vault.status() === 'failed') {
        <p role="alert" class="error">{{ vault.error() }}</p>
      } @else if (vault.status() === 'unlocked' || vault.status() === 'stale') {
        <km-vault-shell />
      } @else {
        <km-start />
      }
    </main>
  `,
})
export class App implements OnInit {
  protected readonly vault = inject(VaultService);

  ngOnInit(): void {
    void this.vault.init();
  }
}
