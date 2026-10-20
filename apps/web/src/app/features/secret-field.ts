import { Component, OnDestroy, inject, input, signal } from '@angular/core';
import { VaultService } from '../core/vault.service';

let nextId = 0;

/**
 * One masked secret slot. The plaintext is fetched from the core only on an
 * explicit Reveal or Copy, rendered as text content (never an attribute), and
 * hidden again after 30 seconds or when the component is destroyed (e.g. on
 * lock).
 */
@Component({
  selector: 'km-secret-field',
  template: `
    <div class="secret-row">
      <span class="label" [id]="labelId">{{ label() }}</span>
      <span class="value mono" [attr.aria-labelledby]="labelId" data-testid="secret-value">
        @if (shown() !== null) {
          {{ shown() }}
        } @else {
          <span aria-label="hidden">••••••••</span>
        }
      </span>
      <span class="actions">
        <button type="button" (click)="toggle()" [attr.aria-pressed]="shown() !== null">
          {{ shown() !== null ? 'Hide' : 'Reveal' }}
        </button>
        <button type="button" (click)="copy()">Copy</button>
      </span>
    </div>
    @if (status()) {
      <span class="hint" role="status">{{ status() }}</span>
    }
  `,
})
export class SecretField implements OnDestroy {
  private readonly vault = inject(VaultService);
  readonly itemId = input.required<string>();
  readonly slot = input.required<string>();
  readonly label = input.required<string>();
  protected readonly shown = signal<string | null>(null);
  protected readonly status = signal<string | null>(null);
  protected readonly labelId = `secret-label-${++nextId}`;
  private timer: ReturnType<typeof setTimeout> | null = null;

  protected toggle(): void {
    if (this.shown() !== null) {
      this.hide();
      return;
    }
    try {
      this.shown.set(this.vault.reveal(this.itemId(), this.slot()));
      this.timer = setTimeout(() => this.hide(), 30_000);
    } catch (e) {
      this.status.set(e instanceof Error ? e.message : 'Cannot reveal');
    }
  }

  protected async copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(this.vault.reveal(this.itemId(), this.slot()));
      this.status.set('Copied to clipboard.');
    } catch (e) {
      this.status.set(e instanceof Error ? e.message : 'Copy failed');
    }
  }

  private hide(): void {
    this.shown.set(null);
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  ngOnDestroy(): void {
    this.hide();
  }
}
