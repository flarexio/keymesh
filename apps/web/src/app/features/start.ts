import { Component, inject, signal } from '@angular/core';
import { errorKey } from '../core/errors';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { KeyMode, VaultService } from '../core/vault.service';
import { ConfirmService } from '../shared/feedback';
import { Icon } from '../shared/icon';

@Component({
  selector: 'km-start',
  imports: [Icon],
  template: `
    <div class="start-wrap">
      <section class="card start-card" aria-labelledby="start-title">
        @switch (vault.status()) {
          @case ('locked') {
            <span class="state-icon"><km-icon name="lock" /></span>
            <h2 id="start-title">{{ i18n.t('start.locked.title') }}</h2>
            <p class="lead">{{ i18n.t('start.locked.body') }}</p>
            <button type="button" data-testid="unlock" class="btn btn-primary btn-lg" [disabled]="busy()" (click)="act(vault.openStored())">
              <km-icon name="unlock" /><span>{{ i18n.t('start.locked.unlock') }}</span>
            </button>
          }
          @case ('stored') {
            <span class="state-icon"><km-icon name="archive" /></span>
            <h2 id="start-title">{{ i18n.t('start.stored.title') }}</h2>
            <dl class="meta-grid">
              <dt>{{ i18n.t('common.revision') }}</dt>
              <dd class="mono">{{ vault.stored()?.revision }}</dd>
              <dt>{{ i18n.t('start.stored.keyId') }}</dt>
              <dd class="mono">{{ vault.stored()?.kek_id }}</dd>
            </dl>
            @if (vault.storedNeedsLostKey()) {
              <div class="callout callout-danger" role="alert">
                <km-icon name="alert" />
                <p>{{ i18n.t('start.stored.lostKey') }}</p>
              </div>
            } @else if (vault.canOpenStored()) {
              <button type="button" data-testid="open-fixture" class="btn btn-primary btn-lg" [disabled]="busy()" (click)="act(vault.openStored())">
                <km-icon name="unlock" /><span>{{ i18n.t('start.stored.open') }}</span>
              </button>
            }
            <div class="danger-zone">
              <p class="hint">{{ i18n.t('start.stored.discardHint') }}</p>
              <button type="button" data-testid="discard" class="btn btn-danger-ghost" (click)="discard()">
                <km-icon name="trash" /><span>{{ i18n.t('start.stored.discard') }}</span>
              </button>
            </div>
          }
          @default {
            <span class="state-icon"><km-icon name="logo" /></span>
            <h2 id="start-title">{{ i18n.t('start.new.title') }}</h2>
            <p class="lead">{{ i18n.t('start.new.lead') }}</p>
            <fieldset class="choice-group">
              <legend>{{ i18n.t('start.new.provider') }}</legend>
              @for (o of options; track o.mode) {
                <label class="choice" [class.selected]="mode() === o.mode">
                  <input type="radio" name="mode" [value]="o.mode" [checked]="mode() === o.mode" (change)="mode.set(o.mode)" />
                  <span class="choice-body">
                    <span class="choice-title">{{ i18n.t(o.title) }}</span>
                    <span class="choice-text">{{ i18n.t(o.body) }}</span>
                  </span>
                </label>
              }
            </fieldset>
            <button type="button" data-testid="start-vault" class="btn btn-primary btn-lg" [disabled]="busy()" (click)="act(vault.startNew(mode()))">
              <km-icon name="plus" /><span>{{ i18n.t('start.new.start') }}</span>
            </button>
            <div class="divider"><span>{{ i18n.t('common.or') }}</span></div>
            <h3 class="section-label">{{ i18n.t('start.restore.title') }}</h3>
            <p class="hint">{{ i18n.t('start.restore.hint') }}</p>
            <label class="file-drop">
              <km-icon name="upload" />
              <span>{{ i18n.t('backup.chooseFile') }}</span>
              <input type="file" class="visually-hidden-input" data-testid="initial-restore-input" (change)="restore($event)" />
            </label>
          }
        }
        @if (error(); as e) {
          <div class="callout callout-danger" role="alert" data-testid="start-error">
            <km-icon name="alert" />
            <p>{{ i18n.t(e) }}</p>
          </div>
        }
      </section>
      <aside class="card start-aside" aria-labelledby="limits-title">
        <h3 id="limits-title" class="section-label">{{ i18n.t('start.limits.title') }}</h3>
        <ul class="check-list">
          <li><km-icon name="check" /><span>{{ i18n.t('start.limits.wasm') }}</span></li>
          <li><km-icon name="check" /><span>{{ i18n.t('start.limits.storage') }}</span></li>
          <li class="no"><km-icon name="x" /><span>{{ i18n.t('start.limits.noAuth') }}</span></li>
          <li class="no"><km-icon name="x" /><span>{{ i18n.t('start.limits.noRecovery') }}</span></li>
          <li class="no"><km-icon name="x" /><span>{{ i18n.t('start.limits.noReal') }}</span></li>
        </ul>
      </aside>
    </div>
  `,
})
export class Start {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  private readonly confirm = inject(ConfirmService);
  protected readonly mode = signal<KeyMode>('ephemeral');
  protected readonly error = signal<MessageKey | null>(null);
  protected readonly busy = signal(false);
  protected readonly options: { mode: KeyMode; title: MessageKey; body: MessageKey }[] = [
    { mode: 'ephemeral', title: 'start.new.ephemeral', body: 'start.new.ephemeralBody' },
    { mode: 'synthetic-fixture', title: 'start.new.fixture', body: 'start.new.fixtureBody' },
  ];

  protected async act(p: Promise<void>): Promise<void> {
    this.error.set(null);
    this.busy.set(true);
    try {
      await p;
    } catch (e) {
      this.error.set(errorKey(e));
    } finally {
      this.busy.set(false);
    }
  }

  protected restore(ev: Event): Promise<void> | void {
    const el = ev.target as HTMLInputElement;
    const file = el.files?.[0];
    el.value = '';
    if (file) return this.act(this.vault.restore(file));
  }

  protected async discard(): Promise<void> {
    const ok = await this.confirm.ask({
      title: 'start.discard.title',
      body: 'start.discard.body',
      confirm: 'start.discard.confirm',
      danger: true,
    });
    if (ok) await this.act(this.vault.discard());
  }
}
