import { Component, ElementRef, computed, inject, signal, viewChild } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { ItemKind, KINDS } from '../core/types';
import { Icon, IconName, KIND_ICONS } from '../shared/icon';
import { ItemDetail } from './item-detail';
import { ItemForm } from './item-form';
import { Generators } from './generators';
import { Backup } from './backup';
import { ImportInfo } from './import-info';
import { NewItemMenu } from './new-item-menu';

type Pane =
  | { mode: 'none' }
  | { mode: 'view'; id: string }
  | { mode: 'create'; kind: ItemKind }
  | { mode: 'edit'; id: string; kind: ItemKind };

type Tab = 'items' | 'generators' | 'backup' | 'import';

const TABS: { id: Tab; label: MessageKey; icon: IconName }[] = [
  { id: 'items', label: 'nav.items', icon: 'layers' },
  { id: 'generators', label: 'nav.generators', icon: 'dice' },
  { id: 'backup', label: 'nav.backup', icon: 'archive' },
  { id: 'import', label: 'nav.import', icon: 'terminal' },
];

@Component({
  selector: 'km-vault-shell',
  imports: [ItemDetail, ItemForm, Generators, Backup, ImportInfo, Icon, NewItemMenu],
  template: `
    <div class="shell">
      <aside class="sidebar" [attr.aria-label]="i18n.t('nav.sidebar')">
        <nav [attr.aria-label]="i18n.t('nav.sections')">
          <ul class="nav-list">
            @for (t of tabs; track t.id) {
              <li>
                <button type="button" class="nav-item" [attr.data-testid]="'nav-' + t.id" [attr.aria-current]="tab() === t.id ? 'page' : null" (click)="tab.set(t.id)">
                  <km-icon [name]="t.icon" /><span>{{ i18n.t(t.label) }}</span>
                </button>
              </li>
            }
          </ul>
        </nav>
        @if (tab() === 'items') {
          <nav class="categories" [attr.aria-label]="i18n.t('nav.categories')">
            <h2 class="nav-heading">{{ i18n.t('nav.categories') }}</h2>
            <ul class="nav-list">
              <li>
                <button type="button" class="nav-item" data-testid="category-all"
                  [attr.aria-current]="vault.kindFilter() === '' ? 'true' : null" (click)="setFilter('')">
                  <km-icon name="layers" /><span>{{ i18n.t('kind.all') }}</span>
                  <span class="count">{{ total() }}</span>
                </button>
              </li>
              @for (k of kinds; track k) {
                <li>
                  <button type="button" class="nav-item" [attr.data-testid]="'category-' + k"
                    [attr.aria-current]="vault.kindFilter() === k ? 'true' : null" (click)="setFilter(k)">
                    <km-icon [name]="kindIcon(k)" /><span>{{ i18n.t(kindKey(k)) }}</span>
                    <span class="count">{{ counts()[k] }}</span>
                  </button>
                </li>
              }
            </ul>
          </nav>
        }
        <div class="vault-status" data-testid="key-mode">
          <span class="status-dot" [class.warn]="vault.status() === 'stale'" aria-hidden="true"></span>
          <span>
            <span class="status-line">{{ i18n.t(vault.status() === 'stale' ? 'shell.statusStale' : 'shell.statusOpen') }}</span>
            <span class="status-meta">{{ i18n.t('shell.keyMeta', { mode: vault.keyMode() ?? '', rev: vault.revision() }) }}</span>
          </span>
        </div>
      </aside>

      <div class="workspace">
        @if (vault.status() === 'stale') {
          <div class="callout callout-warn stale" role="alert">
            <km-icon name="alert" />
            <p>{{ i18n.t('shell.stale') }}</p>
            <button type="button" class="btn btn-sm" (click)="reload()"><km-icon name="refresh" /><span>{{ i18n.t('shell.reload') }}</span></button>
          </div>
        }
        @switch (tab()) {
          @case ('items') {
            <div class="items-layout" [class.has-pane]="pane().mode !== 'none'">
              <section class="list-pane" [attr.aria-label]="i18n.t('list.label')">
                <div class="list-head">
                  <div class="list-title">
                    <h2>{{ listTitle() }}</h2>
                    <span class="muted small" aria-live="polite" data-testid="item-count">{{ i18n.plural('list.countOne', 'list.countOther', vault.items().length) }}</span>
                  </div>
                  <km-new-item-menu (picked)="create($event)" />
                </div>
                <div class="search-field">
                  <km-icon name="search" />
                  <input type="search" data-testid="search" [value]="vault.query()" (input)="search($event)"
                    [attr.aria-label]="i18n.t('list.search')" [placeholder]="i18n.t('list.searchPlaceholder')" />
                </div>
                <label class="mobile-only filter-select">
                  <span class="visually-hidden">{{ i18n.t('list.filter') }}</span>
                  <select data-testid="kind-filter" (change)="filter($event)">
                    <option value="" [selected]="vault.kindFilter() === ''">{{ i18n.t('kind.all') }}</option>
                    @for (k of kinds; track k) {
                      <option [value]="k" [selected]="vault.kindFilter() === k">{{ i18n.t(kindKey(k)) }}</option>
                    }
                  </select>
                </label>
                <ul class="item-list" [attr.aria-label]="i18n.t('list.items')">
                  @for (i of vault.items(); track i.id) {
                    <li>
                      <button type="button" (click)="open(i.id)" [class.selected]="selected() === i.id"
                        [attr.aria-current]="selected() === i.id ? 'true' : null">
                        <span class="kind-tile" [attr.data-kind]="i.kind"><km-icon [name]="kindIcon(i.kind)" /></span>
                        <span class="item-text">
                          <span class="title">{{ i.title }}</span>
                          <span class="subtitle">{{ i18n.t(kindKey(i.kind)) }}@if (i.subtitle) { · {{ i.subtitle }} }</span>
                        </span>
                      </button>
                    </li>
                  } @empty {
                    <li class="list-empty">
                      @if (vault.query() || vault.kindFilter()) {
                        <p>{{ i18n.t('list.noMatches') }}</p>
                        <button type="button" class="btn btn-sm" (click)="clearFilters()">{{ i18n.t('list.clearFilters') }}</button>
                      } @else {
                        <p>{{ i18n.t('list.empty') }}</p>
                      }
                    </li>
                  }
                </ul>
              </section>
              <section class="detail-pane" #detail tabindex="-1" [attr.aria-label]="i18n.t('detail.region')">
                @if (pane().mode !== 'none') {
                  <button type="button" class="btn btn-ghost btn-sm mobile-only back-btn" data-testid="back" (click)="back()">
                    <km-icon name="chevronLeft" /><span>{{ i18n.t('common.backToList') }}</span>
                  </button>
                }
                @switch (pane().mode) {
                  @case ('view') {
                    @if (paneId(); as id) {
                      <km-item-detail [itemId]="id" (edit)="edit($event)" (deleted)="pane.set({ mode: 'none' })" />
                    }
                  }
                  @case ('create') {
                    @if (paneKind(); as k) {
                      <km-item-form [kind]="k" (saved)="open($event)" (cancelled)="pane.set({ mode: 'none' })" />
                    }
                  }
                  @case ('edit') {
                    @if (paneKind(); as k) {
                      <km-item-form [kind]="k" [editId]="paneId()" (saved)="open($event)" (cancelled)="open(paneId()!)" />
                    }
                  }
                  @default {
                    @if (total() === 0) {
                      <div class="empty-state">
                        <span class="state-icon"><km-icon name="inbox" /></span>
                        <h2>{{ i18n.t('detail.emptyVaultTitle') }}</h2>
                        <p>{{ i18n.t('detail.emptyVaultBody') }}</p>
                        <div class="kind-grid">
                          @for (k of kinds; track k) {
                            <button type="button" class="kind-card" (click)="pane.set({ mode: 'create', kind: k })">
                              <span class="kind-tile" [attr.data-kind]="k"><km-icon [name]="kindIcon(k)" /></span>
                              <span>{{ i18n.t(kindKey(k)) }}</span>
                            </button>
                          }
                        </div>
                      </div>
                    } @else {
                      <div class="empty-state">
                        <span class="state-icon"><km-icon name="layers" /></span>
                        <p>{{ i18n.t('detail.selectHint') }}</p>
                      </div>
                    }
                  }
                }
              </section>
            </div>
          }
          @case ('generators') {
            <km-generators (created)="openFromTab($event)" />
          }
          @case ('backup') {
            <km-backup />
          }
          @case ('import') {
            <km-import-info />
          }
        }
      </div>

      <nav class="bottom-nav" [attr.aria-label]="i18n.t('nav.sections')">
        @for (t of tabs; track t.id) {
          <button type="button" [attr.data-testid]="'bnav-' + t.id" [attr.aria-current]="tab() === t.id ? 'page' : null" (click)="tab.set(t.id)">
            <km-icon [name]="t.icon" /><span>{{ i18n.t(t.label) }}</span>
          </button>
        }
      </nav>
    </div>
  `,
})
export class VaultShell {
  protected readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  protected readonly kinds = KINDS;
  protected readonly tabs = TABS;
  protected readonly tab = signal<Tab>('items');
  protected readonly pane = signal<Pane>({ mode: 'none' });
  private readonly detail = viewChild<ElementRef<HTMLElement>>('detail');

  /** Item counts per kind, independent of search. */
  protected readonly counts = computed<Record<ItemKind, number>>(() => {
    this.vault.version();
    const out = {} as Record<ItemKind, number>;
    for (const k of KINDS) {
      try {
        out[k] = this.vault.summaries(k).length; // also while stale (read-only)
      } catch {
        out[k] = 0;
      }
    }
    return out;
  });
  protected readonly total = computed(() => Object.values(this.counts()).reduce((a, b) => a + b, 0));
  protected readonly listTitle = computed(() => {
    const k = this.vault.kindFilter();
    return this.i18n.t(k ? this.kindKey(k) : 'kind.all');
  });

  protected kindKey(k: ItemKind): MessageKey {
    return `kind.${k}`;
  }

  protected kindIcon(k: ItemKind): IconName {
    return KIND_ICONS[k];
  }

  protected selected(): string | null {
    const p = this.pane();
    return p.mode === 'view' || p.mode === 'edit' ? p.id : null;
  }

  protected paneId(): string | null {
    return this.selected();
  }

  protected paneKind(): ItemKind | null {
    const p = this.pane();
    return p.mode === 'create' || p.mode === 'edit' ? p.kind : null;
  }

  protected search(ev: Event): void {
    this.vault.query.set((ev.target as HTMLInputElement).value);
    this.vault.refreshList();
  }

  protected filter(ev: Event): void {
    this.setFilter((ev.target as HTMLSelectElement).value as ItemKind | '');
  }

  protected setFilter(k: ItemKind | ''): void {
    this.vault.kindFilter.set(k);
    this.vault.refreshList();
  }

  protected clearFilters(): void {
    this.vault.query.set('');
    this.setFilter('');
  }

  protected create(kind: ItemKind): void {
    this.tab.set('items');
    this.pane.set({ mode: 'create', kind });
    this.focusDetail();
  }

  protected open(id: string): void {
    this.pane.set({ mode: 'view', id });
    this.focusDetail();
  }

  protected openFromTab(id: string): void {
    this.tab.set('items');
    this.open(id);
  }

  protected edit(id: string): void {
    const v = this.vault.get(id);
    this.pane.set({ mode: 'edit', id, kind: v.kind });
  }

  protected back(): void {
    this.pane.set({ mode: 'none' });
  }

  /** On narrow screens the detail replaces the list; move focus with it. */
  private focusDetail(): void {
    if (!matchMedia('(max-width: 860px)').matches) return;
    setTimeout(() => this.detail()?.nativeElement.focus(), 0);
  }

  protected async reload(): Promise<void> {
    this.pane.set({ mode: 'none' });
    await this.vault.reload();
  }
}
