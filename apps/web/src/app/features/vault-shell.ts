import { Component, inject, signal } from '@angular/core';
import { VaultService } from '../core/vault.service';
import { ItemKind, KINDS, KIND_LABELS } from '../core/types';
import { ItemDetail } from './item-detail';
import { ItemForm } from './item-form';
import { Generators } from './generators';
import { Backup } from './backup';
import { ImportInfo } from './import-info';

type Pane =
  | { mode: 'none' }
  | { mode: 'view'; id: string }
  | { mode: 'create'; kind: ItemKind }
  | { mode: 'edit'; id: string; kind: ItemKind };

type Tab = 'items' | 'generators' | 'backup' | 'import';

@Component({
  selector: 'km-vault-shell',
  imports: [ItemDetail, ItemForm, Generators, Backup, ImportInfo],
  template: `
    @if (vault.status() === 'stale') {
      <div class="stale" role="alert">
        The stored vault was changed elsewhere (for example in another tab). Editing is blocked to avoid
        overwriting newer data.
        <button type="button" (click)="reload()">Reload from storage</button>
      </div>
    }
    <nav class="tabs" aria-label="Sections">
      @for (t of tabs; track t.id) {
        <button type="button" [class.active]="tab() === t.id" [attr.aria-current]="tab() === t.id ? 'page' : null"
          (click)="tab.set(t.id)">{{ t.label }}</button>
      }
    </nav>

    @switch (tab()) {
      @case ('items') {
        <div class="layout">
          <aside class="list-pane" aria-label="Items">
            <label class="search">Search
              <input type="search" data-testid="search" [value]="vault.query()" (input)="search($event)" placeholder="Title, username, URL, tag…" />
            </label>
            <label>Type
              <select data-testid="kind-filter" (change)="filter($event)">
                <option value="">All types</option>
                @for (k of kinds; track k) {
                  <option [value]="k" [selected]="vault.kindFilter() === k">{{ label(k) }}</option>
                }
              </select>
            </label>
            <label>New item
              <select data-testid="new-item" (change)="create($event)">
                <option value="">Choose type…</option>
                @for (k of kinds; track k) {
                  <option [value]="k">{{ label(k) }}</option>
                }
              </select>
            </label>
            <p class="muted small" aria-live="polite">{{ vault.items().length }} item(s)</p>
            <ul class="item-list" role="listbox" aria-label="Vault items">
              @for (i of vault.items(); track i.id) {
                <li role="option" [attr.aria-selected]="selected() === i.id">
                  <button type="button" (click)="open(i.id)" [class.selected]="selected() === i.id">
                    <span class="title">{{ i.title }}</span>
                    <span class="muted small">{{ label(i.kind) }}@if (i.subtitle) { · {{ i.subtitle }} }</span>
                  </button>
                </li>
              } @empty {
                <li class="muted">No items.</li>
              }
            </ul>
          </aside>
          <section class="detail-pane">
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
                <p class="muted">Select an item or create a new one.</p>
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
  `,
})
export class VaultShell {
  protected readonly vault = inject(VaultService);
  protected readonly kinds = KINDS;
  protected readonly tabs: { id: Tab; label: string }[] = [
    { id: 'items', label: 'Items' },
    { id: 'generators', label: 'Generators' },
    { id: 'backup', label: 'Backup' },
    { id: 'import', label: 'Import (CLI)' },
  ];
  protected readonly tab = signal<Tab>('items');
  protected readonly pane = signal<Pane>({ mode: 'none' });

  protected label(k: ItemKind): string {
    return KIND_LABELS[k];
  }

  protected selected(): string | null {
    const p = this.pane();
    return p.mode === 'view' || p.mode === 'edit' ? p.id : null;
  }

  protected paneId(): string | null {
    const p = this.pane();
    return p.mode === 'view' || p.mode === 'edit' ? p.id : null;
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
    this.vault.kindFilter.set((ev.target as HTMLSelectElement).value as ItemKind | '');
    this.vault.refreshList();
  }

  protected create(ev: Event): void {
    const el = ev.target as HTMLSelectElement;
    const kind = el.value as ItemKind;
    el.value = '';
    if (kind) this.pane.set({ mode: 'create', kind });
  }

  protected open(id: string): void {
    this.pane.set({ mode: 'view', id });
  }

  protected openFromTab(id: string): void {
    this.tab.set('items');
    this.open(id);
  }

  protected edit(id: string): void {
    const v = this.vault.get(id);
    this.pane.set({ mode: 'edit', id, kind: v.kind });
  }

  protected async reload(): Promise<void> {
    this.pane.set({ mode: 'none' });
    await this.vault.reload();
  }
}
