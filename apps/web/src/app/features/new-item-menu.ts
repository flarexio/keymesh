import { Component, ElementRef, inject, output, signal, viewChildren } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { ItemKind, KINDS } from '../core/types';
import { Icon, KIND_ICONS } from '../shared/icon';

/** "New item" menu button: arrow keys, Home/End, Escape, click-outside. */
@Component({
  selector: 'km-new-item-menu',
  imports: [Icon],
  template: `
    <button type="button" class="btn btn-primary" data-testid="new-item" aria-haspopup="menu"
      [attr.aria-expanded]="open()" aria-controls="new-item-menu" (click)="toggle()" (keydown)="onButtonKey($event)">
      <km-icon name="plus" /><span>{{ i18n.t('list.newItem') }}</span>
    </button>
    @if (open()) {
      <div class="menu" id="new-item-menu" role="menu" [attr.aria-label]="i18n.t('list.newItem')" (keydown)="onMenuKey($event)">
        @for (k of kinds; track k) {
          <button #item type="button" role="menuitem" class="menu-item" [attr.data-kind]="k" (click)="pick(k)">
            <span class="kind-tile" [attr.data-kind]="k"><km-icon [name]="icons[k]" /></span>
            <span>{{ i18n.t(kindKey(k)) }}</span>
          </button>
        }
      </div>
    }
  `,
  host: {
    class: 'menu-anchor',
    '(document:click)': 'outside($event)',
  },
})
export class NewItemMenu {
  protected readonly i18n = inject(I18n);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  readonly picked = output<ItemKind>();
  protected readonly kinds = KINDS;
  protected readonly icons = KIND_ICONS;
  protected readonly open = signal(false);
  private readonly items = viewChildren<ElementRef<HTMLButtonElement>>('item');

  protected toggle(): void {
    this.open() ? this.close() : this.show(0);
  }

  private show(index: number): void {
    this.open.set(true);
    setTimeout(() => this.focus(index), 0);
  }

  private close(refocus = false): void {
    this.open.set(false);
    if (refocus) this.host.nativeElement.querySelector<HTMLButtonElement>('[data-testid=new-item]')?.focus();
  }

  private focus(index: number): void {
    const list = this.items();
    if (list.length) list[(index + list.length) % list.length].nativeElement.focus();
  }

  protected kindKey(k: ItemKind): MessageKey {
    return `kind.${k}`;
  }

  protected pick(k: ItemKind): void {
    this.close();
    this.picked.emit(k);
  }

  protected onButtonKey(ev: KeyboardEvent): void {
    if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
      ev.preventDefault();
      this.show(ev.key === 'ArrowDown' ? 0 : -1);
    }
  }

  protected onMenuKey(ev: KeyboardEvent): void {
    const list = this.items().map((r) => r.nativeElement);
    const i = list.indexOf(document.activeElement as HTMLButtonElement);
    const moves: Record<string, number> = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: -1 };
    if (ev.key in moves) {
      ev.preventDefault();
      this.focus(moves[ev.key]);
    } else if (ev.key === 'Escape' || ev.key === 'Tab') {
      if (ev.key === 'Escape') ev.preventDefault();
      this.close(ev.key === 'Escape');
    }
  }

  protected outside(ev: MouseEvent): void {
    if (this.open() && !this.host.nativeElement.contains(ev.target as Node)) this.close();
  }
}
