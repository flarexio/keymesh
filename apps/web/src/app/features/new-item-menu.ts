import { Component, ElementRef, OnDestroy, inject, output, signal, viewChildren } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { ItemKind, KINDS } from '../core/types';
import { Icon, KIND_ICONS } from '../shared/icon';

/** Fixed-position placement relative to the viewport. */
interface MenuPos {
  top: number | null;
  bottom: number | null;
  right: number;
  maxHeight: number;
}

const GAP = 6;
const MARGIN = 8;
/** Below this much room under the button, open upwards if there is more above. */
const MIN_BELOW = 240;

/**
 * "New item" menu button: arrow keys, Home/End, Escape, click-outside.
 *
 * The menu is `position: fixed` and placed from the button's viewport rect,
 * so scrolling/clipping panes (overflow: hidden/auto) can never cut it off.
 * It opens downwards or upwards, whichever fits, is capped to the viewport
 * and scrolls internally; it closes on resize or when anything else scrolls.
 */
@Component({
  selector: 'km-new-item-menu',
  imports: [Icon],
  template: `
    <button type="button" class="btn btn-primary" data-testid="new-item" aria-haspopup="menu"
      [attr.aria-expanded]="open()" aria-controls="new-item-menu" (click)="toggle()" (keydown)="onButtonKey($event)">
      <km-icon name="plus" /><span>{{ i18n.t('list.newItem') }}</span>
    </button>
    @if (open()) {
      <div #menu class="menu" id="new-item-menu" role="menu" [attr.aria-label]="i18n.t('list.newItem')" (keydown)="onMenuKey($event)"
        [style.top.px]="pos().top" [style.bottom.px]="pos().bottom" [style.right.px]="pos().right" [style.max-height.px]="pos().maxHeight">
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
    '(window:resize)': 'close()',
  },
})
export class NewItemMenu implements OnDestroy {
  protected readonly i18n = inject(I18n);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  readonly picked = output<ItemKind>();
  protected readonly kinds = KINDS;
  protected readonly icons = KIND_ICONS;
  protected readonly open = signal(false);
  protected readonly pos = signal<MenuPos>({ top: null, bottom: null, right: MARGIN, maxHeight: 0 });
  private readonly items = viewChildren<ElementRef<HTMLButtonElement>>('item');
  private readonly onScroll = (ev: Event) => {
    const menu = this.host.nativeElement.querySelector('[role=menu]');
    if (!menu || !menu.contains(ev.target as Node)) this.close();
  };

  protected toggle(): void {
    this.open() ? this.close() : this.show(0);
  }

  private show(index: number): void {
    this.place();
    this.open.set(true);
    document.addEventListener('scroll', this.onScroll, true);
    setTimeout(() => this.focus(index), 0);
  }

  private place(): void {
    const btn = this.host.nativeElement.querySelector('[data-testid=new-item]')!.getBoundingClientRect();
    const vh = window.innerHeight;
    const right = Math.max(MARGIN, document.documentElement.clientWidth - btn.right);
    const below = vh - btn.bottom - GAP - MARGIN;
    const above = btn.top - GAP - MARGIN;
    this.pos.set(
      below >= MIN_BELOW || below >= above
        ? { top: btn.bottom + GAP, bottom: null, right, maxHeight: below }
        : { top: null, bottom: vh - btn.top + GAP, right, maxHeight: above },
    );
  }

  protected close(refocus = false): void {
    document.removeEventListener('scroll', this.onScroll, true);
    if (!this.open()) return;
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

  ngOnDestroy(): void {
    document.removeEventListener('scroll', this.onScroll, true);
  }
}
