/**
 * "New item": on the all-items view it opens the kind menu; inside one
 * category it creates an item of that kind directly, with a matching label.
 */
import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ItemKind, KINDS } from '../core/types';
import { en } from '../core/i18n/en';
import { NewItemMenu } from './new-item-menu';

@Component({
  imports: [NewItemMenu],
  template: `<km-new-item-menu [kind]="kind()" (picked)="picked.push($event)" />`,
})
class Host {
  readonly kind = signal<ItemKind | ''>('');
  readonly picked: ItemKind[] = [];
}

async function render(kind: ItemKind | '') {
  const f = TestBed.createComponent(Host);
  f.componentInstance.kind.set(kind);
  document.body.appendChild(f.nativeElement);
  await f.whenStable();
  const el = f.nativeElement as HTMLElement;
  const button = () => el.querySelector<HTMLButtonElement>('[data-testid=new-item]')!;
  return { f, el, button };
}

afterEach(() => {
  document.body.querySelectorAll('[ng-version]').forEach((n) => n.remove());
  TestBed.resetTestingModule();
});

describe('NewItemMenu', () => {
  it('all items: the button opens the kind menu', async () => {
    const { f, el, button } = await render('');
    expect(button().getAttribute('aria-haspopup')).toBe('menu');
    expect(button().textContent).toContain(en['list.newItem']);
    button().click();
    await f.whenStable();
    expect(el.querySelectorAll('[role=menuitem]').length).toBe(KINDS.length);
    expect(f.componentInstance.picked).toEqual([]);
  });

  it('inside a category: the button creates that kind directly (no menu) and says so', async () => {
    for (const kind of KINDS) {
      const { f, el, button } = await render(kind);
      expect(button().hasAttribute('aria-haspopup'), kind).toBe(false);
      expect(button().hasAttribute('aria-expanded'), kind).toBe(false);
      expect(button().getAttribute('data-kind')).toBe(kind);
      expect(button().textContent?.trim()).toBe(en[`list.new.${kind}`]);
      button().click();
      await f.whenStable();
      expect(el.querySelector('[role=menu]'), kind).toBeNull();
      expect(f.componentInstance.picked).toEqual([kind]);
      document.body.querySelectorAll('[ng-version]').forEach((n) => n.remove());
      TestBed.resetTestingModule();
    }
  });

  it('an open menu closes when a category is chosen', async () => {
    const { f, el, button } = await render('');
    button().click();
    await f.whenStable();
    expect(el.querySelector('[role=menu]')).not.toBeNull();
    f.componentInstance.kind.set('totp');
    await f.whenStable();
    expect(el.querySelector('[role=menu]')).toBeNull();
    expect(button().textContent?.trim()).toBe(en['list.new.totp']);
  });
});
