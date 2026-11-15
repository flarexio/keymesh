import { Component, computed, inject, input } from '@angular/core';
import { LoginCategory, loginIcon } from '../core/login-icon';
import type { ItemKind } from '../core/types';
import { BrandCatalog } from './brand-catalog';
import { Icon, IconName, KIND_ICONS } from './icon';

const CATEGORY_ICONS: Record<LoginCategory, IconName> = {
  bank: 'bank',
  mail: 'mail',
  shop: 'cart',
  crypto: 'wallet',
  dev: 'terminal',
  chat: 'chat',
  gov: 'bank',
};

/** Black or white, whichever reads better on the brand colour (WCAG relative luminance). */
export function onBrand(hex: string): '#ffffff' | '#000000' {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  const lum = 0.2126 * r + 0.7152 * g + 0.0722 * b;
  return (lum + 0.05) / 0.05 > 1.05 / (lum + 0.05) ? '#000000' : '#ffffff';
}

/**
 * Item icon: Login items get an automatic local icon (brand, private host,
 * category or letter, see core/login-icon.ts); other kinds keep their kind
 * tile. Decorative: the title is always shown as text next to it.
 */
@Component({
  selector: 'km-item-icon',
  imports: [Icon],
  template: `
    @switch (look().kind) {
      @case ('brand') {
        <span class="kind-tile brand-tile" [class.kind-tile-lg]="large()" data-icon="brand" [attr.data-brand]="look().id"
          [style.background]="look().bg" [style.color]="look().fg" aria-hidden="true">
          <svg viewBox="0 0 24 24" class="icon" focusable="false"><path [attr.d]="look().path" fill="currentColor" /></svg>
        </span>
      }
      @case ('letter') {
        <span class="kind-tile letter-tile" [class.kind-tile-lg]="large()" data-icon="letter" [attr.data-tone]="look().tone"
          aria-hidden="true">{{ look().letter }}</span>
      }
      @default {
        <span class="kind-tile" [class.kind-tile-lg]="large()" [attr.data-kind]="kind()" [attr.data-icon]="look().kind"
          aria-hidden="true"><km-icon [name]="iconName()" /></span>
      }
    }
  `,
})
export class ItemIcon {
  readonly kind = input.required<ItemKind>();
  readonly title = input('');
  readonly url = input<string | null>(null);
  readonly large = input(false);
  private readonly catalog = inject(BrandCatalog);

  /** Typed: an unknown name is a compile error, not an empty tile. */
  protected readonly iconName = computed<IconName>(() => {
    const l = this.look();
    switch (l?.kind) {
      case 'kind':
      case 'private':
      case 'category':
        return l.icon;
      default:
        return 'login';
    }
  });

  protected readonly look = computed(() => {
    if (this.kind() !== 'login') return { kind: 'kind', icon: KIND_ICONS[this.kind()] } as const;
    const l = loginIcon(this.url(), this.title(), this.catalog.brands());
    switch (l.kind) {
      case 'brand':
        return { kind: 'brand', id: l.brand.id, path: l.brand.path, bg: l.brand.hex, fg: onBrand(l.brand.hex) } as const;
      case 'private':
        return { kind: 'private', icon: 'server' } as const;
      case 'category':
        return { kind: 'category', icon: CATEGORY_ICONS[l.category] } as const;
      case 'letter':
        return { kind: 'letter', letter: l.letter, tone: l.tone } as const;
    }
  });
}
