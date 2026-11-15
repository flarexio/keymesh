import { Component, computed, effect, inject, input, signal } from '@angular/core';
import { FaviconPref } from '../core/favicon-pref';
import { LoginCategory, hostOf, isPrivateHost, loginIcon } from '../core/login-icon';
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
    @if (remoteHost(); as h) {
      <span class="kind-tile remote-tile" [class.kind-tile-lg]="large()" data-icon="remote" aria-hidden="true">
        <img [src]="'/api/favicon?host=' + h" alt="" width="32" height="32" referrerpolicy="no-referrer" (error)="failed.set(h)" />
      </span>
    } @else {
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
    }
  `,
})
export class ItemIcon {
  readonly kind = input.required<ItemKind>();
  readonly title = input('');
  readonly url = input<string | null>(null);
  readonly large = input(false);
  /** Allow an opted-in website icon (only the item detail view sets this). */
  readonly remote = input(false);
  private readonly catalog = inject(BrandCatalog);
  private readonly favicon = inject(FaviconPref);
  /** Host whose icon failed: fall back to the local icon. */
  protected readonly failed = signal<string | null>(null);

  /** A public login host to ask our server about, or null (local icon). */
  protected readonly remoteHost = computed(() => {
    if (!this.remote() || !this.favicon.enabled() || this.kind() !== 'login') return null;
    if (this.look().kind === 'brand') return null; // a reviewed local icon already
    const h = hostOf(this.url());
    if (!h || isPrivateHost(h) || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(h)) return null;
    return this.failed() === h ? null : h.toLowerCase();
  });

  constructor() {
    effect(() => {
      this.url(); // a new item gets a new try
      this.failed.set(null);
    });
  }

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
