import { Component, computed, input } from '@angular/core';
import type { ItemKind } from '../core/types';

/**
 * Local stroke icon set (24×24, `currentColor`). Decorative only: callers
 * always provide a text label or `aria-label` on the control itself.
 */
const circle = (cx: number, cy: number, r: number) =>
  `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
const rect = (x: number, y: number, w: number, h: number, r: number) =>
  `M${x + r} ${y}h${w - 2 * r}a${r} ${r} 0 0 1 ${r} ${r}v${h - 2 * r}a${r} ${r} 0 0 1 ${-r} ${r}` +
  `h${-(w - 2 * r)}a${r} ${r} 0 0 1 ${-r} ${-r}v${-(h - 2 * r)}a${r} ${r} 0 0 1 ${r} ${-r}z`;
const shield = 'M12 3l8 3v6c0 4.9-3.4 8-8 9-4.6-1-8-4.1-8-9V6z';

export const ICONS = {
  logo: ['M12 2.5l8.5 4.9v9.2L12 21.5l-8.5-4.9V7.4z', circle(12, 10.5, 2.3), 'M12 12.8v3.7'],
  lock: [rect(5, 11, 14, 10, 2), 'M8 11V7.5a4 4 0 0 1 8 0V11'],
  unlock: [rect(5, 11, 14, 10, 2), 'M8 11V7.5a4 4 0 0 1 7.6-1.8'],
  key: [circle(8, 15, 4), 'M10.9 12.1L19 4', 'M15.5 7.5l2 2', 'M13.5 9.5l1.5 1.5'],
  search: [circle(11, 11, 7), 'M20.5 20.5l-4.6-4.6'],
  plus: ['M12 5v14', 'M5 12h14'],
  login: ['M14 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4', 'M9.5 16.5L14 12 9.5 7.5', 'M14 12H3'],
  user: [circle(12, 8, 4), 'M4.5 20.5a7.5 7.5 0 0 1 15 0'],
  wallet: [rect(3, 6, 18, 14, 2.5), 'M3 10h18', 'M15.5 15h2'],
  clock: [circle(12, 12, 9), 'M12 7v5l3.2 2'],
  note: ['M6 3h8.5L19 7.5V21H6z', 'M14 3v5h5', 'M9 13h6', 'M9 17h6'],
  signature: [shield, circle(12, 10.5, 2), 'M12 12.5V16'],
  layers: ['M12 3l9 5-9 5-9-5z', 'M3 13l9 5 9-5'],
  dice: [rect(4, 4, 16, 16, 3), circle(9, 9, 0.6), circle(15, 15, 0.6), circle(15, 9, 0.6), circle(9, 15, 0.6)],
  archive: [rect(3, 4, 18, 5, 1.2), 'M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9', 'M10 13h4'],
  terminal: [rect(3, 4, 18, 16, 2.5), 'M7 9.5l3 2.5-3 2.5', 'M12.5 15H17'],
  globe: [circle(12, 12, 9), 'M3 12h18', 'M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z'],
  sun: [circle(12, 12, 4), 'M12 2.5v2', 'M12 19.5v2', 'M4.9 4.9l1.4 1.4', 'M17.7 17.7l1.4 1.4', 'M2.5 12h2', 'M19.5 12h2', 'M4.9 19.1l1.4-1.4', 'M17.7 6.3l1.4-1.4'],
  moon: ['M20 14.5A8.5 8.5 0 1 1 9.5 4a6.8 6.8 0 0 0 10.5 10.5z'],
  monitor: [rect(3, 4, 18, 12, 2), 'M8.5 20h7', 'M12 16v4'],
  copy: [rect(9, 9, 11, 11, 2), 'M5 15V6a2 2 0 0 1 2-2h8'],
  eye: ['M2.5 12S6 5 12 5s9.5 7 9.5 7-3.5 7-9.5 7-9.5-7-9.5-7z', circle(12, 12, 3)],
  eyeOff: ['M3 3l18 18', 'M10.6 5.1C11 5 11.5 5 12 5c6 0 9.5 7 9.5 7a16.5 16.5 0 0 1-3 4', 'M6.6 6.6C4 8.4 2.5 12 2.5 12S6 19 12 19c1.9 0 3.6-.6 5-1.5', 'M9.9 9.9a3 3 0 0 0 4.2 4.2'],
  edit: ['M4 20h4L19 9l-4-4L4 16z', 'M13.5 6.5l4 4'],
  trash: ['M4 7h16', 'M10 11v6', 'M14 11v6', 'M6 7l1 13h10l1-13', 'M9 7V4h6v3'],
  download: ['M12 3v12', 'M7 10l5 5 5-5', 'M5 21h14'],
  upload: ['M12 16V4', 'M7 9l5-5 5 5', 'M5 21h14'],
  refresh: ['M20 12a8 8 0 1 1-2.3-5.7', 'M20 4v5h-5'],
  alert: ['M12 3.5l9.5 17h-19z', 'M12 10v4.5', 'M12 17.5v.01'],
  shieldAlert: [shield, 'M12 8v4.5', 'M12 15.8v.01'],
  shield: [shield, 'M8.5 12l2.5 2.5 4.5-5'],
  check: ['M5 12.5l4.5 4.5L19 7.5'],
  x: ['M6 6l12 12', 'M18 6L6 18'],
  chevronLeft: ['M15 18l-6-6 6-6'],
  chevronDown: ['M6 9l6 6 6-6'],
  info: [circle(12, 12, 9), 'M12 11v6', 'M12 7.5v.01'],
  inbox: ['M3 13l3-8h12l3 8v6H3z', 'M3 13h5l1.5 2.5h5L16 13h5'],
} satisfies Record<string, string[]>;

export type IconName = keyof typeof ICONS;

export const KIND_ICONS: Record<ItemKind, IconName> = {
  login: 'login',
  secret: 'key',
  contact: 'user',
  crypto_wallet: 'wallet',
  ed25519_key: 'signature',
  totp: 'clock',
  secure_note: 'note',
};

@Component({
  selector: 'km-icon',
  template: `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
    @for (d of paths(); track $index) {
      <path [attr.d]="d" />
    }
  </svg>`,
  host: { class: 'icon' },
})
export class Icon {
  readonly name = input.required<IconName>();
  protected readonly paths = computed(() => ICONS[this.name()]);
}
