import { Injectable, signal } from '@angular/core';
import { MessageKey } from './i18n/i18n.service';

/**
 * Password settings, mirrored 1:1 by the core's `PasswordOptions` (strict
 * JSON, camelCase). The core validates and generates; nothing here draws
 * random numbers.
 */
export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  /** Allowed symbols (ASCII punctuation; duplicates ignored by the core). */
  symbolSet: string;
  excludeAmbiguous: boolean;
  requireEachClass: boolean;
}

export type PasswordPreset = 'default' | 'strong' | 'custom';

export const DEFAULT_SYMBOLS = '!#$%&()*+,-./:;<=>?@[]^_{|}~';
export const LENGTH_MIN = 8;
export const LENGTH_MAX = 128;
export const SYMBOL_SET_MAX = 64;

const ALL_TYPES = {
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  symbolSet: DEFAULT_SYMBOLS,
  excludeAmbiguous: false,
  requireEachClass: true,
};

/** Equal to the core's built-in Default and Strong profiles. */
export const PASSWORD_PRESETS: Readonly<Record<Exclude<PasswordPreset, 'custom'>, Readonly<PasswordOptions>>> = {
  default: Object.freeze({ length: 24, ...ALL_TYPES }),
  strong: Object.freeze({ length: 32, ...ALL_TYPES }),
};

/** Checks that need no core call; everything else is validated by the core. */
export function clientProblem(o: PasswordOptions): MessageKey | null {
  if (!Number.isInteger(o.length) || o.length < LENGTH_MIN || o.length > LENGTH_MAX) return 'errors.pwLength';
  if (!(o.lowercase || o.uppercase || o.digits || o.symbols)) return 'errors.pwNoClass';
  if (o.symbols && [...o.symbolSet].length > SYMBOL_SET_MAX) return 'errors.pwSymbolsLong';
  return null;
}

/**
 * Settings shared by the generator page and the item forms for this page
 * session. They are not secret but are deliberately not persisted.
 */
@Injectable({ providedIn: 'root' })
export class PasswordSettings {
  readonly options = signal<PasswordOptions>({ ...PASSWORD_PRESETS.default });
  readonly preset = signal<PasswordPreset>('default');

  setPreset(p: PasswordPreset): void {
    this.preset.set(p);
    if (p !== 'custom') this.options.set({ ...PASSWORD_PRESETS[p] });
  }

  /** Any change by the user means Custom; preset rules are not re-applied. */
  update(patch: Partial<PasswordOptions>): void {
    this.options.update((o) => ({ ...o, ...patch }));
    this.preset.set('custom');
  }
}
