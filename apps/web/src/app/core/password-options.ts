import { Injectable, effect, inject, signal } from '@angular/core';
import { MessageKey } from './i18n/i18n.service';
import { PREFERENCE_STORAGE } from './preferences';
import { VaultService } from './vault.service';

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
const PRESETS: readonly PasswordPreset[] = ['default', 'strong', 'custom'];
const FLAGS = ['lowercase', 'uppercase', 'digits', 'symbols', 'excludeAmbiguous', 'requireEachClass'] as const;
const OPTION_KEYS = ['length', 'symbolSet', ...FLAGS] as const;

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

export function sameOptions(a: PasswordOptions, b: PasswordOptions): boolean {
  return OPTION_KEYS.every((k) => Object.is(a[k], b[k]));
}

/** ASCII punctuation only, like the core; at most SYMBOL_SET_MAX characters. */
function validSymbolSet(v: string): boolean {
  return [...v].length <= SYMBOL_SET_MAX && /^[!-/:-@[-`{-~]*$/.test(v);
}

/** Exact shape and basic ranges; the core decides whether a policy is usable. */
function wellFormed(o: PasswordOptions): boolean {
  return clientProblem(o) === null && validSymbolSet(o.symbolSet);
}

/** Separate from display preferences; never holds generated values. */
export const PASSWORD_SETTINGS_KEY = 'keymesh.password-settings.v1';

export interface StoredPasswordSettings {
  preset: PasswordPreset;
  options: PasswordOptions;
}

/**
 * Strict parse: exactly the known fields with well-formed values, else null
 * (the caller then uses the defaults). A preset whose settings no longer
 * match it is read as Custom. Policy validity is decided by the core, not
 * here (see `PasswordSettings`).
 */
export function parsePasswordSettings(raw: string | null): StoredPasswordSettings | null {
  if (!raw) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return null;
  }
  const isObject = (x: unknown): x is Record<string, unknown> =>
    typeof x === 'object' && x !== null && !Array.isArray(x);
  if (!isObject(v) || !PRESETS.includes(v['preset'] as PasswordPreset)) return null;
  const o = v['options'];
  if (!isObject(o) || Object.keys(o).length !== OPTION_KEYS.length) return null;
  if (typeof o['length'] !== 'number' || typeof o['symbolSet'] !== 'string') return null;
  if (!FLAGS.every((f) => typeof o[f] === 'boolean')) return null;
  const options = Object.fromEntries(OPTION_KEYS.map((k) => [k, o[k]])) as unknown as PasswordOptions;
  if (!wellFormed(options)) return null;
  let preset = v['preset'] as PasswordPreset;
  if (preset !== 'custom' && !sameOptions(options, PASSWORD_PRESETS[preset])) preset = 'custom';
  return { preset, options };
}

/**
 * Settings shared by the generator page and the item forms. They are not
 * secret: the last settings the core accepts are kept in Web Storage (when
 * available) under their own key. Generated values are never stored.
 *
 * Validity is the core's policy check (`passwordPolicySummary`, no RNG), the
 * same one generation uses, so there is no second policy in TypeScript.
 * Until the core is loaded nothing is restored or saved; stored settings are
 * then applied once, unless the user already changed something.
 */
@Injectable({ providedIn: 'root' })
export class PasswordSettings {
  private readonly storage = inject(PREFERENCE_STORAGE);
  private readonly vault = inject(VaultService);
  readonly options = signal<PasswordOptions>({ ...PASSWORD_PRESETS.default });
  readonly preset = signal<PasswordPreset>('default');
  /** False when settings cannot be saved (storage blocked or full). */
  readonly persistent = signal(this.storage !== null);
  private restored = false;
  private touched = false;

  constructor() {
    this.restore();
    if (!this.restored) {
      effect(() => {
        if (this.vault.coreReady()) this.restore();
      });
    }
  }

  setPreset(p: PasswordPreset): void {
    this.touched = true;
    this.preset.set(p);
    if (p !== 'custom') this.options.set({ ...PASSWORD_PRESETS[p] });
    this.save();
  }

  /** Any change by the user means Custom; preset rules are not re-applied. */
  update(patch: Partial<PasswordOptions>): void {
    this.touched = true;
    this.options.update((o) => ({ ...o, ...patch }));
    this.preset.set('custom');
    this.save();
  }

  /** Accepted by the core's policy check (false while the core isn't loaded). */
  private usable(o: PasswordOptions): boolean {
    if (!wellFormed(o) || !this.vault.coreReady()) return false;
    try {
      this.vault.checkPasswordOptions(o);
      return true;
    } catch {
      return false;
    }
  }

  private restore(): void {
    if (this.restored || !this.vault.coreReady()) return;
    this.restored = true;
    const stored = this.read();
    if (this.touched || !stored || !this.usable(stored.options)) return;
    this.options.set(stored.options);
    this.preset.set(stored.preset);
  }

  private read(): StoredPasswordSettings | null {
    try {
      return parsePasswordSettings(this.storage?.getItem(PASSWORD_SETTINGS_KEY) ?? null);
    } catch {
      return null;
    }
  }

  /** Only settings the core accepts are saved; otherwise the last good ones stay. */
  private save(): void {
    const options = this.options();
    if (!this.storage || !this.usable(options)) return;
    const value: StoredPasswordSettings = { preset: this.preset(), options };
    try {
      this.storage.setItem(PASSWORD_SETTINGS_KEY, JSON.stringify(value));
    } catch {
      this.persistent.set(false); // keep the in-memory settings for this page
    }
  }
}
