/**
 * Non-secret display preferences: language and appearance.
 *
 * - Only an explicit choice is persisted, as JSON under one key in its own
 *   namespace (`keymesh.settings.v1`). Vault data, keys and item indexes are
 *   never written to Web Storage.
 * - Storage may be missing, blocked or corrupt: every read and write is
 *   guarded and falls back to defaults (navigator language, system theme).
 * - `public/preferences-boot.js` applies the same rules before the first
 *   paint (no inline script under the CSP); keep the two in sync.
 */
import { DOCUMENT, Injectable, InjectionToken, computed, effect, inject, signal } from '@angular/core';

export const LOCALES = ['zh-TW', 'en'] as const;
export type Locale = (typeof LOCALES)[number];

export const THEMES = ['system', 'light', 'dark'] as const;
export type ThemePreference = (typeof THEMES)[number];
export type ResolvedTheme = 'light' | 'dark';

export const SETTINGS_KEY = 'keymesh.settings.v1';

/** Explicit choices; `undefined` means "not chosen, use the default". */
export interface StoredPreferences {
  locale?: Locale;
  theme?: ThemePreference;
}

const isLocale = (v: unknown): v is Locale => LOCALES.includes(v as Locale);
const isTheme = (v: unknown): v is ThemePreference => THEMES.includes(v as ThemePreference);

/** Tolerant parse: unknown fields are dropped, each field validated alone. */
export function parsePreferences(raw: string | null): StoredPreferences {
  if (!raw) return {};
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return {};
  }
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return {};
  const o = v as Record<string, unknown>;
  const out: StoredPreferences = {};
  if (isLocale(o['locale'])) out.locale = o['locale'];
  if (isTheme(o['theme'])) out.theme = o['theme'];
  return out;
}

/** Any Chinese browser language selects Traditional Chinese, else English. */
export function localeFromLanguages(languages: readonly string[]): Locale {
  for (const l of languages) {
    if (typeof l === 'string' && /^zh\b/i.test(l)) return 'zh-TW';
    if (typeof l === 'string' && /^en\b/i.test(l)) return 'en';
  }
  return 'en';
}

export function resolveTheme(pref: ThemePreference, systemDark: boolean): ResolvedTheme {
  if (pref === 'system') return systemDark ? 'dark' : 'light';
  return pref;
}

/** Preference storage, or null when Web Storage is unavailable or blocked. */
export const PREFERENCE_STORAGE = new InjectionToken<Storage | null>('keymesh.preference-storage', {
  providedIn: 'root',
  factory: () => {
    try {
      const s = globalThis.localStorage;
      s.getItem(SETTINGS_KEY); // throws when blocked
      return s;
    } catch {
      return null;
    }
  },
});

export const NAVIGATOR_LANGUAGES = new InjectionToken<readonly string[]>('keymesh.navigator-languages', {
  providedIn: 'root',
  factory: () => {
    const n = globalThis.navigator;
    return n?.languages?.length ? n.languages : [n?.language ?? 'en'];
  },
});

/** `(prefers-color-scheme: dark)` media query, or null if unsupported. */
export const DARK_SCHEME_QUERY = new InjectionToken<MediaQueryList | null>('keymesh.dark-scheme-query', {
  providedIn: 'root',
  factory: () =>
    typeof globalThis.matchMedia === 'function'
      ? globalThis.matchMedia('(prefers-color-scheme: dark)')
      : null,
});

@Injectable({ providedIn: 'root' })
export class PreferencesService {
  private readonly storage = inject(PREFERENCE_STORAGE);
  private readonly query = inject(DARK_SCHEME_QUERY);
  private readonly doc = inject(DOCUMENT);
  private readonly initial = this.read();

  readonly locale = signal<Locale>(this.initial.locale ?? localeFromLanguages(inject(NAVIGATOR_LANGUAGES)));
  readonly theme = signal<ThemePreference>(this.initial.theme ?? 'system');
  /** Live OS/browser colour scheme. */
  readonly systemDark = signal(this.query?.matches ?? false);
  readonly resolvedTheme = computed(() => resolveTheme(this.theme(), this.systemDark()));
  /** False when choices cannot be saved (storage blocked or full). */
  readonly persistent = signal(this.storage !== null);

  constructor() {
    this.query?.addEventListener('change', (e) => this.systemDark.set(e.matches));
    effect(() => this.apply(this.locale(), this.resolvedTheme()));
  }

  setLocale(locale: Locale): void {
    if (!isLocale(locale)) return;
    this.locale.set(locale);
    this.save({ locale });
  }

  setTheme(theme: ThemePreference): void {
    if (!isTheme(theme)) return;
    this.theme.set(theme);
    this.save({ theme });
  }

  private read(): StoredPreferences {
    try {
      return parsePreferences(this.storage?.getItem(SETTINGS_KEY) ?? null);
    } catch {
      return {};
    }
  }

  private save(patch: StoredPreferences): void {
    if (!this.storage) return;
    try {
      this.storage.setItem(SETTINGS_KEY, JSON.stringify({ ...this.read(), ...patch }));
    } catch {
      this.persistent.set(false); // keep the in-memory choice for this page
    }
  }

  private apply(locale: Locale, theme: ResolvedTheme): void {
    const root = this.doc.documentElement;
    root.lang = locale;
    root.dataset['theme'] = theme;
  }
}
