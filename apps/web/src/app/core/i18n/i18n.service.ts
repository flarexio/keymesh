/**
 * Runtime translation for the two supported locales.
 *
 * `en` is the source catalog and defines `MessageKey`; `zh-TW` is typed as
 * `Record<MessageKey, string>`, so a missing or extra key fails the build.
 * `t()` reads the locale signal, so any template or computed that calls it
 * re-renders on a language switch without touching component state.
 */
import { DOCUMENT, Injectable, effect, inject } from '@angular/core';
import { Locale, PreferencesService } from '../preferences';
import { MessageKey, en } from './en';
import { zhTW } from './zh-tw';

export type { MessageKey } from './en';
export type Params = Record<string, string | number>;

/** A message to render later, so it follows language switches. */
export interface Message {
  key: MessageKey;
  params?: Params;
}

export const CATALOGS: Record<Locale, Record<MessageKey, string>> = { en, 'zh-TW': zhTW };

/** Shown only if a key is somehow absent at runtime; tests assert it never is. */
export const MISSING = (key: string) => `⟦${key}⟧`;

export function format(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (m, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : m,
  );
}

@Injectable({ providedIn: 'root' })
export class I18n {
  private readonly prefs = inject(PreferencesService);
  private readonly doc = inject(DOCUMENT);
  readonly locale = this.prefs.locale;

  constructor() {
    effect(() => (this.doc.title = this.t('app.documentTitle')));
  }

  /** Translate `key` in the current locale; `{name}` placeholders from params. */
  readonly t = (key: MessageKey, params?: Params): string => {
    const value = CATALOGS[this.locale()][key] ?? MISSING(key);
    return format(value, this.localizeNumbers(params));
  };

  readonly msg = (m: Message): string => this.t(m.key, m.params);

  /** Pick the singular or plural key with the locale's plural rules. */
  readonly plural = (one: MessageKey, other: MessageKey, count: number): string => {
    const rule = new Intl.PluralRules(this.locale()).select(count);
    return this.t(rule === 'one' ? one : other, { count });
  };

  readonly dateTime = (epochMillis: number): string =>
    new Intl.DateTimeFormat(this.locale(), { dateStyle: 'medium', timeStyle: 'short' }).format(
      new Date(epochMillis),
    );

  private localizeNumbers(params?: Params): Params | undefined {
    if (!params) return params;
    const nf = new Intl.NumberFormat(this.locale(), { useGrouping: true });
    const out: Params = {};
    for (const [k, v] of Object.entries(params)) out[k] = typeof v === 'number' ? nf.format(v) : v;
    return out;
  }
}
