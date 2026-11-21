/**
 * Language/appearance preferences: defaults, persistence, corrupt or
 * unavailable storage, theme resolution and live system changes. Storage,
 * navigator languages and the colour-scheme media query are injected fakes.
 */
import { TestBed } from '@angular/core/testing';
import { DOCUMENT } from '@angular/core';
import {
  DARK_SCHEME_QUERY,
  NAVIGATOR_LANGUAGES,
  PREFERENCE_STORAGE,
  PreferencesService,
  SETTINGS_KEY,
  localeFromLanguages,
  parsePreferences,
  resolveTheme,
} from './preferences';

class MemoryStorage implements Storage {
  data = new Map<string, string>();
  failWrites = false;
  failReads = false;
  get length() {
    return this.data.size;
  }
  clear() {
    this.data.clear();
  }
  getItem(k: string) {
    if (this.failReads) throw new DOMException('blocked', 'SecurityError');
    return this.data.get(k) ?? null;
  }
  key(i: number) {
    return [...this.data.keys()][i] ?? null;
  }
  removeItem(k: string) {
    this.data.delete(k);
  }
  setItem(k: string, v: string) {
    if (this.failWrites) throw new DOMException('full', 'QuotaExceededError');
    this.data.set(k, String(v));
  }
}

/** Controllable `(prefers-color-scheme: dark)` query. */
class FakeQuery extends EventTarget {
  media = '(prefers-color-scheme: dark)';
  onchange = null;
  constructor(public matches: boolean) {
    super();
  }
  addListener() {}
  removeListener() {}
  set(dark: boolean) {
    this.matches = dark;
    this.dispatchEvent(Object.assign(new Event('change'), { matches: dark }));
  }
}

function setup(opts: { storage?: Storage | null; languages?: string[]; dark?: boolean } = {}) {
  const query = new FakeQuery(opts.dark ?? false);
  TestBed.resetTestingModule();
  TestBed.configureTestingModule({
    providers: [
      { provide: PREFERENCE_STORAGE, useValue: opts.storage === undefined ? new MemoryStorage() : opts.storage },
      { provide: NAVIGATOR_LANGUAGES, useValue: opts.languages ?? ['en-US'] },
      { provide: DARK_SCHEME_QUERY, useValue: query },
    ],
  });
  const prefs = TestBed.inject(PreferencesService);
  TestBed.tick();
  return { prefs, query, root: TestBed.inject(DOCUMENT).documentElement };
}

describe('preference parsing and resolution', () => {
  it('parses tolerantly and validates each field on its own', () => {
    expect(parsePreferences(null)).toEqual({});
    expect(parsePreferences('')).toEqual({});
    expect(parsePreferences('{not json')).toEqual({});
    expect(parsePreferences('[1,2]')).toEqual({});
    expect(parsePreferences('"dark"')).toEqual({});
    expect(parsePreferences('null')).toEqual({});
    expect(parsePreferences('{"locale":"zh-TW","theme":"dark"}')).toEqual({ locale: 'zh-TW', theme: 'dark' });
    expect(parsePreferences('{"locale":"zh-CN","theme":"dark"}')).toEqual({ theme: 'dark' });
    expect(parsePreferences('{"locale":"en","theme":"Ligth","vault":"x"}')).toEqual({ locale: 'en' });
  });

  it('maps any Chinese browser language to zh-TW, otherwise English', () => {
    expect(localeFromLanguages(['zh-TW'])).toBe('zh-TW');
    expect(localeFromLanguages(['zh-Hant-HK'])).toBe('zh-TW');
    expect(localeFromLanguages(['zh-CN', 'en'])).toBe('zh-TW');
    expect(localeFromLanguages(['zh'])).toBe('zh-TW');
    expect(localeFromLanguages(['en-GB', 'zh-TW'])).toBe('en');
    expect(localeFromLanguages(['fr-FR', 'zh-TW'])).toBe('zh-TW');
    expect(localeFromLanguages(['fr-FR', 'de'])).toBe('en');
    expect(localeFromLanguages(['zhx-foo'])).toBe('en');
    expect(localeFromLanguages([])).toBe('en');
  });

  it('resolves system against the OS scheme; explicit choices override it', () => {
    expect(resolveTheme('system', false)).toBe('light');
    expect(resolveTheme('system', true)).toBe('dark');
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('dark', false)).toBe('dark');
  });
});

describe('PreferencesService', () => {
  it('defaults to the navigator language and the system theme, writing nothing', () => {
    const storage = new MemoryStorage();
    const { prefs, root } = setup({ storage, languages: ['zh-TW', 'en'], dark: true });
    expect(prefs.locale()).toBe('zh-TW');
    expect(prefs.theme()).toBe('system');
    expect(prefs.resolvedTheme()).toBe('dark');
    expect(root.lang).toBe('zh-TW');
    expect(root.dataset['theme']).toBe('dark');
    expect(storage.length).toBe(0);
  });

  it('persists explicit choices under one settings key and restores them', () => {
    const storage = new MemoryStorage();
    const first = setup({ storage, languages: ['en-US'] }).prefs;
    first.setLocale('zh-TW');
    first.setTheme('dark');
    expect([...storage.data.keys()]).toEqual([SETTINGS_KEY]);
    expect(JSON.parse(storage.data.get(SETTINGS_KEY)!)).toEqual({ locale: 'zh-TW', theme: 'dark' });

    const { prefs, root } = setup({ storage, languages: ['en-US'], dark: false });
    expect(prefs.locale()).toBe('zh-TW');
    expect(prefs.theme()).toBe('dark');
    expect(root.dataset['theme']).toBe('dark');
    expect(root.lang).toBe('zh-TW');

    prefs.setTheme('system');
    expect(JSON.parse(storage.data.get(SETTINGS_KEY)!)).toEqual({ locale: 'zh-TW', theme: 'system' });
  });

  it('ignores values outside the supported set', () => {
    const storage = new MemoryStorage();
    const { prefs } = setup({ storage });
    prefs.setLocale('fr' as never);
    prefs.setTheme('ligth' as never);
    expect(prefs.locale()).toBe('en');
    expect(prefs.theme()).toBe('system');
    expect(storage.length).toBe(0);
  });

  it('falls back to defaults on corrupt stored data and repairs it on the next choice', () => {
    const storage = new MemoryStorage();
    storage.data.set(SETTINGS_KEY, '{"locale":');
    const { prefs } = setup({ storage, languages: ['zh-Hant'] });
    expect(prefs.locale()).toBe('zh-TW');
    expect(prefs.theme()).toBe('system');
    prefs.setTheme('light');
    expect(JSON.parse(storage.data.get(SETTINGS_KEY)!)).toEqual({ theme: 'light' });
  });

  it('works in memory when storage is unavailable', () => {
    const { prefs, root } = setup({ storage: null, dark: true });
    expect(prefs.persistent()).toBe(false);
    prefs.setTheme('light');
    prefs.setLocale('zh-TW');
    TestBed.tick();
    expect(prefs.resolvedTheme()).toBe('light');
    expect(root.dataset['theme']).toBe('light');
    expect(root.lang).toBe('zh-TW');
  });

  it('survives storage that throws on read and on write', () => {
    const storage = new MemoryStorage();
    storage.failReads = true;
    storage.failWrites = true;
    const { prefs } = setup({ storage, languages: ['en'] });
    expect(prefs.locale()).toBe('en');
    expect(prefs.persistent()).toBe(true);
    prefs.setTheme('dark');
    expect(prefs.theme()).toBe('dark'); // choice kept for this page
    expect(prefs.persistent()).toBe(false);
  });

  it('tracks live system changes only while "system" is selected', () => {
    const { prefs, query, root } = setup({ dark: false });
    expect(prefs.resolvedTheme()).toBe('light');
    query.set(true);
    TestBed.tick();
    expect(prefs.resolvedTheme()).toBe('dark');
    expect(root.dataset['theme']).toBe('dark');

    prefs.setTheme('light'); // explicit light under a dark OS
    TestBed.tick();
    expect(root.dataset['theme']).toBe('light');
    query.set(false);
    query.set(true);
    TestBed.tick();
    expect(root.dataset['theme']).toBe('light');

    prefs.setTheme('system'); // follows the OS again
    TestBed.tick();
    expect(root.dataset['theme']).toBe('dark');
    query.set(false);
    TestBed.tick();
    expect(root.dataset['theme']).toBe('light');

    prefs.setTheme('dark'); // explicit dark under a light OS
    TestBed.tick();
    expect(root.dataset['theme']).toBe('dark');
  });
});
