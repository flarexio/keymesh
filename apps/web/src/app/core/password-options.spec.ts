/**
 * Password settings shared by the generator page and item forms: presets,
 * preset → custom transitions and client-side checks. Generation itself is
 * only ever done by the Rust core.
 */
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { VaultService } from './vault.service';
import {
  PASSWORD_PRESETS,
  PASSWORD_SETTINGS_KEY,
  PasswordSettings,
  SYMBOL_TEXT_STORE_MAX,
  clientProblem,
  parsePasswordSettings,
  sameOptions,
} from './password-options';
import { PREFERENCE_STORAGE } from './preferences';

/**
 * Stand-in for the core's policy check (the real one runs in WASM and is
 * exercised end to end): rejects digits-only below 20 characters, like the
 * core, and enabled symbol sets that are empty, too long or not ASCII
 * punctuation (disabled symbol text is ignored, as in the core).
 */
function fakeVault() {
  return {
    coreReady: signal(true),
    checks: 0,
    checkPasswordOptions(o: { length: number; lowercase: boolean; uppercase: boolean; digits: boolean; symbols: boolean; symbolSet: string }) {
      this.checks++;
      if (!this.coreReady()) throw new Error('core not loaded');
      // Like the core: symbol text is checked only while Symbols is on.
      if (o.symbols && o.symbolSet === '') throw new Error('invalid generator policy: symbol set is empty');
      if (o.symbols && [...o.symbolSet].length > 64) throw new Error('invalid generator policy: symbol set is too long');
      if (o.symbols && !/^[!-/:-@[-`{-~]+$/.test(o.symbolSet)) {
        throw new Error('invalid generator policy: symbol set may only contain ASCII punctuation');
      }
      if (o.digits && !o.lowercase && !o.uppercase && !o.symbols && o.length < 20) {
        throw new Error('invalid generator policy: policy entropy below 64 bits');
      }
    },
  };
}

/** In-memory Web Storage; `blocked` makes every access throw. */
class MemoryStorage implements Storage {
  data = new Map<string, string>();
  blocked = false;
  full = false;
  get length() {
    return this.data.size;
  }
  clear() {
    this.data.clear();
  }
  key(i: number) {
    return [...this.data.keys()][i] ?? null;
  }
  getItem(k: string) {
    if (this.blocked) throw new DOMException('blocked', 'SecurityError');
    return this.data.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    if (this.blocked) throw new DOMException('blocked', 'SecurityError');
    if (this.full) throw new DOMException('full', 'QuotaExceededError');
    this.data.set(k, v);
  }
  removeItem(k: string) {
    this.data.delete(k);
  }
}

describe('PasswordSettings', () => {
  let s: PasswordSettings;
  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: PREFERENCE_STORAGE, useValue: null },
        { provide: VaultService, useValue: fakeVault() },
      ],
    });
    s = TestBed.inject(PasswordSettings);
  });

  it('starts on the Default preset (32, all four types, required each)', () => {
    expect(s.preset()).toBe('default');
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    expect(PASSWORD_PRESETS.default).toMatchObject({ length: 32, lowercase: true, uppercase: true, digits: true, symbols: true, requireEachClass: true, excludeAmbiguous: false });
    expect(PASSWORD_PRESETS.strong).toMatchObject({ length: 64, lowercase: true, uppercase: true, digits: true, symbols: true, requireEachClass: true, excludeAmbiguous: false });
    expect(PASSWORD_PRESETS.strong.symbolSet).toBe(PASSWORD_PRESETS.default.symbolSet);
  });

  it('a preset visibly fills every setting; any change makes it Custom without restoring preset rules', () => {
    s.setPreset('strong');
    expect(s.options()).toEqual(PASSWORD_PRESETS.strong);
    s.update({ symbols: false });
    expect(s.preset()).toBe('custom');
    expect(s.options()).toMatchObject({ length: 64, symbols: false, lowercase: true });
    s.update({ length: 32, symbols: true });
    // Equal values again, but the user chose Custom: it stays Custom.
    expect(s.preset()).toBe('custom');
    s.setPreset('default');
    expect(s.preset()).toBe('default');
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
  });

  it('choosing Custom keeps the current settings', () => {
    s.setPreset('strong');
    s.setPreset('custom');
    expect(s.options()).toEqual(PASSWORD_PRESETS.strong);
  });

  it('presets are not mutated by updates', () => {
    s.update({ length: 40 });
    expect(PASSWORD_PRESETS.default.length).toBe(32);
  });
});

describe('clientProblem', () => {
  const base = PASSWORD_PRESETS.default;
  it('flags an unusable length or no selected type before calling the core', () => {
    for (const length of [NaN, 7, 129, 24.5]) expect(clientProblem({ ...base, length })).toBe('errors.pwLength');
    expect(clientProblem({ ...base, lowercase: false, uppercase: false, digits: false, symbols: false })).toBe('errors.pwNoClass');
    expect(clientProblem({ ...base, symbolSet: '!'.repeat(65) })).toBe('errors.pwSymbolsLong');
    expect(clientProblem({ ...base, symbols: false, symbolSet: '!'.repeat(65) })).toBeNull();
    expect(clientProblem(base)).toBeNull();
  });
});

describe('sameOptions', () => {
  it('compares every setting', () => {
    const a = PASSWORD_PRESETS.default;
    expect(sameOptions(a, { ...a })).toBe(true);
    for (const patch of [{ length: 25 }, { symbols: false }, { symbolSet: '!' }, { excludeAmbiguous: true }, { requireEachClass: false }]) {
      expect(sameOptions(a, { ...a, ...patch })).toBe(false);
    }
  });
});

describe('PasswordSettings persistence (non-secret settings only)', () => {
  let storage: MemoryStorage;
  let vault: ReturnType<typeof fakeVault>;
  const make = () => {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: PREFERENCE_STORAGE, useValue: storage },
        { provide: VaultService, useValue: vault },
      ],
    });
    return TestBed.inject(PasswordSettings);
  };
  const custom = { ...PASSWORD_PRESETS.default, length: 40, lowercase: false, symbolSet: '-_', excludeAmbiguous: true };

  beforeEach(() => {
    storage = new MemoryStorage();
    vault = fakeVault();
  });

  const digitsOnly = (length: number) => ({
    ...PASSWORD_PRESETS.default,
    length,
    lowercase: false,
    uppercase: false,
    symbols: false,
  });

  it('stored Default/Strong from the old lengths (24/32) pick up the new preset lengths (32/64)', () => {
    const all = { ...PASSWORD_PRESETS.default };
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'default', options: { ...all, length: 24 } }));
    let s = make();
    expect(s.preset()).toBe('default');
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'strong', options: { ...all, length: 32 } }));
    s = make();
    expect(s.preset()).toBe('strong');
    expect(s.options()).toEqual(PASSWORD_PRESETS.strong);
    expect(s.options().length).toBe(64);
    // Already on the new lengths: unchanged.
    expect(parsePasswordSettings(JSON.stringify({ preset: 'default', options: PASSWORD_PRESETS.default }))).toEqual({ preset: 'default', options: PASSWORD_PRESETS.default });
  });

  it('a stored Custom keeps its exact settings, even when they equal an old preset', () => {
    const old = { ...PASSWORD_PRESETS.default, length: 24 };
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'custom', options: old }));
    const s = make();
    expect(s.preset()).toBe('custom');
    expect(s.options()).toEqual(old);
    // A preset label whose settings match neither its old nor its new form is Custom.
    expect(parsePasswordSettings(JSON.stringify({ preset: 'strong', options: { ...old, length: 40 } }))?.preset).toBe('custom');
    expect(parsePasswordSettings(JSON.stringify({ preset: 'default', options: { ...old, symbols: false } }))?.preset).toBe('custom');
  });

  it('settings the core rejects stay in memory; the last accepted ones stay stored', () => {
    const s = make();
    s.update(digitsOnly(24)); // accepted by the core
    s.update({ length: 8 }); // weak: core rejects it
    expect(s.options().length).toBe(8); // the user's edit is kept on screen
    expect(parsePasswordSettings(storage.getItem(PASSWORD_SETTINGS_KEY))?.options).toEqual(digitsOnly(24));
    s.update({ symbols: true, symbolSet: '' }); // enabled but empty symbol set
    expect(parsePasswordSettings(storage.getItem(PASSWORD_SETTINGS_KEY))?.options).toEqual(digitsOnly(24));
    expect(make().options()).toEqual(digitsOnly(24));
  });

  it('stored settings the core rejects are ignored on load (defaults)', () => {
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'custom', options: digitsOnly(8) }));
    const s = make();
    expect(s.preset()).toBe('default');
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    // The rejected entry is not rewritten by loading.
    expect(JSON.parse(storage.getItem(PASSWORD_SETTINGS_KEY)!).options.length).toBe(8);
  });

  it('before the core is ready nothing is restored or saved; then stored settings apply once', () => {
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'custom', options: custom }));
    vault.coreReady.set(false);
    const s = make();
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    vault.coreReady.set(true);
    TestBed.tick();
    expect(s.preset()).toBe('custom');
    expect(s.options()).toEqual(custom);
  });

  it('a change made before the core is ready is kept, not replaced by the stored settings', () => {
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'custom', options: custom }));
    vault.coreReady.set(false);
    const s = make();
    s.setPreset('strong');
    // Not validated yet: not saved over the stored entry.
    expect(JSON.parse(storage.getItem(PASSWORD_SETTINGS_KEY)!).options).toEqual(custom);
    vault.coreReady.set(true);
    TestBed.tick();
    expect(s.options()).toEqual(PASSWORD_PRESETS.strong);
  });

  it('loading writes nothing; a change is saved under its own key and restored', () => {
    const s = make();
    expect(storage.length).toBe(0);
    s.update(custom);
    expect([...storage.data.keys()]).toEqual([PASSWORD_SETTINGS_KEY]);
    expect(JSON.parse(storage.getItem(PASSWORD_SETTINGS_KEY)!)).toEqual({ preset: 'custom', options: custom });
    const again = make();
    expect(again.preset()).toBe('custom');
    expect(again.options()).toEqual(custom);
    again.setPreset('strong');
    expect(make().preset()).toBe('strong');
    expect(make().options()).toEqual(PASSWORD_PRESETS.strong);
  });

  it('an unusable intermediate value is never saved; the last valid settings are kept', () => {
    const s = make();
    s.update({ length: 40 });
    s.update({ length: NaN }); // number box cleared while typing
    expect(parsePasswordSettings(storage.getItem(PASSWORD_SETTINGS_KEY))?.options.length).toBe(40);
    s.update({ symbolSet: 'abc' });
    expect(parsePasswordSettings(storage.getItem(PASSWORD_SETTINGS_KEY))?.options.symbolSet).toBe(PASSWORD_PRESETS.default.symbolSet);
  });

  it('malformed or tampered settings are ignored entirely (defaults)', () => {
    const bad = [
      'not json',
      'null',
      '[]',
      JSON.stringify({ preset: 'custom' }),
      JSON.stringify({ preset: 'custom', options: { ...custom, length: 7 } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, length: 129 } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, length: '40' } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, digits: 'yes' } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, symbolSet: 'x'.repeat(SYMBOL_TEXT_STORE_MAX + 1) } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, symbols: false, symbolSet: 7 } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, lowercase: false, uppercase: false, digits: false, symbols: false } }),
      JSON.stringify({ preset: 'custom', options: { ...custom, password: 'SYNTH' } }),
      JSON.stringify({ preset: 'weird', options: custom }),
    ];
    for (const raw of bad) {
      storage.data.set(PASSWORD_SETTINGS_KEY, raw);
      expect(parsePasswordSettings(raw)).toBeNull();
      const s = make();
      expect(s.preset()).toBe('default');
      expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    }
  });

  it('enabled symbol sets the core rejects are ignored on load', () => {
    for (const symbolSet of ['abc', '！', '!'.repeat(65)]) {
      const raw = JSON.stringify({ preset: 'custom', options: { ...custom, symbolSet } });
      storage.data.set(PASSWORD_SETTINGS_KEY, raw);
      expect(make().options()).toEqual(PASSWORD_PRESETS.default);
    }
  });

  it('disabled symbol text is ignored like the core: invalid edit, disable Symbols, edit length, reload', () => {
    for (const text of ['abc', '!'.repeat(65), 'x'.repeat(SYMBOL_TEXT_STORE_MAX)]) {
      storage.clear();
      const s = make();
      s.update({ length: 32 });
      s.update({ symbolSet: text }); // rejected while Symbols is on: not saved
      expect(parsePasswordSettings(storage.getItem(PASSWORD_SETTINGS_KEY))?.options.symbolSet).toBe(PASSWORD_PRESETS.default.symbolSet);
      s.update({ symbols: false }); // now accepted by the core
      s.update({ length: 40 });
      const again = make();
      expect(again.options()).toMatchObject({ length: 40, symbols: false });
      expect(again.options().symbolSet).toBe(text); // the user's text is kept, not replaced
    }
  });

  it('symbol text longer than the storage bound is not saved (the input enforces the bound)', () => {
    const s = make();
    s.update({ length: 30 });
    s.update({ symbols: false, symbolSet: 'x'.repeat(SYMBOL_TEXT_STORE_MAX + 1), length: 31 });
    expect(parsePasswordSettings(storage.getItem(PASSWORD_SETTINGS_KEY))?.options.length).toBe(30);
  });

  it('a preset label that no longer matches its settings becomes Custom', () => {
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'strong', options: custom }));
    const s = make();
    expect(s.preset()).toBe('custom');
    expect(s.options()).toEqual(custom);
  });

  it('blocked or full storage falls back to in-memory settings', () => {
    storage.data.set(PASSWORD_SETTINGS_KEY, JSON.stringify({ preset: 'custom', options: custom }));
    storage.blocked = true;
    const s = make();
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    expect(() => s.update({ length: 30 })).not.toThrow();
    expect(s.options().length).toBe(30);
    expect(s.persistent()).toBe(false);
    storage.blocked = false;
    storage.full = true;
    const t = make();
    t.update({ length: 50 });
    expect(t.options().length).toBe(50);
    expect(t.persistent()).toBe(false);
  });
});
