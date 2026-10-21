/**
 * Password settings shared by the generator page and item forms: presets,
 * preset → custom transitions and client-side checks. Generation itself is
 * only ever done by the Rust core.
 */
import { TestBed } from '@angular/core/testing';
import { PASSWORD_PRESETS, PasswordSettings, clientProblem } from './password-options';

describe('PasswordSettings', () => {
  let s: PasswordSettings;
  beforeEach(() => {
    TestBed.configureTestingModule({});
    s = TestBed.inject(PasswordSettings);
  });

  it('starts on the Default preset (24, all four types, required each)', () => {
    expect(s.preset()).toBe('default');
    expect(s.options()).toEqual(PASSWORD_PRESETS.default);
    expect(PASSWORD_PRESETS.default).toMatchObject({ length: 24, lowercase: true, uppercase: true, digits: true, symbols: true, requireEachClass: true, excludeAmbiguous: false });
    expect(PASSWORD_PRESETS.strong.length).toBe(32);
  });

  it('a preset visibly fills every setting; any change makes it Custom without restoring preset rules', () => {
    s.setPreset('strong');
    expect(s.options()).toEqual(PASSWORD_PRESETS.strong);
    s.update({ symbols: false });
    expect(s.preset()).toBe('custom');
    expect(s.options()).toMatchObject({ length: 32, symbols: false, lowercase: true });
    s.update({ length: 24, symbols: true });
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
    expect(PASSWORD_PRESETS.default.length).toBe(24);
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
