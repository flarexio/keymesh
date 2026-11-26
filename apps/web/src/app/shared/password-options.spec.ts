/**
 * Password settings panel layout: the preset and the length stay visible;
 * the character types, the allowed symbols and the fine options sit under one
 * collapsed "More options". Hiding them changes nothing: all four types (and
 * symbols) stay on by default.
 */
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { VaultService } from '../core/vault.service';
import { PREFERENCE_STORAGE } from '../core/preferences';
import { PASSWORD_PRESETS, PasswordSettings } from '../core/password-options';
import { en } from '../core/i18n/en';
import { PasswordOptionsPanel } from './password-options';

function render() {
  TestBed.configureTestingModule({
    providers: [
      { provide: PREFERENCE_STORAGE, useValue: null },
      { provide: VaultService, useValue: { coreReady: signal(true), checkPasswordOptions: () => undefined } },
    ],
  });
  const f = TestBed.createComponent(PasswordOptionsPanel);
  f.detectChanges();
  return { f, el: f.nativeElement as HTMLElement };
}

const inClosedDetails = (n: Element) => {
  const d = n.closest('details');
  return !!d && !d.open && !n.closest('summary');
};

afterEach(() => TestBed.resetTestingModule());

describe('PasswordOptionsPanel', () => {
  it('keeps preset and length visible, and puts every type and symbol option under a collapsed More options', () => {
    const { el } = render();
    expect(inClosedDetails(el.querySelector('select[name=pwPreset]')!)).toBe(false);
    expect(inClosedDetails(el.querySelector('input[name=pwLength]')!)).toBe(false);
    expect(inClosedDetails(el.querySelector('input[name=pwLengthRange]')!)).toBe(false);
    const more = el.querySelector<HTMLDetailsElement>('details[data-testid=pw-more]')!;
    expect(more).not.toBeNull();
    expect(more.open).toBe(false);
    expect(more.querySelector('summary')?.textContent).toContain(en['pwopt.more']);
    for (const name of ['pw-lowercase', 'pw-uppercase', 'pw-digits', 'pw-symbols', 'pw-excludeAmbiguous', 'pw-requireEachClass', 'pwSymbolSet']) {
      const n = el.querySelector(`[name=${name}]`);
      expect(n, name).not.toBeNull();
      expect(inClosedDetails(n!), name).toBe(true);
    }
  });

  it('symbols stay on by default while hidden, and the summary says which types are included', () => {
    const { el } = render();
    expect(TestBed.inject(PasswordSettings).options()).toEqual(PASSWORD_PRESETS.default);
    expect(el.querySelector<HTMLInputElement>('[name=pw-symbols]')!.checked).toBe(true);
    const summary = el.querySelector('[data-testid=pw-more-summary]')!.textContent!;
    for (const k of ['pwopt.short.lowercase', 'pwopt.short.uppercase', 'pwopt.short.digits', 'pwopt.short.symbols'] as const) {
      expect(summary).toContain(en[k]);
    }
  });

  it('the summary follows the settings', () => {
    const { f, el } = render();
    TestBed.inject(PasswordSettings).update({ symbols: false });
    f.detectChanges();
    const summary = el.querySelector('[data-testid=pw-more-summary]')!.textContent!;
    expect(summary).not.toContain(en['pwopt.short.symbols']);
    expect(summary).toContain(en['pwopt.short.digits']);
  });
});
