/**
 * Catalog completeness and quality, plus runtime translation behaviour.
 */
import { TestBed } from '@angular/core/testing';
import { DOCUMENT } from '@angular/core';
import { DARK_SCHEME_QUERY, NAVIGATOR_LANGUAGES, PREFERENCE_STORAGE, PreferencesService } from '../preferences';
import { CATALOGS, I18n, MISSING, MessageKey, format } from './i18n.service';
import { en } from './en';
import { zhTW } from './zh-tw';

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

/**
 * Characters that exist only in Simplified Chinese (their Traditional forms
 * differ), e.g. 设→設, 据→據, 钥→鑰, 码→碼. Any of them in the zh-TW catalog
 * means a Simplified string slipped in.
 */
const SIMPLIFIED_ONLY = [
  ...'设据钥码锁储复导网络删编辑显隐这们时对发认证务项线数页选择输错误无应该将从么还过开关会实现变换动态视图标签户记忆体软档类别钱载统浅败启闭简历贴账号创链节随机产维摄头扫',
];

describe('i18n catalogs', () => {
  const keys = Object.keys(en).sort();

  it('zh-TW has exactly the English keys, none empty', () => {
    expect(Object.keys(zhTW).sort()).toEqual(keys);
    for (const [locale, cat] of Object.entries(CATALOGS)) {
      for (const k of keys) expect(cat[k as MessageKey].trim().length, `${locale}:${k}`).toBeGreaterThan(0);
    }
  });

  it('placeholders match in every locale', () => {
    for (const k of keys as MessageKey[]) {
      expect(placeholders(zhTW[k]), k).toEqual(placeholders(en[k]));
    }
  });

  it('every zh-TW string is actually translated', () => {
    const same = (keys as MessageKey[]).filter((k) => zhTW[k] === en[k]);
    expect(same).toEqual([]);
  });

  it('zh-TW uses Traditional characters only', () => {
    for (const k of keys as MessageKey[]) {
      const bad = [...zhTW[k]].filter((c) => SIMPLIFIED_ONLY.includes(c));
      expect(bad, `${k}: ${zhTW[k]}`).toEqual([]);
    }
  });

  it('formats placeholders and leaves unknown ones visible', () => {
    expect(format('{a} and {b}', { a: 1, b: 'x' })).toBe('1 and x');
    expect(format('{a} {missing}', { a: 'z' })).toBe('z {missing}');
    expect(format('plain')).toBe('plain');
  });
});

describe('I18n service', () => {
  let prefs: PreferencesService;
  let i18n: I18n;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        { provide: PREFERENCE_STORAGE, useValue: null },
        { provide: NAVIGATOR_LANGUAGES, useValue: ['en-US'] },
        { provide: DARK_SCHEME_QUERY, useValue: null },
      ],
    });
    prefs = TestBed.inject(PreferencesService);
    i18n = TestBed.inject(I18n);
  });

  it('switches language immediately, including the document title', () => {
    const doc = TestBed.inject(DOCUMENT);
    TestBed.tick();
    expect(i18n.t('app.lock')).toBe('Lock');
    expect(doc.title).toBe(en['app.documentTitle']);
    prefs.setLocale('zh-TW');
    TestBed.tick();
    expect(i18n.t('app.lock')).toBe('鎖定');
    expect(doc.title).toBe(zhTW['app.documentTitle']);
    expect(doc.documentElement.lang).toBe('zh-TW');
  });

  it('interpolates and pluralizes with locale rules and number formatting', () => {
    expect(i18n.plural('list.countOne', 'list.countOther', 1)).toBe('1 item');
    expect(i18n.plural('list.countOne', 'list.countOther', 2)).toBe('2 items');
    expect(i18n.plural('list.countOne', 'list.countOther', 1234)).toBe('1,234 items');
    expect(i18n.t('detail.secondsRemaining', { s: 5 })).toBe('5s remaining');
    prefs.setLocale('zh-TW');
    expect(i18n.plural('list.countOne', 'list.countOther', 1)).toBe('1 個項目');
    expect(i18n.t('detail.secondsRemaining', { s: 5 })).toBe('剩餘 5 秒');
  });

  it('formats dates for the active locale', () => {
    const when = Date.UTC(2026, 0, 2, 3, 4);
    const enText = i18n.dateTime(when);
    prefs.setLocale('zh-TW');
    const zhText = i18n.dateTime(when);
    expect(enText).toMatch(/2026/);
    expect(zhText).toMatch(/2026年/);
    expect(zhText).not.toBe(enText);
  });

  it('marks an unknown key visibly instead of failing silently', () => {
    expect(i18n.t('no.such.key' as MessageKey)).toBe(MISSING('no.such.key'));
  });
});

/**
 * Safety meaning of the "rotation outcome unknown" instructions (m5b review).
 * A failed unlock with the NEW password does NOT prove the rotation was not
 * saved: storage may be unreadable for now, or the password mistyped. The
 * copy must never infer noncommit / old-password validity from it, and must
 * tell the user to keep BOTH credential sets until one actually opens it.
 */
describe('uncertain rotation instructions never guess which credential applies', () => {
  const keys = ['notice.rotationUncertain', 'errors.rotationUncertain'] as const;

  it('English: no inference from a failed attempt; keep both; try new, then old', () => {
    for (const k of keys) {
      const s = en[k];
      expect(s, k).not.toMatch(/wasn.t saved|was not saved|not been saved|still works|rolled back|old one works|old password works/i);
      expect(s, k).toMatch(/\bBOTH\b/);
      expect(s, k).toMatch(/NEW/);
      expect(s, k).toMatch(/OLD/);
      expect(s, k).toMatch(/doesn.t (tell|mean|show)/i);
    }
  });

  it('中文: no inference from a failed attempt; keep both; try new, then old', () => {
    for (const k of keys) {
      const s = zhTW[k];
      expect(s, k).not.toMatch(/沒有儲存|未儲存|仍然有效|仍有效|已回復|已還原/);
      expect(s, k).toContain('兩組');
      expect(s, k).toContain('新的');
      expect(s, k).toContain('舊的');
      expect(s, k).toMatch(/不代表|無法判斷|不表示/);
    }
  });
});
