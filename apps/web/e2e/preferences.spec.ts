/**
 * M3: runtime language (zh-TW / en) and appearance (system / light / dark)
 * against the production build and the real Rust/WASM core. SYNTHETIC DATA
 * ONLY. The OS colour scheme is controlled with page.emulateMedia().
 *
 * Screenshots go to $KEYMESH_SCREENSHOT_DIR (absolute, outside the repo) or
 * the ignored Playwright output directory.
 */
import { Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { zhTW } from '../src/app/core/i18n/zh-tw';
import { RFC_URI, storedBytes } from './helpers';

type Locale = 'zh-TW' | 'en';
type Pref = 'system' | 'light' | 'dark';
type Scheme = 'light' | 'dark';

const BG: Record<Scheme, string> = { light: 'rgb(245, 244, 240)', dark: 'rgb(20, 21, 23)' };
const SETTINGS_KEY = 'keymesh.settings.v1';

function shotPath(testInfo: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return testInfo.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

/** Records the theme/lang present when <body> is first parsed (before app code). */
async function recordFirstPaintState(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __boot?: { theme: string | null; lang: string | null } };
    const obs = new MutationObserver(() => {
      if (document.body && !w.__boot) {
        w.__boot = {
          theme: document.documentElement.getAttribute('data-theme'),
          lang: document.documentElement.getAttribute('lang'),
        };
        obs.disconnect();
      }
    });
    obs.observe(document, { childList: true, subtree: true });
  });
}

async function firstPaintState(page: Page) {
  return page.evaluate(() => (window as unknown as { __boot?: unknown }).__boot);
}

async function expectTheme(page: Page, scheme: Scheme) {
  await expect(page.locator('html')).toHaveAttribute('data-theme', scheme);
  await expect
    .poll(() => page.evaluate(() => getComputedStyle(document.body).backgroundColor))
    .toBe(BG[scheme]);
  expect(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme)).toBe(scheme);
}

async function setLocale(page: Page, locale: Locale) {
  await page.locator(`[data-testid=language-switch] [data-locale="${locale}"]`).click();
  await expect(page.locator('html')).toHaveAttribute('lang', locale);
}

async function setTheme(page: Page, pref: Pref) {
  const btn = page.locator(`[data-testid=theme-switch] [data-theme-option="${pref}"]`);
  await btn.click();
  await expect(btn).toHaveAttribute('aria-pressed', 'true');
}

async function startFixtureVault(page: Page) {
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('lock')).toBeVisible();
}

async function newItem(page: Page, kind: string) {
  // Narrow layouts show either the list or the detail: go back to the list.
  if (await page.getByTestId('back').isVisible()) await page.getByTestId('back').click();
  await page.getByTestId('new-item').click();
  await page.locator(`[role=menuitem][data-kind=${kind}]`).click();
}

async function submit(page: Page, title: string) {
  await page.locator('form.item-form button[type=submit]').click();
  await expect(page.locator('#detail-title')).toHaveText(title);
}

/** Synthetic items used for views and screenshots. */
async function seed(page: Page) {
  await newItem(page, 'login');
  await page.locator('form [name=title]').fill('Synthetic Mail');
  await page.locator('form [name=username]').fill('ada@example.test');
  await page.locator('form [name=password]').fill('SYNTH-pw-0001');
  await page.locator('form [name=urls]').fill('https://mail.example.test/login');
  await page.locator('form [name=tags]').fill('synthetic, demo');
  await submit(page, 'Synthetic Mail');

  await newItem(page, 'totp');
  await page.locator('form [name=title]').fill('Synthetic TOTP');
  await page.locator('form [name=totpSetup]').fill(RFC_URI);
  await page.locator('form [name=issuer]').fill('SynthIssuer');
  await submit(page, 'Synthetic TOTP');

  await newItem(page, 'crypto_wallet');
  await page.locator('form [name=title]').fill('Synthetic testnet wallet');
  await page.locator('form [name=network]').fill('testnet');
  await page.locator('form [name=walletAddresses]').fill('tb1-synthetic-address-0001');
  await page.locator('form [name=recoveryPhrase]').fill('synthetic alpha beta gamma');
  await submit(page, 'Synthetic testnet wallet');
}

async function openItem(page: Page, title: string) {
  await page.locator('.item-list button', { hasText: title }).first().click();
  await expect(page.locator('#detail-title')).toHaveText(title);
}

async function noHorizontalOverflow(page: Page, where: string) {
  const { scroll, width } = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    width: document.documentElement.clientWidth,
  }));
  expect(scroll, `horizontal overflow at ${where}`).toBeLessThanOrEqual(width);
}

// --- Mixed-language detection -------------------------------------------------

/** Multi-word English fragments from the catalog (placeholders removed). */
const EN_FRAGMENTS = [
  ...new Set(
    Object.values(en)
      .flatMap((v) => v.split(/\{\w+\}/))
      .map((s) => s.trim().replace(/[.:…]+$/, ''))
      .filter((s) => s.length >= 8 && /\s/.test(s) && /[a-z]{3}/.test(s)),
  ),
];
/** zh-TW catalog fragments with at least two CJK characters. */
const ZH_FRAGMENTS = [
  ...new Set(
    Object.values(zhTW)
      .flatMap((v) => v.split(/\{\w+\}|[，。：；、（）「」…]/))
      .map((s) => s.trim())
      .filter((s) => /[一-鿿]{2}/.test(s)),
  ),
];
const CJK = /[㐀-鿿豈-﫿　-〿＀-￯]/;

/** Visible text plus accessible names, titles and placeholders. */
async function ownedText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const attrs = Array.from(document.querySelectorAll('[aria-label],[title],[placeholder]')).flatMap((el) =>
      ['aria-label', 'title', 'placeholder'].map((a) => el.getAttribute(a) ?? ''),
    );
    return [document.title, document.body.innerText, ...attrs].join('\n');
  });
}

async function expectSingleLanguage(page: Page, locale: Locale, where: string) {
  const text = await ownedText(page);
  expect(text, `missing translation marker at ${where}`).not.toContain('⟦');
  if (locale === 'zh-TW') {
    const leaked = EN_FRAGMENTS.filter((f) => text.includes(f));
    expect(leaked, `English UI text in zh-TW at ${where}`).toEqual([]);
  } else {
    // The only Chinese an English page may show is the language option itself.
    const rest = text.replaceAll('繁中', '').replaceAll('繁體中文', '');
    const cjk = rest.split('\n').filter((l) => CJK.test(l));
    expect(cjk, `Chinese UI text in en at ${where}`).toEqual([]);
    expect(ZH_FRAGMENTS.filter((f) => rest.includes(f))).toEqual([]);
  }
}

/** Visit every screen of an unlocked vault and check its language. */
async function checkAllScreens(page: Page, locale: Locale) {
  await expectSingleLanguage(page, locale, 'list');
  await openItem(page, 'Synthetic Mail');
  await expectSingleLanguage(page, locale, 'login detail');
  await openItem(page, 'Synthetic TOTP');
  await expectSingleLanguage(page, locale, 'totp detail');
  await page.getByTestId('edit').click();
  await expectSingleLanguage(page, locale, 'edit form');
  await page.locator('form.item-form button[type=button]', { hasText: locale === 'en' ? 'Cancel' : '取消' }).click();
  await newItem(page, 'secret');
  await page.locator('form.item-form button[type=submit]').click(); // empty: validation errors
  await expect(page.locator('form [aria-invalid=true]').first()).toBeVisible();
  await expectSingleLanguage(page, locale, 'form validation');
  await page.getByTestId('nav-generators').click();
  await page.locator('.tool-card').first().locator('button', { hasText: locale === 'en' ? 'Preview' : '預覽' }).click();
  await expectSingleLanguage(page, locale, 'generators');
  await page.getByTestId('nav-backup').click();
  await page.getByTestId('restore-input').setInputFiles({
    name: 'garbage.keymesh',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('not a vault'),
  });
  await expect(page.getByTestId('backup-error')).toHaveText(locale === 'en' ? en['errors.backupRejected'] : zhTW['errors.backupRejected']);
  await expectSingleLanguage(page, locale, 'backup error');
  await page.getByTestId('nav-import').click();
  await expectSingleLanguage(page, locale, 'import');
  await page.getByTestId('nav-items').click();
  await openItem(page, 'Synthetic Mail');
  await page.getByTestId('delete').click();
  await expect(page.locator('dialog[open]')).toBeVisible();
  await expectSingleLanguage(page, locale, 'confirm dialog');
  await page.keyboard.press('Escape');
  await expect(page.locator('dialog[open]')).toHaveCount(0);
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock')).toBeVisible();
  await expectSingleLanguage(page, locale, 'locked');
  await page.getByTestId('unlock').click();
  await expect(page.getByTestId('lock')).toBeVisible();
}

// --- Tests ----------------------------------------------------------------------

test.describe('default language and theme', () => {
  for (const [lang, expected] of [
    ['zh-TW', 'zh-TW'],
    ['zh-CN', 'zh-TW'],
    ['en-GB', 'en'],
    ['fr-FR', 'en'],
  ] as const) {
    test(`navigator ${lang} → ${expected}, theme follows the OS, nothing stored`, async ({ browser }) => {
      const ctx = await browser.newContext({ locale: lang, colorScheme: 'dark' });
      const page = await ctx.newPage();
      await recordFirstPaintState(page);
      await page.goto('/');
      await expect(page.getByTestId('start-vault')).toBeVisible();
      await expect(page.locator('html')).toHaveAttribute('lang', expected);
      await expect(page).toHaveTitle(expected === 'en' ? en['app.documentTitle'] : zhTW['app.documentTitle']);
      await expectTheme(page, 'dark');
      expect(await firstPaintState(page)).toEqual({ theme: 'dark', lang: expected });
      expect(await page.evaluate(() => localStorage.length)).toBe(0);
      await expectSingleLanguage(page, expected, 'start');
      await ctx.close();
    });
  }
});

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: all three appearance preferences, live OS changes, reload, screenshots`, async ({ browser }, testInfo) => {
    const ctx = await browser.newContext({ locale: locale === 'en' ? 'zh-TW' : 'en-US', colorScheme: 'light' });
    const page = await ctx.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
    const requests: string[] = [];
    page.on('request', (r) => requests.push(r.url()));
    await recordFirstPaintState(page);
    await page.setViewportSize({ width: 1280, height: 860 });
    await page.goto('/');
    await setLocale(page, locale); // explicit choice, opposite of the browser default
    await startFixtureVault(page);
    await seed(page);
    await page.clock.setFixedTime(new Date(59_000));
    await checkAllScreens(page, locale);

    for (const pref of ['system', 'light', 'dark'] as const) {
      await setTheme(page, pref);
      // Opposite OS scheme first: explicit choices must not follow it.
      const opposite: Scheme = pref === 'dark' ? 'light' : 'dark';
      await page.emulateMedia({ colorScheme: opposite });
      await expectTheme(page, pref === 'system' ? opposite : pref);
      if (pref === 'system') {
        await page.emulateMedia({ colorScheme: 'light' }); // live change, no reload
        await expectTheme(page, 'light');
        await page.emulateMedia({ colorScheme: 'dark' });
        await expectTheme(page, 'dark');
      }
      const resolved: Scheme = pref === 'system' ? 'dark' : pref;

      // Reload: choice and language restored before the first paint.
      await page.reload();
      expect(await firstPaintState(page)).toEqual({ theme: resolved, lang: locale });
      await expectTheme(page, resolved);
      await expect(page.locator(`[data-theme-option="${pref}"]`)).toHaveAttribute('aria-pressed', 'true');
      await expect(page.locator(`[data-locale="${locale}"]`)).toHaveAttribute('aria-pressed', 'true');
      await expectSingleLanguage(page, locale, `stored screen (${pref})`);
      await page.getByTestId('open-fixture').click();
      await openItem(page, 'Synthetic TOTP');
      await expectSingleLanguage(page, locale, `detail (${pref})`);
      await page.screenshot({ path: shotPath(testInfo, `keymesh-${locale}-${pref}-${resolved}.png`) });
    }

    // Only the non-secret settings key, holding only the two preferences.
    const stored = await page.evaluate((k) => ({ keys: Object.keys(localStorage), value: localStorage.getItem(k) }), SETTINGS_KEY);
    expect(stored.keys).toEqual([SETTINGS_KEY]);
    expect(JSON.parse(stored.value!)).toEqual({ locale, theme: 'dark' });

    const origin = new URL(page.url()).origin;
    expect(requests.filter((u) => !u.startsWith(origin) && !u.startsWith('blob:'))).toEqual([]);
    expect(errors).toEqual([]);
    await ctx.close();
  });
}

test('switching language/theme keeps unsaved input, selection, TOTP and keys; vault bytes unchanged', async ({ page }) => {
  await page.goto('/');
  await startFixtureVault(page);
  await seed(page);
  await page.clock.setFixedTime(new Date(59_000));

  // Generated Ed25519 key and a password preview.
  await page.getByTestId('nav-generators').click();
  await page.locator('#gen-key-title').fill('Synthetic signing key');
  await page.locator('.tool-card', { has: page.locator('#gen-key') }).locator('button.btn-primary').click();
  await expect(page.locator('#detail-title')).toHaveText('Synthetic signing key');
  const openssh = await page.locator('.field-row', { hasText: 'OpenSSH' }).locator('dd').innerText();
  const before = await storedBytes(page);

  for (const [locale, pref] of [
    ['zh-TW', 'dark'],
    ['en', 'light'],
    ['zh-TW', 'system'],
  ] as const) {
    await setLocale(page, locale);
    await setTheme(page, pref);
    await expect(page.locator('#detail-title')).toHaveText('Synthetic signing key');
    await expect(page.locator('.field-row', { hasText: 'OpenSSH' }).locator('dd')).toHaveText(openssh);
  }
  await openItem(page, 'Synthetic TOTP');
  await expect(page.getByTestId('totp-code')).toHaveText('94287082');
  await setLocale(page, 'en');
  await expect(page.getByTestId('totp-code')).toHaveText('94287082');
  await expect(page.getByTestId('totp-remaining')).toHaveText('1s remaining');
  await setLocale(page, 'zh-TW');
  await expect(page.getByTestId('totp-remaining')).toHaveText('剩餘 1 秒');

  // Unsaved form input survives switches.
  await newItem(page, 'login');
  const form = page.locator('form.item-form');
  await form.locator('[name=username]').fill('unsaved-user');
  await form.locator('[name=password]').fill('SYNTH-unsaved-pw');
  await form.locator('[name=notes]').fill('unsaved note');
  await form.locator('button', { hasText: '新增自訂欄位' }).click();
  await form.locator('.custom-row input').first().fill('pin');
  await form.locator('.custom-row input').nth(1).fill('SYNTH-1234');
  await page.locator('form.item-form button[type=submit]').click(); // empty title: validation error
  await expect(form.locator('.field-error')).toHaveText(zhTW['validation.titleRequired']);
  for (const [locale, pref] of [
    ['en', 'dark'],
    ['zh-TW', 'light'],
    ['en', 'system'],
  ] as const) {
    await setLocale(page, locale);
    await setTheme(page, pref);
    await expect(form.locator('[name=title]')).toHaveValue('');
    await expect(form.locator('[name=username]')).toHaveValue('unsaved-user');
    await expect(form.locator('[name=password]')).toHaveValue('SYNTH-unsaved-pw');
    await expect(form.locator('[name=notes]')).toHaveValue('unsaved note');
    await expect(form.locator('.custom-row input').nth(1)).toHaveValue('SYNTH-1234');
    // The validation message follows the language.
    await expect(form.locator('.field-error')).toHaveText(locale === 'en' ? en['validation.titleRequired'] : zhTW['validation.titleRequired']);
  }
  expect((await storedBytes(page)).equals(before), 'language/theme changes must not write the vault').toBe(true);

  // Saving afterwards works and is the only write.
  await form.locator('[name=title]').fill('Saved synthetic login');
  await submit(page, 'Saved synthetic login');
  expect((await storedBytes(page)).equals(before)).toBe(false);

  // Generator: edited titles survive, untouched defaults follow the language.
  await page.getByTestId('nav-generators').click();
  await page.locator('#gen-secret-title').fill('My synthetic token');
  await setLocale(page, 'zh-TW');
  await expect(page.locator('#gen-secret-title')).toHaveValue('My synthetic token');
  await expect(page.locator('#gen-pw-title')).toHaveValue(zhTW['gen.pw.defaultTitle']);
  await page.locator('.tool-card').first().locator('button', { hasText: '預覽' }).click();
  const preview = await page.getByTestId('password-preview').innerText();
  await setLocale(page, 'en');
  await setTheme(page, 'dark');
  await expect(page.getByTestId('password-preview')).toHaveText(preview);
  await expect(page.locator('#gen-pw-title')).toHaveValue(en['gen.pw.defaultTitle']);
});

test('keyboard: skip link, visible focus, preference controls, menu and dialog', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId('start-vault')).toBeVisible();
  await page.keyboard.press('Tab');
  await expect(page.locator('.skip-link')).toBeFocused();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab'); // globe icon is not focusable: 繁中, then EN
  const zhBtn = page.locator('[data-locale="zh-TW"]');
  await page.keyboard.press('Shift+Tab');
  await expect(zhBtn).toBeFocused();
  const outline = await zhBtn.evaluate((el) => getComputedStyle(el).outlineStyle);
  expect(outline).not.toBe('none');
  await page.keyboard.press('Enter');
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-TW');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await expect(page.locator('[data-theme-option=dark]')).toBeFocused();
  await page.keyboard.press('Space');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

  // Reach and press the start button with the keyboard only.
  await page.locator('input[name=mode][value=synthetic-fixture]').focus();
  await page.keyboard.press('Space');
  for (let i = 0; i < 10 && !(await page.getByTestId('start-vault').evaluate((el) => el === document.activeElement)); i++) {
    await page.keyboard.press('Tab');
  }
  await expect(page.getByTestId('start-vault')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByTestId('lock')).toBeVisible();

  // New-item menu: arrows, Escape returns focus, Enter picks.
  await page.getByTestId('new-item').focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('[role=menuitem][data-kind=login]')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.locator('[role=menu]')).toHaveCount(0);
  await expect(page.getByTestId('new-item')).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('[role=menuitem][data-kind=login]')).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('[role=menuitem][data-kind=secret]')).toBeFocused();
  await page.keyboard.press('End');
  await expect(page.locator('[role=menuitem][data-kind=secure_note]')).toBeFocused();
  await page.keyboard.press('Enter');
  await page.locator('form [name=title]').fill('Keyboard note');
  await page.locator('form [name=body]').fill('synthetic');
  await page.locator('form [name=body]').focus();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await page.keyboard.press('Tab');
  await expect(page.locator('form.item-form button[type=submit]')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#detail-title')).toHaveText('Keyboard note');

  // Destructive confirmation: Cancel is focused first; Escape cancels.
  await page.getByTestId('delete').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('dialog[open]')).toBeVisible();
  await expect(page.locator('dialog[open] button', { hasText: '取消' })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.locator('dialog[open]')).toHaveCount(0);
  await expect(page.locator('.item-list')).toContainText('Keyboard note');
});

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: narrow viewports have no horizontal overflow; mobile navigation works`, async ({ browser }, testInfo) => {
    const ctx = await browser.newContext({ locale, colorScheme: locale === 'en' ? 'dark' : 'light', hasTouch: true });
    const page = await ctx.newPage();
    await page.setViewportSize({ width: 360, height: 760 });
    await page.goto('/');
    await expect(page.getByTestId('start-vault')).toBeVisible();
    await noHorizontalOverflow(page, 'start');
    await expect(page.getByTestId('language-switch')).toBeVisible();
    await expect(page.getByTestId('theme-switch')).toBeVisible();
    await startFixtureVault(page);
    await seed(page);
    for (const width of [320, 360, 390]) {
      await page.setViewportSize({ width, height: 760 });
      await noHorizontalOverflow(page, `${width} detail`);
      await page.getByTestId('back').click();
      await expect(page.locator('.item-list')).toBeVisible();
      await noHorizontalOverflow(page, `${width} list`);
      await openItem(page, 'Synthetic testnet wallet');
      await noHorizontalOverflow(page, `${width} wallet`);
      await page.getByTestId('edit').click();
      await noHorizontalOverflow(page, `${width} form`);
      await page.locator('form.item-form .form-actions button[type=button]').click();
      for (const tab of ['generators', 'backup', 'import', 'items'] as const) {
        await page.getByTestId(`bnav-${tab}`).click();
        await expect(page.getByTestId(`bnav-${tab}`)).toHaveAttribute('aria-current', 'page');
        await noHorizontalOverflow(page, `${width} ${tab}`);
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByTestId('back').click();
    await page.getByTestId('kind-filter').selectOption('totp');
    await expect(page.locator('.item-list .title')).toHaveText(['Synthetic TOTP']);
    await page.getByTestId('kind-filter').selectOption('');
    await openItem(page, 'Synthetic Mail');
    await expectSingleLanguage(page, locale, 'mobile detail');
    await page.screenshot({ path: shotPath(testInfo, `keymesh-mobile-${locale}.png`), fullPage: true });
    await page.getByTestId('lock').click();
    await noHorizontalOverflow(page, 'locked');
    await page.screenshot({ path: shotPath(testInfo, `keymesh-mobile-locked-${locale}.png`), fullPage: true });
    await ctx.close();
  });
}

test('corrupt and unavailable preference storage fall back safely', async ({ browser }) => {
  // Corrupt value.
  const a = await browser.newContext({ locale: 'zh-TW', colorScheme: 'dark' });
  await a.addInitScript((k) => localStorage.setItem(k, '{"theme":"neon","locale":'), SETTINGS_KEY);
  const p = await a.newPage();
  const errors: string[] = [];
  p.on('pageerror', (e) => errors.push(e.message));
  await p.goto('/');
  await expect(p.getByTestId('start-vault')).toBeVisible();
  await expect(p.locator('html')).toHaveAttribute('lang', 'zh-TW');
  await expectTheme(p, 'dark');
  await setTheme(p, 'light');
  expect(JSON.parse((await p.evaluate((k) => localStorage.getItem(k), SETTINGS_KEY))!)).toEqual({ theme: 'light' });
  await a.close();

  // Storage blocked entirely: works for this page, says choices are not saved.
  const b = await browser.newContext({ locale: 'en-US', colorScheme: 'light' });
  await b.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', {
      get() {
        throw new DOMException('blocked', 'SecurityError');
      },
    });
  });
  const q = await b.newPage();
  q.on('pageerror', (e) => errors.push(e.message));
  await q.goto('/');
  await expect(q.getByTestId('start-vault')).toBeVisible();
  await expect(q.getByRole('note').filter({ hasText: en['prefs.notSaved'] })).toBeVisible();
  await setTheme(q, 'dark');
  await expectTheme(q, 'dark');
  await setLocale(q, 'zh-TW');
  await startFixtureVault(q);
  await expect(q.locator('[data-testid=key-mode]')).toContainText('synthetic-fixture');
  await b.close();
  expect(errors).toEqual([]);
});

test('CSP stays strict: no inline scripts, no violations, reduced motion respected', async ({ page, request }) => {
  const html = await (await request.get('/')).text();
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  expect(scripts.length).toBeGreaterThan(0);
  for (const [, attrs, body] of scripts) {
    expect(attrs).toMatch(/\bsrc=/);
    expect(body.trim()).toBe('');
  }
  const csp = (await request.get('/')).headers()['content-security-policy'];
  expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval';");
  expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);

  const violations: string[] = [];
  page.on('console', (m) => /Content Security Policy/i.test(m.text()) && violations.push(m.text()));
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await expect(page.getByTestId('start-vault')).toBeVisible();
  const duration = await page.getByTestId('start-vault').evaluate((el) => getComputedStyle(el).transitionDuration);
  expect(parseFloat(duration)).toBeLessThan(0.001);
  await setTheme(page, 'dark');
  await setLocale(page, 'zh-TW');
  await page.reload();
  await expect(page.getByTestId('start-vault')).toBeVisible();
  expect(violations).toEqual([]);
});

// --- M3 review 1 -----------------------------------------------------------------

const KINDS = ['login', 'secret', 'contact', 'crypto_wallet', 'ed25519_key', 'totp', 'secure_note'] as const;

/**
 * Every New-item option must be reachable by a real pointer click: no
 * programmatic scrolling first (a user cannot scroll an overflow:hidden
 * pane), no ancestor clipping, centre hit-tests to the option, then a mouse
 * click at those coordinates.
 */
async function clickEveryNewItemKind(page: Page, where: string) {
  for (const kind of KINDS) {
    await page.getByTestId('new-item').click();
    const option = page.locator(`[role=menuitem][data-kind=${kind}]`);
    await expect(option).toBeVisible();
    const vp = page.viewportSize()!;
    const measure = () =>
      option.evaluate((el) => {
        const r = el.getBoundingClientRect();
        const menu = (el.closest('[role=menu]') as HTMLElement).getBoundingClientRect();
        const clippedBy: string[] = [];
        // A position:fixed menu escapes overflow clipping unless an ancestor
        // becomes its containing block (transform, filter, contain, …).
        const fixed = getComputedStyle(el.closest('[role=menu]')!).position === 'fixed';
        const containing = (cs: CSSStyleDeclaration) =>
          cs.transform !== 'none' || cs.filter !== 'none' || cs.perspective !== 'none' ||
          cs.backdropFilter !== 'none' || /paint|layout|strict|content/.test(cs.contain) ||
          /transform|filter/.test(cs.willChange);
        let escaped = fixed;
        for (let a = el.parentElement; a; a = a.parentElement) {
          const cs = getComputedStyle(a);
          if (a.getAttribute('role') === 'menu') continue; // the menu's own scroll
          if (escaped && containing(cs)) escaped = false;
          if (escaped) continue;
          if (cs.overflowX === 'visible' && cs.overflowY === 'visible') continue;
          const c = a.getBoundingClientRect();
          if (r.top < c.top - 0.5 || r.bottom > c.bottom + 0.5 || r.left < c.left - 0.5 || r.right > c.right + 0.5) {
            clippedBy.push(String(a.className || a.tagName));
          }
        }
        return {
          x: r.x + r.width / 2,
          y: r.y + r.height / 2,
          bottom: r.bottom,
          clippedBy,
          menuCenter: { x: menu.x + menu.width / 2, y: menu.y + menu.height / 2 },
          inMenuView: r.top >= menu.top - 0.5 && r.bottom <= menu.bottom + 0.5,
        };
      });
    let state = await measure();
    // A short viewport caps the menu height; scroll the menu itself with the wheel, like a user.
    for (let i = 0; i < 10 && !state.inMenuView; i++) {
      await page.mouse.move(state.menuCenter.x, state.menuCenter.y);
      await page.mouse.wheel(0, 120);
      await expect(page.locator('[role=menu]')).toHaveCount(1);
      state = await measure();
    }
    expect(state.inMenuView, `${where}: ${kind} not reachable inside the menu`).toBe(true);
    expect(state.clippedBy, `${where}: ${kind} clipped by ancestors`).toEqual([]);
    expect(state.bottom, `${where}: ${kind} below viewport`).toBeLessThanOrEqual(vp.height);
    const hit = await page.evaluate(
      ({ x, y, k }) => !!document.elementFromPoint(x, y)?.closest(`[role=menuitem][data-kind="${k}"]`),
      { x: state.x, y: state.y, k: kind },
    );
    expect(hit, `${where}: ${kind} option is not hit-testable`).toBe(true);
    await page.mouse.click(state.x, state.y);
    await expect(page.locator(`form.item-form .form-head .kind-tile[data-kind=${kind}]`)).toBeVisible();
    await expect(page.locator('[role=menu]')).toHaveCount(0);
    await page.locator('form.item-form .form-actions button[type=button]').click();
  }
}

test('desktop New-item menu: every kind is clickable with an empty and a one-item list, at several heights', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1280, height: 860 });
  await page.goto('/');
  await startFixtureVault(page);
  for (const height of [860, 600, 460]) {
    await page.setViewportSize({ width: 1280, height });
    await clickEveryNewItemKind(page, `empty ${height}`);
  }
  await newItem(page, 'login');
  await page.locator('form [name=title]').fill('Synthetic Mail');
  await submit(page, 'Synthetic Mail');
  for (const height of [860, 600, 460]) {
    await page.setViewportSize({ width: 1280, height });
    await clickEveryNewItemKind(page, `one item ${height}`);
  }
  await page.setViewportSize({ width: 1280, height: 600 });
  await page.getByTestId('new-item').click();
  await expect(page.locator('[role=menu]')).toBeVisible();
  await page.screenshot({ path: shotPath(testInfo, 'keymesh-en-new-item-menu-1280x600.png') });
  await page.keyboard.press('Escape');
  // Independent pane scrolling still works with the menu change.
  await page.setViewportSize({ width: 1280, height: 860 });
  await expect(page.locator('main')).toHaveCSS('overflow', 'hidden');
  await expect(page.locator('.list-pane .item-list')).toHaveCSS('overflow-y', 'auto');
  await expect(page.locator('.detail-pane')).toHaveCSS('overflow-y', 'auto');
});

test('mobile New-item menu: every kind is clickable by touch-size pointer', async ({ browser }) => {
  const ctx = await browser.newContext({ hasTouch: true, isMobile: true, viewport: { width: 360, height: 640 } });
  const page = await ctx.newPage();
  await page.goto('/');
  await startFixtureVault(page);
  await clickEveryNewItemKind(page, 'mobile empty');
  await ctx.close();
});

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: preference controls are ≥44px touch targets on coarse pointers`, async ({ browser }, testInfo) => {
    for (const width of [320, 390]) {
      const ctx = await browser.newContext({ locale, hasTouch: true, isMobile: true, viewport: { width, height: 760 } });
      const page = await ctx.newPage();
      await page.goto('/');
      await expect(page.getByTestId('start-vault')).toBeVisible();
      expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
      const check = async (where: string) => {
        const targets = page.locator('[data-testid=language-switch] button, [data-testid=theme-switch] button');
        await expect(targets).toHaveCount(5);
        for (const t of await targets.all()) {
          const box = (await t.boundingBox())!;
          const name = (await t.getAttribute('aria-label')) ?? (await t.innerText());
          expect(box.height, `${where} ${width}px ${name} height`).toBeGreaterThanOrEqual(44);
          expect(box.width, `${where} ${width}px ${name} width`).toBeGreaterThanOrEqual(44);
        }
        await noHorizontalOverflow(page, `${where} ${width}px`);
      };
      await check('start');
      await startFixtureVault(page);
      await check('unlocked');
      if (width === 320) await page.screenshot({ path: shotPath(testInfo, `keymesh-touch-prefs-${locale}-320.png`) });
      const lock = (await page.getByTestId('lock').boundingBox())!;
      expect(lock.height).toBeGreaterThanOrEqual(44);
      await ctx.close();
    }
  });
}
