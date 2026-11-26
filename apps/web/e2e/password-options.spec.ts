/**
 * Password settings, end to end against the real Rust/WASM core: presets and
 * custom rules on the generator page and inside the Login/Secret forms, in
 * 中文 and EN. SYNTHETIC DATA ONLY.
 *
 * Generated values are read into the test but never asserted by printing
 * them: checks compare booleans, so a failure cannot log a generated secret.
 */
import { Browser, Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { zhTW } from '../src/app/core/i18n/zh-tw';
import { pwMore } from './helpers';

type Locale = 'zh-TW' | 'en';
type Catalog = Record<keyof typeof en, string>;
const catalog = (l: Locale): Catalog => (l === 'en' ? en : zhTW);

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const DEFAULT_SYMBOLS = '!#$%&()*+,-./:;<=>?@[]^_{|}~';
const AMBIGUOUS = 'Il1O0o';
const noAmbiguous = (s: string) => [...s].filter((c) => !AMBIGUOUS.includes(c)).join('');

function shotPath(testInfo: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return testInfo.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

/** Booleans only: exact length, allowed set, and one of each required class. */
function verdict(value: string, length: number, classes: string[]) {
  const chars = [...value];
  const all = classes.join('');
  return {
    length: chars.length === length,
    allowed: chars.every((c) => all.includes(c)),
    each: classes.map((set) => chars.some((c) => set.includes(c))),
  };
}
const ok = (n: number) => ({ length: true, allowed: true, each: Array<boolean>(n).fill(true) });

async function openVault(browser: Browser, locale: Locale, viewport = { width: 1280, height: 900 }) {
  const context = await browser.newContext({ locale: locale === 'en' ? 'en-US' : 'zh-TW', viewport });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('lang', locale);
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('lock')).toBeVisible();
  return { context, page, errors };
}

const opts = (page: Page) => page.getByTestId('password-options').first();

async function setLength(page: Page, n: number | string) {
  await opts(page).locator('[name=pwLength]').fill(String(n));
}

async function setChecks(page: Page, on: Partial<Record<'lowercase' | 'uppercase' | 'digits' | 'symbols', boolean>>) {
  await moreOptions(page);
  for (const [flag, value] of Object.entries(on)) await opts(page).locator(`[name=pw-${flag}]`).setChecked(value);
}

async function moreOptions(page: Page) {
  const details = opts(page).locator('details.more-options');
  if (!(await details.evaluate((d) => (d as HTMLDetailsElement).open))) await details.locator('summary').click();
}

/** Reveal the generated value on screen and read it (never printed). */
async function revealGenerated(page: Page, t: Catalog): Promise<string> {
  const row = page.getByTestId('generated-password');
  await expect(row.getByTestId('generated-value')).toContainText('•');
  await row.getByRole('button', { name: t['secret.reveal'] }).click();
  await expect(row.getByTestId('generated-value')).not.toContainText('•');
  return row.getByTestId('generated-value').innerText();
}

async function revealStored(page: Page, t: Catalog, label: string): Promise<string> {
  const row = page.locator('km-secret-field', { hasText: label });
  await row.getByRole('button', { name: t['secret.reveal'] }).click();
  await expect(row.getByTestId('secret-value')).not.toContainText('•');
  return row.getByTestId('secret-value').innerText();
}

async function lockAndUnlock(page: Page) {
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock')).toBeVisible();
  await page.getByTestId('unlock').click();
  await expect(page.getByTestId('lock')).toBeVisible();
}

async function noHorizontalOverflow(page: Page, where: string) {
  const { scroll, width } = await page.evaluate(() => ({
    scroll: document.documentElement.scrollWidth,
    width: document.documentElement.clientWidth,
  }));
  expect(scroll, `horizontal overflow at ${where}`).toBeLessThanOrEqual(width);
}

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: generator page presets, custom rules and real WASM output`, async ({ browser }, testInfo) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale);
    await page.getByTestId('nav-generators').click();
    const preset = opts(page).locator('[name=pwPreset]');
    const length = opts(page).locator('[name=pwLength]');
    const slider = opts(page).locator('[name=pwLengthRange]');

    // Preset and length are in view; the types and symbols wait under More options (all on).
    await expect(preset).toBeVisible();
    await expect(length).toBeVisible();
    await expect(opts(page).locator('[name=pw-symbols]')).toBeHidden();
    await expect(opts(page).getByTestId('pw-more-summary')).toHaveText(['pwopt.short.lowercase', 'pwopt.short.uppercase', 'pwopt.short.digits', 'pwopt.short.symbols'].map((k) => t[k as keyof Catalog]).join(' · '));
    await moreOptions(page);
    // Default preset: 32 characters, all four types; Strong fills 64.
    await expect(preset).toHaveValue('default');
    await expect(length).toHaveValue('32');
    await expect(slider).toHaveValue('32');
    for (const f of ['lowercase', 'uppercase', 'digits', 'symbols']) await expect(opts(page).locator(`[name=pw-${f}]`)).toBeChecked();
    await expect(opts(page).locator('[name=pwSymbolSet]')).toHaveValue(DEFAULT_SYMBOLS);
    await expect(slider).toHaveAccessibleName(t['pwopt.lengthSlider']);
    await expect(length).toHaveAccessibleName(t['pwopt.length']);
    await preset.selectOption('strong');
    await expect(length).toHaveValue('64');
    await expect(slider).toHaveValue('64');
    await page.getByTestId('generate-password').click();
    expect(verdict(await revealGenerated(page, t), 64, [LOWER, UPPER, DIGITS, DEFAULT_SYMBOLS])).toEqual(ok(4));

    // Any change makes it Custom and keeps the other settings.
    await setLength(page, 40);
    await expect(preset).toHaveValue('custom');
    await expect(slider).toHaveValue('40');
    await slider.focus();
    await page.keyboard.press('ArrowRight');
    await expect(length).toHaveValue('41');
    await page.keyboard.press('ArrowLeft');
    await expect(length).toHaveValue('40');
    await setChecks(page, { lowercase: false });
    await opts(page).locator('[name=pwSymbolSet]').fill('#@!#@!');
    await moreOptions(page);
    await opts(page).locator('[name=pw-excludeAmbiguous]').check();
    await expect(opts(page).locator('[name=pw-requireEachClass]')).toBeChecked();
    await expect(preset).toHaveValue('custom');
    await expect(length).toHaveValue('40');
    await expect(page.getByTestId('password-options-error')).toHaveCount(0);
    for (let i = 0; i < 5; i++) {
      await page.getByTestId('generate-password').click();
      if (i === 0) {
        // Masked by default: the screenshot shows settings and a hidden value.
        await page.setViewportSize({ width: 1280, height: 1250 });
        await page.locator('.tool-card-wide').evaluate((el) => el.scrollIntoView({ block: 'start' }));
        await page.screenshot({ path: shotPath(testInfo, `keymesh-password-options-${locale}-desktop.png`) });
        await page.setViewportSize({ width: 1280, height: 900 });
      }
      const v = await revealGenerated(page, t);
      expect(verdict(v, 40, [noAmbiguous(UPPER), noAmbiguous(DIGITS), '#@!'])).toEqual(ok(3));
    }

    // Friendly validation before anything is generated.
    const error = page.getByTestId('password-options-error');
    const generate = page.getByTestId('generate-password');
    const save = page.getByTestId('save-password');
    await setChecks(page, { uppercase: false, symbols: false }); // digits only, look-alikes excluded
    await setLength(page, 8);
    await expect(error).toHaveText(t['errors.pwWeak']);
    await expect(generate).toBeDisabled();
    await expect(save).toBeDisabled();
    // Settings changes never regenerate; the old value is withdrawn as outdated.
    await expect(page.getByTestId('generated-password')).toHaveCount(0);
    await expect(page.getByTestId('generated-outdated')).toHaveText(t['gen.outdated']);
    await setLength(page, 22); // 8 digits left: 22 × 3 = 66 bits
    await expect(error).toHaveCount(0);
    await generate.click();
    expect(verdict(await revealGenerated(page, t), 22, [noAmbiguous(DIGITS)])).toEqual(ok(1));
    await setChecks(page, { digits: false });
    await expect(error).toHaveText(t['errors.pwNoClass']);
    await setChecks(page, { lowercase: true });
    await setLength(page, 14);
    await expect(error).toHaveCount(0);
    await generate.click();
    expect(verdict(await revealGenerated(page, t), 14, [noAmbiguous(LOWER)])).toEqual(ok(1));
    for (const bad of [7, 129, '']) {
      await setLength(page, bad);
      await expect(error).toHaveText(t['errors.pwLength']);
      await expect(opts(page).locator('[name=pwLength]')).toHaveAttribute('aria-invalid', 'true');
    }
    await setLength(page, 30);
    await setChecks(page, { symbols: true });
    for (const [set, key] of [
      ['ab', 'errors.pwSymbolChars'],
      ['! 1', 'errors.pwSymbolChars'],
      ['！', 'errors.pwSymbolChars'],
      ['', 'errors.pwSymbolsEmpty'],
      ['!'.repeat(65), 'errors.pwSymbolsLong'],
    ] as const) {
      await opts(page).locator('[name=pwSymbolSet]').fill(set);
      await expect(error).toHaveText(t[key]);
      await expect(generate).toBeDisabled();
    }
    await opts(page).getByRole('button', { name: t['pwopt.symbolReset'] }).click();
    await expect(opts(page).locator('[name=pwSymbolSet]')).toHaveValue(DEFAULT_SYMBOLS);
    await expect(error).toHaveCount(0);

    // Language and theme changes keep the settings and the shown value.
    await generate.click();
    const shown = await revealGenerated(page, t);
    await page.locator(`[data-testid=language-switch] [data-locale="${locale === 'en' ? 'zh-TW' : 'en'}"]`).click();
    await page.locator('[data-testid=theme-switch] [data-theme-option=dark]').click();
    expect((await page.getByTestId('generated-value').innerText()) === shown).toBe(true);
    await expect(opts(page).locator('[name=pwLength]')).toHaveValue('30');
    await expect(opts(page).locator('[name=pw-uppercase]')).not.toBeChecked();
    await page.locator(`[data-testid=language-switch] [data-locale="${locale}"]`).click();

    // Save stores exactly the shown preview; after an encrypted round trip
    // (lock, decrypt from storage) it is unchanged.
    await preset.selectOption('default');
    await setChecks(page, { lowercase: false, uppercase: false, symbols: false });
    await setLength(page, 30);
    await expect(save).toBeDisabled();
    await generate.click();
    const previewed = await revealGenerated(page, t);
    expect(verdict(previewed, 30, [DIGITS])).toEqual(ok(1));
    await save.click();
    await expect(page.locator('#detail-title')).toHaveText(t['gen.pw.defaultTitle']);
    const stored = await revealStored(page, t, t['field.secret']);
    expect(stored === previewed).toBe(true);
    await lockAndUnlock(page);
    await page.locator('.item-list button', { hasText: t['gen.pw.defaultTitle'] }).click();
    expect((await revealStored(page, t, t['field.secret'])) === previewed).toBe(true);

    // Locking discards a generated value that was on screen.
    await page.getByTestId('nav-generators').click();
    await expect(page.getByTestId('generated-password')).toHaveCount(0);
    expect(errors).toEqual([]);
    await context.close();
  });

  test(`${locale}: Login and Secret forms generate, apply only on request, and keep input`, async ({ browser }) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale);
    await page.getByTestId('new-item').click();
    await page.locator('[role=menuitem][data-kind=login]').click();
    const form = page.locator('form.item-form');
    await form.locator('[name=title]').fill('Synthetic generated login');
    await form.locator('[name=password]').fill('SYNTH-prior-pw');
    const opener = form.getByTestId('open-generator');
    await expect(opener).toHaveAttribute('aria-expanded', 'false');

    // Generate then Cancel: the field keeps its value.
    await opener.click();
    await expect(opener).toHaveAttribute('aria-expanded', 'true');
    const panel = form.getByTestId('form-generator');
    await expect(panel.getByTestId('form-use-password')).toBeDisabled();
    await panel.getByTestId('form-generate').click();
    await expect(panel.getByTestId('generated-value')).toContainText('•');
    await panel.getByTestId('form-generator-cancel').click();
    await expect(panel).toHaveCount(0);
    await expect(form.locator('[name=password]')).toHaveValue('SYNTH-prior-pw');

    // Custom settings; Enter in a settings field must not submit the form.
    await opener.click();
    await panel.locator('[name=pwLength]').fill('50');
    await panel.locator('[name=pwLength]').press('Enter');
    await expect(form).toBeVisible();
    await pwMore(panel);
    await panel.locator('[name=pwSymbolSet]').fill('-_');
    await panel.getByTestId('form-generate').click();
    const first = await revealGenerated(page, t);
    expect(verdict(first, 50, [LOWER, UPPER, DIGITS, '-_'])).toEqual(ok(4));
    // Changing a setting withdraws it: it can't be used for the new settings.
    await panel.locator('[name=pwLength]').fill('51');
    await expect(panel.getByTestId('generated-outdated')).toHaveText(t['gen.outdated']);
    await expect(panel.getByTestId('generated-password')).toHaveCount(0);
    await expect(panel.getByTestId('form-use-password')).toBeDisabled();
    await panel.locator('[name=pwLength]').fill('50');
    await panel.getByTestId('form-generate').click();
    const candidate = await revealGenerated(page, t);
    expect(candidate === first).toBe(false);
    expect(verdict(candidate, 50, [LOWER, UPPER, DIGITS, '-_'])).toEqual(ok(4));
    await expect(form.locator('[name=password]')).toHaveValue('SYNTH-prior-pw');

    // Switching language/theme keeps the form input, the panel and the candidate.
    await page.locator(`[data-testid=language-switch] [data-locale="${locale === 'en' ? 'zh-TW' : 'en'}"]`).click();
    await page.locator('[data-testid=theme-switch] [data-theme-option=dark]').click();
    await expect(form.locator('[name=title]')).toHaveValue('Synthetic generated login');
    expect((await panel.getByTestId('generated-value').innerText()) === candidate).toBe(true);
    await page.locator(`[data-testid=language-switch] [data-locale="${locale}"]`).click();

    // Use this password: field filled (still masked), panel closed.
    await panel.getByTestId('form-use-password').click();
    await expect(panel).toHaveCount(0);
    await expect(form.locator('[name=password]')).toHaveAttribute('type', 'password');
    expect((await form.locator('[name=password]').inputValue()) === candidate).toBe(true);
    await form.locator('button[type=submit]').click();
    await expect(page.locator('#detail-title')).toHaveText('Synthetic generated login');
    await lockAndUnlock(page);
    await page.locator('.item-list button', { hasText: 'Synthetic generated login' }).click();
    expect((await revealStored(page, t, t['field.password'])) === candidate).toBe(true);

    // Secret form uses the same shared settings (length 50, symbols "-_").
    await page.getByTestId('new-item').click();
    await page.locator('[role=menuitem][data-kind=secret]').click();
    await form.locator('[name=title]').fill('Synthetic generated token');
    await form.getByTestId('open-generator').click();
    await expect(panel.locator('[name=pwLength]')).toHaveValue('50');
    await panel.getByTestId('form-generate').click();
    const secret = await revealGenerated(page, t);
    await panel.getByTestId('form-use-password').click();
    await form.locator('button[type=submit]').click();
    await expect(page.locator('#detail-title')).toHaveText('Synthetic generated token');
    const storedSecret = await revealStored(page, t, t['field.secret']);
    expect(storedSecret === secret).toBe(true);
    expect(verdict(storedSecret, 50, [LOWER, UPPER, DIGITS, '-_'])).toEqual(ok(4));
    expect(errors).toEqual([]);
    await context.close();
  });

  test(`${locale}: password settings fit phones without horizontal overflow`, async ({ browser }, testInfo) => {
    for (const width of [320, 390]) {
      const { context, page } = await openVault(browser, locale, { width, height: 844 });
      await page.getByTestId('bnav-generators').click();
      await moreOptions(page);
      await noHorizontalOverflow(page, `generators ${width}px`);
      await opts(page).scrollIntoViewIfNeeded();
      if (width === 390) {
        await page.screenshot({ path: shotPath(testInfo, `keymesh-password-options-${locale}-mobile.png`), fullPage: true });
      }
      await page.getByTestId('bnav-items').click();
      await page.getByTestId('new-item').click();
      await page.locator('[role=menuitem][data-kind=login]').click();
      await page.getByTestId('open-generator').click();
      await page.getByTestId('form-generate').click();
      await noHorizontalOverflow(page, `login form generator ${width}px`);
      await context.close();
    }
  });
}
