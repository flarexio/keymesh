/**
 * Generator acceptance: the masked preview is exactly what Save stores (and
 * only once), outdated previews can't be saved, previews vanish on lock, a
 * failed save changes nothing, and only non-secret settings persist.
 * Real production build, real Rust/WASM core, 中文 and EN. SYNTHETIC DATA ONLY.
 *
 * Generated values are read but never printed: checks compare booleans.
 */
import { Browser, Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { zhTW } from '../src/app/core/i18n/zh-tw';
import { storedBytes, titles } from './helpers';

type Locale = 'zh-TW' | 'en';
type Catalog = Record<keyof typeof en, string>;
const catalog = (l: Locale): Catalog => (l === 'en' ? en : zhTW);
const SETTINGS_KEY = 'keymesh.password-settings.v1';

function shotPath(testInfo: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return testInfo.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

async function openVault(browser: Browser, locale: Locale, viewport = { width: 1280, height: 900 }) {
  const context = await browser.newContext({ locale: locale === 'en' ? 'en-US' : 'zh-TW', viewport });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('lock')).toBeVisible();
  return { context, page, errors };
}

const pwCard = (page: Page) => page.locator('.tool-card-wide');
const secretCard = (page: Page) => page.locator('section[aria-labelledby=gen-secret]');

/** Reveal a generated preview inside `scope` and read it (never printed). */
async function revealIn(scope: ReturnType<Page['locator']>, t: Catalog): Promise<string> {
  const row = scope.getByTestId('generated-password');
  await expect(row.getByTestId('generated-value')).toContainText('•');
  await row.getByRole('button', { name: t['secret.reveal'] }).click();
  await expect(row.getByTestId('generated-value')).not.toContainText('•');
  return row.getByTestId('generated-value').innerText();
}

async function revealStored(page: Page, t: Catalog): Promise<string> {
  const row = page.locator('km-secret-field', { hasText: t['field.secret'] });
  await row.getByRole('button', { name: t['secret.reveal'] }).click();
  await expect(row.getByTestId('secret-value')).not.toContainText('•');
  return row.getByTestId('secret-value').innerText();
}

async function unlockAgain(page: Page) {
  await expect(page.getByTestId('unlock')).toBeVisible();
  await page.getByTestId('unlock').click();
  await expect(page.getByTestId('lock')).toBeVisible();
}

/**
 * Hold the vault object store with a readwrite transaction on a second
 * connection, so the app's next write really waits inside IndexedDB.
 */
async function blockStorage(page: Page) {
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        const r = indexedDB.open('keymesh-demo', 1);
        r.onsuccess = () => {
          const db = r.result;
          const w = window as unknown as { __kmHold: boolean };
          w.__kmHold = true;
          const tx = db.transaction('vault', 'readwrite');
          const spin = () => {
            if (w.__kmHold) tx.objectStore('vault').get('primary').onsuccess = spin;
          };
          spin();
          tx.oncomplete = () => db.close();
          resolve();
        };
      }),
  );
}

async function releaseStorage(page: Page) {
  await page.evaluate(() => ((window as unknown as { __kmHold: boolean }).__kmHold = false));
}

async function localEntries(page: Page) {
  return page.evaluate(() => Object.fromEntries(Object.keys(localStorage).map((k) => [k, localStorage.getItem(k) ?? ''])));
}

/** Minimal probe that also runs on the old UI: the saved value must be the preview. */
test('the saved password is the one that was previewed', async ({ browser }) => {
  const { context, page } = await openVault(browser, 'en');
  await page.getByTestId('nav-generators').click();
  await page.getByTestId('generate-password').click();
  const shown = await revealIn(page.locator('.tool-card-wide'), en);
  await page.getByTestId('save-password').click();
  await expect(page.locator('#detail-title')).toHaveText(en['gen.pw.defaultTitle']);
  expect((await revealStored(page, en)) === shown, 'saved value equals the preview').toBe(true);
  await context.close();
});

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: Save stores exactly the shown preview, once; outdated previews can't be saved`, async ({ browser }, testInfo) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale);
    await page.getByTestId('nav-generators').click();
    const card = pwCard(page);
    const generate = page.getByTestId('generate-password');
    const save = page.getByTestId('save-password');

    // Nothing generated: Save is unavailable and the next step is stated.
    await expect(save).toBeDisabled();
    await expect(page.getByTestId('save-password-hint')).toHaveText(t['gen.pw.none']);
    await expect(save).toHaveText(t['gen.save']);

    // Custom settings, then a preview.
    await card.locator('[name=pwLength]').fill('36');
    await card.locator('[name=pwSymbolSet]').fill('-_');
    await card.locator('details.more-options summary').click();
    await card.locator('[name=pw-excludeAmbiguous]').check();
    const title = `Synthetic exact ${locale}`;
    await page.locator('#gen-pw-title').fill(title);
    await generate.click();
    const first = await revealIn(card, t);
    await expect(save).toBeEnabled();
    await expect(page.getByTestId('save-password-hint')).toHaveText(t['gen.pw.saveHint']);

    // A settings change withdraws the preview: it can't be saved as if it
    // matched the new settings.
    await card.locator('[name=pwLength]').fill('37');
    await expect(card.getByTestId('generated-outdated')).toHaveText(t['gen.outdated']);
    await expect(card.getByTestId('generated-password')).toHaveCount(0);
    await expect(save).toBeDisabled();
    await card.locator('[name=pwLength]').fill('36');
    await generate.click();
    const shown = await revealIn(card, t);
    expect(shown === first).toBe(false);
    expect([...shown].length === 36 && [...shown].every((c) => !'Il1O0o'.includes(c))).toBe(true);
    await page.setViewportSize({ width: 1280, height: 1300 });
    await card.evaluate((el) => el.scrollIntoView({ block: 'start' }));
    await page.screenshot({ path: shotPath(testInfo, `keymesh-generator-preview-${locale}-desktop.png`) });
    await page.setViewportSize({ width: 1280, height: 900 });

    // Double click: one item, holding exactly the previewed value.
    await save.dblclick();
    await expect(page.locator('#detail-title')).toHaveText(title);
    await expect(page.locator('.detail')).toContainText(t['detail.originGenerated']);
    expect((await revealStored(page, t)) === shown).toBe(true);
    await expect(titles(page).filter({ hasText: title })).toHaveCount(1);

    // Ciphertext only: the value is not in IndexedDB or Web Storage.
    const bytes = await storedBytes(page);
    expect(bytes.toString('utf8').includes(shown)).toBe(false);
    const local = await localEntries(page);
    expect(Object.keys(local)).toEqual([SETTINGS_KEY]);
    expect(Object.values(local).some((v) => v.includes(shown) || v.includes(first))).toBe(false);
    expect(JSON.parse(local[SETTINGS_KEY])).toEqual({
      preset: 'custom',
      options: {
        length: 36, lowercase: true, uppercase: true, digits: true, symbols: true,
        symbolSet: '-_', excludeAmbiguous: true, requireEachClass: true,
      },
    });

    // Encrypted round trip: lock, decrypt from storage, same value.
    await page.getByTestId('lock').click();
    await unlockAgain(page);
    await page.locator('.item-list button', { hasText: title }).click();
    expect((await revealStored(page, t)) === shown).toBe(true);

    // The saved preview was consumed: nothing left to save again.
    await page.getByTestId('nav-generators').click();
    await expect(page.getByTestId('generated-password')).toHaveCount(0);
    await expect(save).toBeDisabled();

    // Random secret: the same exact preview → save, kept as hex.
    const sc = secretCard(page);
    await expect(page.getByTestId('save-secret')).toBeDisabled();
    await page.getByTestId('generate-secret').click();
    const hex = await revealIn(sc, t);
    expect(/^[0-9a-f]{64}$/.test(hex)).toBe(true);
    await page.getByTestId('save-secret').click();
    await expect(page.locator('#detail-title')).toHaveText(t['gen.secret.defaultTitle']);
    expect((await revealStored(page, t)) === hex).toBe(true);
    expect(errors).toEqual([]);
    await context.close();
  });

  test(`${locale}: previews vanish on lock; settings persist across reloads, corrupt settings fall back`, async ({ browser }) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale);
    await page.getByTestId('nav-generators').click();
    const card = pwCard(page);
    await card.locator('[name=pwPreset]').selectOption('strong');
    await card.locator('[name=pw-symbols]').uncheck();
    await page.getByTestId('generate-password').click();
    await expect(card.getByTestId('generated-password')).toBeVisible();
    await page.getByTestId('generate-secret').click();

    // Lock while both previews are mounted: unlocking shows neither, and
    // nothing can be saved.
    await page.getByTestId('lock').click();
    await unlockAgain(page);
    await page.getByTestId('nav-generators').click();
    await expect(page.getByTestId('generated-password')).toHaveCount(0);
    await expect(page.getByTestId('save-password')).toBeDisabled();
    await expect(page.getByTestId('save-secret')).toBeDisabled();
    // Leaving the page drops a preview too.
    await page.getByTestId('generate-password').click();
    await page.getByTestId('nav-items').click();
    await page.getByTestId('nav-generators').click();
    await expect(page.getByTestId('generated-password')).toHaveCount(0);

    // Settings (not values) survive a reload.
    await page.reload();
    await page.getByRole('button', { name: t['start.stored.open'] }).click();
    await page.getByTestId('nav-generators').click();
    await expect(card.locator('[name=pwPreset]')).toHaveValue('custom');
    await expect(card.locator('[name=pwLength]')).toHaveValue('32');
    await expect(card.locator('[name=pw-symbols]')).not.toBeChecked();

    // Corrupt or tampered settings: defaults, no errors.
    for (const raw of ['{not json', JSON.stringify({ preset: 'custom', options: { length: 4 } })]) {
      await page.evaluate(([k, v]) => localStorage.setItem(k, v), [SETTINGS_KEY, raw]);
      await page.reload();
      await page.getByRole('button', { name: t['start.stored.open'] }).click();
      await page.getByTestId('nav-generators').click();
      await expect(card.locator('[name=pwPreset]')).toHaveValue('default');
      await expect(card.locator('[name=pwLength]')).toHaveValue('24');
    }
    expect(errors).toEqual([]);
    await context.close();
  });
}

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: lock while Save waits for storage: nothing is written, no success, item absent`, async ({ browser }) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale);
    await page.getByTestId('nav-generators').click();
    const title = `Synthetic pending ${locale}`;
    await page.locator('#gen-pw-title').fill(title);
    await page.getByTestId('generate-password').click();
    await expect(pwCard(page).getByTestId('generated-password')).toBeVisible();
    const before = await storedBytes(page);

    await blockStorage(page);
    await page.getByTestId('save-password').click();
    await expect(page.getByTestId('save-password')).toHaveText(t['gen.saving']);
    await page.getByTestId('lock').click();
    await expect(page.getByTestId('unlock')).toBeVisible();
    await releaseStorage(page);

    // The waiting write was cancelled at the storage boundary.
    await expect.poll(async () => (await storedBytes(page)).equals(before)).toBe(true);
    await page.waitForTimeout(300);
    expect((await storedBytes(page)).equals(before)).toBe(true);
    await expect(page.getByText(t['gen.pw.saved'])).toHaveCount(0);
    await unlockAgain(page);
    await expect(titles(page).filter({ hasText: title })).toHaveCount(0);
    await page.getByTestId('nav-generators').click();
    await expect(page.getByTestId('generated-password')).toHaveCount(0);
    expect(errors).toEqual([]);
    await context.close();
  });

  test(`${locale}: only settings the core accepts persist; rejected stored settings fall back`, async ({ browser }) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale);
    await page.getByTestId('nav-generators').click();
    const card = pwCard(page);
    const reopen = async () => {
      await page.reload();
      await page.getByRole('button', { name: t['start.stored.open'] }).click();
      await page.getByTestId('nav-generators').click();
    };
    const stored = async () => JSON.parse((await localEntries(page))[SETTINGS_KEY] ?? 'null');

    // Digits only, 24 characters: accepted by the core and saved.
    for (const f of ['lowercase', 'uppercase', 'symbols']) await card.locator(`[name=pw-${f}]`).uncheck();
    await expect(card.getByTestId('password-options-error')).toHaveCount(0);
    expect((await stored()).options).toMatchObject({ length: 24, digits: true, lowercase: false, symbols: false });

    // Weak (digits only, 8): shown with the core's message, kept on screen, not saved.
    await card.locator('[name=pwLength]').fill('8');
    await expect(card.getByTestId('password-options-error')).toHaveText(t['errors.pwWeak']);
    expect((await stored()).options.length).toBe(24);
    // Symbols on (default set) is accepted and saved; emptying the set is not.
    await card.locator('[name=pwLength]').fill('24');
    await card.locator('[name=pw-symbols]').check();
    await expect.poll(async () => (await stored()).options.symbols).toBe(true);
    await card.locator('[name=pwSymbolSet]').fill('');
    await expect(card.getByTestId('password-options-error')).toHaveText(t['errors.pwSymbolsEmpty']);
    expect((await stored()).options.symbolSet).not.toBe('');
    // All four types with symbol set "!" at 24 is accepted ...
    await card.locator('[name=pwSymbolSet]').fill('!');
    for (const f of ['lowercase', 'uppercase']) await card.locator(`[name=pw-${f}]`).check();
    const accepted = { length: 24, lowercase: true, uppercase: true, digits: true, symbols: true, symbolSet: '!' };
    expect((await stored()).options).toMatchObject(accepted);
    // ... but at 11 it is the reviewer's case: a 65.75-bit upper bound and
    // under 64 bits of min-entropy. Refused by the core, not saved.
    await card.locator('[name=pwLength]').fill('11');
    await expect(card.getByTestId('password-options-error')).toHaveText(t['errors.pwWeak']);
    expect((await stored()).options).toMatchObject(accepted);

    // Reload: the last accepted settings, not the rejected edit.
    await reopen();
    await expect(card.locator('[name=pwLength]')).toHaveValue('24');
    await expect(card.locator('[name=pwSymbolSet]')).toHaveValue('!');
    for (const f of ['lowercase', 'uppercase', 'digits', 'symbols']) await expect(card.locator(`[name=pw-${f}]`)).toBeChecked();
    await expect(card.getByTestId('password-options-error')).toHaveCount(0);

    // Well-formed stored settings that the core rejects fall back to defaults.
    for (const options of [
      { length: 8, lowercase: false, uppercase: false, digits: true, symbols: false, symbolSet: '!', excludeAmbiguous: false, requireEachClass: true },
      { length: 24, lowercase: true, uppercase: false, digits: false, symbols: true, symbolSet: '', excludeAmbiguous: false, requireEachClass: true },
      { length: 11, lowercase: true, uppercase: true, digits: true, symbols: true, symbolSet: '!', excludeAmbiguous: false, requireEachClass: true },
    ]) {
      await page.evaluate(([k, v]) => localStorage.setItem(k, v), [SETTINGS_KEY, JSON.stringify({ preset: 'custom', options })]);
      await reopen();
      await expect(card.locator('[name=pwPreset]')).toHaveValue('default');
      await expect(card.locator('[name=pwLength]')).toHaveValue('24');
      await expect(card.getByTestId('password-options-error')).toHaveCount(0);
    }
    expect(errors).toEqual([]);
    await context.close();
  });
}

test('blocked Web Storage: settings work for the page session, no errors', async ({ browser }) => {
  const context = await browser.newContext();
  await context.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', {
      get() {
        throw new DOMException('blocked', 'SecurityError');
      },
    });
  });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto('/');
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await page.getByTestId('nav-generators').click();
  await pwCard(page).locator('[name=pwLength]').fill('30');
  await page.getByTestId('generate-password').click();
  const shown = await revealIn(pwCard(page), en);
  await page.getByTestId('save-password').click();
  await expect(page.locator('#detail-title')).toHaveText(en['gen.pw.defaultTitle']);
  expect((await revealStored(page, en)) === shown && [...shown].length === 30).toBe(true);
  expect(errors).toEqual([]);
  await context.close();
});

test('a stale tab cannot save its preview; storage keeps the other tab’s data', async ({ context }) => {
  const a = await context.newPage();
  await a.goto('/');
  await a.locator('input[name=mode][value=synthetic-fixture]').check();
  await a.getByTestId('start-vault').click();
  const b = await context.newPage();
  await b.addInitScript(() => {
    // No cross-tab messages: B only learns of A's write from compare-and-swap.
    (window as unknown as { BroadcastChannel: unknown }).BroadcastChannel = undefined;
  });
  await b.goto('/');
  await b.getByRole('button', { name: en['start.stored.open'] }).click();
  await b.getByTestId('nav-generators').click();
  await b.getByTestId('generate-password').click();

  await a.getByTestId('nav-generators').click();
  await a.getByTestId('generate-password').click();
  await a.getByTestId('save-password').click();
  await expect(a.locator('#detail-title')).toHaveText(en['gen.pw.defaultTitle']);
  const after = await storedBytes(a);

  await b.getByTestId('save-password').click();
  await expect(b.getByRole('alert').filter({ hasText: en['errors.conflict'] }).first()).toBeVisible();
  await expect(b.getByTestId('save-password')).toBeDisabled();
  expect((await storedBytes(b)).equals(after)).toBe(true);
  await b.getByRole('button', { name: en['shell.reload'] }).click();
  await expect(titles(b)).toHaveText([en['gen.pw.defaultTitle']]);
});

for (const locale of ['zh-TW', 'en'] as const) {
  test(`${locale}: phone layout for preview, save hint and outdated note`, async ({ browser }, testInfo) => {
    const t = catalog(locale);
    const { context, page, errors } = await openVault(browser, locale, { width: 390, height: 844 });
    await page.getByTestId('bnav-generators').click();
    await page.getByTestId('generate-password').click();
    await expect(page.getByTestId('save-password-hint')).toHaveText(t['gen.pw.saveHint']);
    await pwCard(page).getByTestId('generated-password').scrollIntoViewIfNeeded();
    const fits = await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
    expect(fits, 'no horizontal overflow').toBe(true);
    await page.screenshot({ path: shotPath(testInfo, `keymesh-generator-preview-${locale}-mobile.png`), fullPage: true });
    await pwCard(page).locator('[name=pw-digits]').uncheck();
    await expect(pwCard(page).getByTestId('generated-outdated')).toBeVisible();
    await pwCard(page).getByTestId('generated-outdated').scrollIntoViewIfNeeded();
    await page.screenshot({ path: shotPath(testInfo, `keymesh-generator-outdated-${locale}-mobile.png`) });
    expect(errors).toEqual([]);
    await context.close();
  });
}
