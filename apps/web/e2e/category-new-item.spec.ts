/**
 * "New item" inside a category creates that kind directly ("New login");
 * the kind menu is offered only on the all-items view. Desktop sidebar and
 * phone filter select, English and 中文. SYNTHETIC DATA ONLY.
 */
import { Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { zhTW } from '../src/app/core/i18n/zh-tw';
import { KINDS } from '../src/app/core/types';
import { category, pwMore, start } from './helpers';

function shot(info: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return info.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

const formKind = (page: Page) => page.locator('form.item-form .kind-tile-lg').getAttribute('data-kind');

test('desktop: each category button creates its own kind; All items keeps the menu', async ({ page }, info) => {
  await start(page, 'synthetic-fixture');
  const button = page.getByTestId('new-item');
  await expect(button).toHaveAttribute('aria-haspopup', 'menu');
  await expect(button).toHaveText(en['list.newItem']);
  for (const kind of KINDS) {
    await category(page, kind);
    await expect(button).toHaveText(en[`list.new.${kind}`]);
    await expect(button).not.toHaveAttribute('aria-haspopup', 'menu');
    await expect(button).not.toHaveAttribute('aria-expanded', /.*/);
    await button.click();
    await expect(page.locator('[role=menu]')).toHaveCount(0);
    await expect.poll(() => formKind(page)).toBe(kind);
    if (kind === 'login') await page.screenshot({ path: shot(info, 'category-new-item-login-en-desktop.png') });
  }
  await category(page, '');
  await expect(button).toHaveText(en['list.newItem']);
  await button.click();
  await expect(page.locator('[role=menuitem]')).toHaveCount(KINDS.length);
  await page.keyboard.press('Escape');
  await expect(page.locator('[role=menu]')).toHaveCount(0);
});

test('中文 phone: the filter select drives the same button (新增登入 / 新增 TOTP)', async ({ browser }, info) => {
  const ctx = await browser.newContext({ locale: 'zh-TW', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const page = await ctx.newPage();
  await page.goto('/');
  await expect(page.getByTestId('demo-banner')).toContainText(zhTW['demo.label']);
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
  const button = page.getByTestId('new-item');
  await page.getByTestId('kind-filter').selectOption('login');
  await expect(button).toHaveText(zhTW['list.new.login']);
  expect(zhTW['list.new.login']).toBe('新增登入');
  await page.screenshot({ path: shot(info, 'category-new-item-login-zh-TW-phone.png') });
  await button.click();
  await expect.poll(() => formKind(page)).toBe('login');
  // The form replaces the list on a phone: back to the list first.
  await page.getByTestId('back').click();
  await page.getByTestId('kind-filter').selectOption('totp');
  await expect(button).toHaveText(zhTW['list.new.totp']);
  await button.click();
  await expect(page.getByTestId('qr-import')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await ctx.close();
});

test('generator: preset and length in view, types under More options (screenshots)', async ({ browser }, info) => {
  for (const [name, viewport] of [
    ['desktop', { width: 1280, height: 900 }],
    ['phone', { width: 390, height: 844 }],
  ] as const) {
    const ctx = await browser.newContext({ viewport, isMobile: name === 'phone', hasTouch: name === 'phone' });
    const page = await ctx.newPage();
    await start(page, 'synthetic-fixture');
    await page.getByTestId(name === 'phone' ? 'bnav-generators' : 'nav-generators').click();
    const card = page.locator('.tool-card-wide');
    await expect(card.locator('[name=pwLength]')).toHaveValue('32');
    await expect(card.locator('[name=pw-symbols]')).toBeHidden();
    await page.screenshot({ path: shot(info, `generator-${name}-collapsed-en.png`), fullPage: true });
    await pwMore(card);
    await expect(card.locator('[name=pw-symbols]')).toBeChecked();
    await page.screenshot({ path: shot(info, `generator-${name}-expanded-en.png`), fullPage: true });
    await ctx.close();
  }
});
