/**
 * Secret clipboard (review M-2), production build in Chromium: a copied
 * secret is cleared after 30 s and on lock, only if the clipboard still holds
 * it (read allowed) or by a best-effort overwrite (read not allowed); copying
 * the recovery code asks first. Playwright's clock drives the countdown.
 * SYNTHETIC DATA ONLY; recovery codes are never printed or captured.
 */
import { BrowserContext, Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { M, createAllKinds, openItem, start } from './helpers';

test.use({ serviceWorkers: 'block' });

function shot(info: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return info.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

const board = (page: Page) => page.evaluate(() => navigator.clipboard.readText());

async function copyLoginPassword(page: Page) {
  await page.clock.install();
  await start(page, 'synthetic-fixture');
  await createAllKinds(page);
  await openItem(page, M.loginTitle);
  await page.locator('km-secret-field', { hasText: 'Password' }).getByRole('button', { name: 'Copy' }).click();
}

async function grant(context: BrowserContext, perms: string[]) {
  await context.clearPermissions();
  await context.grantPermissions(perms);
}

test('copied password: countdown, then cleared after 30 s (read allowed: it was still ours)', async ({ page, context }, info) => {
  await grant(context, ['clipboard-read', 'clipboard-write']);
  await copyLoginPassword(page);
  expect(await board(page)).toBe(M.password);
  const status = page.getByTestId('clipboard-status');
  await expect(status).toBeVisible();
  await expect(status).toHaveAttribute('data-seconds', '30');
  await expect(page.getByTestId('clipboard-live')).toHaveText(en['clipboard.copied'].replace('{n}', '30'));
  // The fake clock freezes CSS animation timelines, so the toast's entrance
  // would stay at its first (transparent) frame; switch it off to capture it.
  await page.addStyleTag({ content: '.toast { animation: none !important; }' });
  expect(await status.evaluate((el) => getComputedStyle(el).opacity)).toBe('1');
  await page.screenshot({ path: shot(info, 'clipboard-countdown-en.png') });
  await page.clock.runFor(10_000);
  await expect(status).toHaveAttribute('data-seconds', '20');
  await page.clock.runFor(20_000);
  await expect(status).toHaveCount(0);
  await expect.poll(() => board(page)).toBe('');
  await expect(page.getByTestId('clipboard-live')).toHaveText(en['clipboard.cleared']);
});

test('the user copied something else meanwhile: left alone', async ({ page, context }) => {
  await grant(context, ['clipboard-read', 'clipboard-write']);
  await copyLoginPassword(page);
  await page.evaluate(() => navigator.clipboard.writeText('synthetic text the user copied later'));
  await page.clock.runFor(31_000);
  await expect(page.getByTestId('clipboard-live')).toHaveText(en['clipboard.changed']);
  expect(await board(page)).toBe('synthetic text the user copied later');
});

test('read not allowed: no read, best-effort overwrite after 30 s; "Clear now" and lock clear at once', async ({ page, context }) => {
  await grant(context, ['clipboard-write']);
  await copyLoginPassword(page);
  await page.clock.runFor(31_000);
  await expect(page.getByTestId('clipboard-status')).toHaveCount(0);
  await context.grantPermissions(['clipboard-read']); // only so the test can look
  expect(await board(page)).toBe('');

  // Clear now.
  await page.locator('km-secret-field', { hasText: 'Password' }).getByRole('button', { name: 'Copy' }).click();
  expect(await board(page)).toBe(M.password);
  await page.getByTestId('clipboard-clear-now').click();
  await expect.poll(() => board(page)).toBe('');

  // Lock.
  await page.locator('km-secret-field', { hasText: 'Password' }).getByRole('button', { name: 'Copy' }).click();
  expect(await board(page)).toBe(M.password);
  await page.getByTestId('lock').click();
  await expect.poll(() => board(page)).toBe('');
  await expect(page.getByTestId('clipboard-status')).toHaveCount(0);
});

test('copying the recovery code asks first; Cancel copies nothing; the copy is cleared after 30 s', async ({ page, context }, info) => {
  test.setTimeout(120_000);
  await grant(context, ['clipboard-read', 'clipboard-write']);
  await page.clock.install();
  await page.goto('/');
  await page.evaluate(() => navigator.clipboard.writeText('synthetic placeholder'));
  await page.getByTestId('create-password').fill('synthetic clipboard passphrase one');
  await page.getByTestId('create-password-confirm').fill('synthetic clipboard passphrase one');
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const copy = page.getByTestId('recovery-step').getByRole('button', { name: en['protected.recovery.copy'] });
  await copy.click();
  const dialog = page.getByRole('dialog');
  await expect(dialog).toContainText(en['clipboard.warnTitle']);
  await expect(dialog).toContainText(en['clipboard.warnBody']);
  // The recovery code is not rendered at all in this capture (hidden and
  // transparent), so no mask box has to cover the dialog in front of it.
  await page.screenshot({
    path: shot(info, 'clipboard-recovery-warning-en.png'),
    style: '[data-testid=recovery-code], [data-testid=recovery-code] * { visibility: hidden !important; color: transparent !important; }',
  });
  await dialog.getByRole('button', { name: en['common.cancel'] }).click();
  expect(await board(page)).toBe('synthetic placeholder');
  await copy.click();
  await page.getByRole('dialog').getByRole('button', { name: en['clipboard.warnConfirm'] }).click();
  // The copied text is the code (compared without printing it).
  const code = await page.getByTestId('recovery-code').last().evaluate((el) => Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'));
  expect((await board(page)) === code).toBe(true);
  await expect(page.getByTestId('clipboard-status')).toBeVisible();
  await page.clock.runFor(31_000);
  await expect.poll(() => board(page)).toBe('');
});
