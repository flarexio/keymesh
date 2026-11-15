/**
 * Auto-lock (M5 C2) in the production build, real WASM. Playwright's clock
 * fakes Date/performance; the system time is JUMPED (setSystemTime fires no
 * timers), and each check is triggered right away by a real lifecycle event
 * or input. (Pausing timers would also stall Angular's rendering.) That
 * locks happen from checks without any timer is proven deterministically in
 * core/auto-lock.spec.ts. Visibility is simulated by overriding
 * `document.visibilityState` and dispatching the real event types; this is
 * not a real OS app switch or freeze. SYNTHETIC DATA ONLY.
 */
import { Page, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { M, openItem, createAllKinds } from './helpers';

test.use({ serviceWorkers: 'block' });

async function openDemo(page: Page) {
  await page.clock.install({ time: new Date('2026-11-16T10:00:00Z') });
  await page.goto('/');
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('lock')).toBeVisible();
}

async function setVisibility(page: Page, state: 'hidden' | 'visible') {
  await page.evaluate((s) => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => s });
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => s === 'hidden' });
    document.dispatchEvent(new Event('visibilitychange'));
  }, state);
}

const locked = (page: Page) => expect(page.getByTestId('lock')).toHaveCount(0);

test('hidden past the grace period: locked on return, before the item renders again', async ({ page }) => {
  await openDemo(page);
  await createAllKinds(page);
  await openItem(page, M.loginTitle);
  await setVisibility(page, 'hidden');
  await page.clock.setSystemTime(new Date(Date.parse(await page.evaluate(() => new Date().toISOString())) + 35_000));
  await setVisibility(page, 'visible');
  await locked(page);
  await expect(page.getByTestId('autolock-reason')).toHaveAttribute('data-reason', 'hidden');
  await expect(page.getByTestId('autolock-reason')).toContainText(en['autolock.reason.hidden']);
  await expect(page.locator('.detail')).toHaveCount(0);
  await expect(page.getByText(M.loginTitle)).toHaveCount(0);
});

test('short hide then active use: no lock; a later hide counts from its own start', async ({ page }) => {
  await openDemo(page);
  const t0 = Date.parse(await page.evaluate(() => new Date().toISOString()));
  await setVisibility(page, 'hidden');
  await page.clock.setSystemTime(new Date(t0 + 10_000));
  await setVisibility(page, 'visible');
  await page.clock.setSystemTime(new Date(t0 + 45_000)); // past the first hide's 30 s
  await page.getByTestId('search').click();
  await expect(page.getByTestId('lock')).toBeVisible();
});

test('first input after the idle deadline locks instead of extending the session', async ({ page }) => {
  await openDemo(page);
  await page.clock.setSystemTime(new Date(Date.parse(await page.evaluate(() => new Date().toISOString())) + 5 * 60_000 + 5_000));
  await page.getByTestId('search').click({ force: true });
  await locked(page);
  await expect(page.getByTestId('autolock-reason')).toHaveAttribute('data-reason', 'idle');
});

test('pagehide locks; wall clock moved backwards locks', async ({ page }) => {
  await openDemo(page);
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await locked(page);
  await expect(page.getByTestId('autolock-reason')).toHaveAttribute('data-reason', 'pagehide');
  await page.getByTestId('unlock').click();
  await expect(page.getByTestId('lock')).toBeVisible();
  await expect(page.getByTestId('autolock-reason')).toHaveCount(0);
  await page.clock.setSystemTime(new Date(Date.parse(await page.evaluate(() => new Date().toISOString())) - 10 * 60_000));
  await page.getByTestId('search').click({ force: true });
  await locked(page);
  await expect(page.getByTestId('autolock-reason')).toHaveAttribute('data-reason', 'clock');
});

test('settings: "immediately" locks on hide; "never" idle shows a warning and persists', async ({ page }) => {
  await openDemo(page);
  await page.getByTestId('nav-backup').click();
  await page.getByTestId('autolock-idle').selectOption('0');
  await expect(page.getByTestId('autolock-never-warning')).toBeVisible();
  await page.getByTestId('autolock-hide').selectOption('0');
  expect(await page.evaluate(() => localStorage.getItem('keymesh.autolock.v1'))).toBe('{"idleMinutes":0,"hideSeconds":0}');
  await page.clock.setSystemTime(new Date(Date.parse(await page.evaluate(() => new Date().toISOString())) + 2 * 3600_000)); // hours idle: "never"
  await page.getByTestId('autolock-idle').click();
  await expect(page.getByTestId('lock')).toBeVisible();
  await setVisibility(page, 'hidden');
  await locked(page); // synchronously in the handler
});

// Regression (review): the hide select once SHOWED "immediately" while the
// real setting was 30 s (select value bound before its options existed).
// The displayed value must match what actually happens.
test('desktop: the settings card shows the real defaults (5 min, 30 s), and a short hide does not lock', async ({ page }) => {
  await openDemo(page);
  await page.getByTestId('nav-backup').click();
  await expect(page.getByTestId('autolock-idle')).toHaveValue('5');
  await expect(page.getByTestId('autolock-hide')).toHaveValue('30');
  await setVisibility(page, 'hidden');
  await setVisibility(page, 'visible');
  await expect(page.getByTestId('lock')).toBeVisible();
});

test('中文 touch device: default "immediately" is shown AND locks on hide; reason on the start screen', async ({ browser }) => {
  const ctx = await browser.newContext({ locale: 'zh-TW', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, serviceWorkers: 'block' });
  const page = await ctx.newPage();
  await openDemo(page);
  expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);
  await page.getByTestId('bnav-backup').click();
  await expect(page.getByTestId('autolock-section')).toBeVisible();
  await expect(page.getByTestId('autolock-hide')).toHaveValue('0');
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (dir) mkdirSync(dir, { recursive: true });
  await page.getByTestId('autolock-section').scrollIntoViewIfNeeded();
  if (dir) await page.screenshot({ path: join(dir, 'm5c-autolock-card-zh-TW-mobile.png') });
  await setVisibility(page, 'hidden');
  await locked(page); // synchronously in the hide handler
  await setVisibility(page, 'visible');
  await expect(page.getByTestId('autolock-reason')).toHaveAttribute('data-reason', 'hidden');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  if (dir) await page.screenshot({ path: join(dir, 'm5c-autolock-reason-zh-TW-mobile.png'), fullPage: true });
  await ctx.close();
});
