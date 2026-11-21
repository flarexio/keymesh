/**
 * Optional website icons (M5 C3), browser side. The test server runs with
 * the route OFF (KEYMESH_FAVICON unset), so every /api/favicon request is
 * answered 404 by the real server, unless a test stubs it in the page with a
 * fixed synthetic PNG. No outbound request is ever made. SYNTHETIC DATA ONLY.
 */
import { Page, expect, test } from '@playwright/test';
import { field, newItem, create, openItem } from './helpers';

test.use({ serviceWorkers: 'block' });

const PNG_1x1 = Buffer.from(
  '89504e470d0a1a0a0000000d4948445200000001000000010806000000' + '1f15c4890000000d49444154789c6360f8cfc0f01f0005000201' + 'e4f7b0a70000000049454e44ae426082',
  'hex',
);

async function loginItem(page: Page, title: string, url: string) {
  await newItem(page, 'login');
  await field(page, 'Title').fill(title);
  await field(page, 'URLs').fill(url);
  await create(page, title);
}

async function setup(page: Page) {
  const asked: string[] = [];
  page.on('request', (r) => {
    if (r.url().includes('/api/favicon')) asked.push(r.url());
  });
  await page.goto('/');
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('lock')).toBeVisible();
  await loginItem(page, 'Synthetic shop', 'https://shop.synthetic-favicon.org/account?id=SECRETMARK');
  await loginItem(page, 'Synthetic NAS', 'https://nas.local/admin');
  await loginItem(page, 'Synthetic internal', 'https://wiki.corp.cloud/');
  return asked;
}

test('off by default: viewing items asks nothing', async ({ page }) => {
  const asked = await setup(page);
  await openItem(page, 'Synthetic shop');
  await openItem(page, 'Synthetic NAS');
  expect(asked).toEqual([]);
});

test('opted in: only the viewed item, only its public host, nothing else; private hosts never', async ({ page }) => {
  const asked = await setup(page);
  await page.route('**/api/favicon?*', (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG_1x1 }));
  await page.getByTestId('nav-backup').click();
  await page.getByTestId('favicon-optin').check();
  expect(await page.evaluate(() => localStorage.getItem('keymesh.favicon.v1'))).toBe('1');
  await page.getByTestId('nav-items').click();
  expect(asked).toEqual([]); // the list never asks
  await openItem(page, 'Synthetic shop');
  await expect(page.locator('.detail-head [data-icon="remote"] img')).toBeVisible();
  await openItem(page, 'Synthetic NAS');
  await expect(page.locator('.detail-head [data-icon="private"]')).toBeVisible();
  await openItem(page, 'Synthetic internal'); // a name the server refuses is never even asked
  await expect(page.locator('.detail-head [data-icon="remote"]')).toHaveCount(0);
  expect(asked.length).toBe(1);
  const u = new URL(asked[0]);
  expect(u.pathname).toBe('/api/favicon');
  expect([...u.searchParams.keys()]).toEqual(['host']);
  expect(u.searchParams.get('host')).toBe('shop.synthetic-favicon.org');
  expect(asked[0]).not.toContain('SECRETMARK');
  expect(asked[0]).not.toContain('account');
});

test('opted in but the server has the route off: 404, the local icon stays', async ({ page }) => {
  await setup(page);
  await page.getByTestId('nav-backup').click();
  await page.getByTestId('favicon-optin').check();
  await page.getByTestId('nav-items').click();
  const res = page.waitForResponse((r) => r.url().includes('/api/favicon'));
  await openItem(page, 'Synthetic shop');
  expect((await res).status()).toBe(404);
  await expect(page.locator('.detail-head [data-icon="remote"]')).toHaveCount(0);
  await expect(page.locator('.detail-head .kind-tile')).toBeVisible();
});
