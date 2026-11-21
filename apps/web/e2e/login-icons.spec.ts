/**
 * Automatic local login icons in the list and detail view. SYNTHETIC DATA
 * ONLY; every request is checked to stay on the app's own origin.
 */
import { expect, test } from '@playwright/test';
import { create, newItem, openItem, start } from './helpers';

const rows: [title: string, url: string, icon: string, extra?: [string, string]][] = [
  ['Synthetic GitHub', 'https://github.com/login', 'brand', ['data-brand', 'github']],
  ['Synthetic Gmail', 'https://mail.google.com/mail/u/0', 'brand', ['data-brand', 'gmail']],
  ['Synthetic router', 'http://192.168.50.1/admin', 'private'],
  ['Synthetic NAS', 'https://nas.home.arpa', 'private'],
  ['玉山銀行 synthetic', '', 'category'],
  ['zebra synthetic', 'https://zebra-unknown.example.org', 'letter', ['data-tone', '']],
];

test('logins get a brand, private-host, category or letter icon chosen locally; nothing is fetched', async ({ page }) => {
  const requests: string[] = [];
  page.on('request', (r) => requests.push(r.url()));
  await start(page, 'synthetic-fixture');
  for (const [title, url] of rows) {
    await newItem(page, 'login');
    await page.locator('input[name=title]').fill(title);
    if (url) await page.locator('textarea[name=urls]').fill(url);
    await create(page, title);
  }
  for (const [title, , icon, extra] of rows) {
    const row = page.locator('.item-list li', { hasText: title });
    const tile = row.locator('km-item-icon > span');
    await expect(tile).toHaveAttribute('data-icon', icon);
    if (extra) await expect(tile).toHaveAttribute(extra[0], extra[1] ? extra[1] : /^[0-7]$/);
    if (icon === 'letter') await expect(tile).toHaveText('Z');
    // Decorative: the title is the accessible name.
    await expect(tile).toHaveAttribute('aria-hidden', 'true');
    // Something is actually drawn (never an empty tile).
    if (icon !== 'letter') expect(await tile.locator('svg path').count()).toBeGreaterThan(0);
  }
  await openItem(page, 'Synthetic GitHub');
  await expect(page.locator('.detail km-item-icon > span, #detail-title').first()).toBeVisible();
  await expect(page.locator('km-item-icon > span.kind-tile-lg')).toHaveAttribute('data-brand', 'github');
  // Other kinds keep their kind tile.
  await newItem(page, 'secure_note');
  await page.locator('input[name=title]').fill('Synthetic note');
  await page.locator('textarea[name=body]').fill('synthetic body');
  await create(page, 'Synthetic note');
  await expect(page.locator('.item-list li', { hasText: 'Synthetic note' }).locator('km-item-icon > span')).toHaveAttribute('data-icon', 'kind');

  const origin = new URL(page.url()).origin;
  expect(requests.filter((u) => !u.startsWith(origin + '/') && !u.startsWith('data:'))).toEqual([]);
});
