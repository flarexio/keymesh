/**
 * Shared E2E helpers. SYNTHETIC DATA ONLY; the real build and real WASM core.
 */
import { expect, Page } from '@playwright/test';
import { en } from '../src/app/core/i18n/en';

/** Planted markers: must never appear in storage or exported bytes. */
export const M = {
  loginTitle: 'SYNTHMARK-TITLE-LOGIN',
  url: 'https://synthmark-url.example.test/login',
  password: 'SYNTHMARK-PW-0001',
  notes: 'SYNTHMARK-NOTES',
  recovery: 'SYNTHMARK-RC-1',
  customSecret: 'SYNTHMARK-CUSTOM-PIN',
  secret: 'SYNTHMARK-API-TOKEN',
  contactName: 'SYNTHMARK Ada',
  email: 'synthmark-ada@example.test',
  walletPhrase: 'SYNTHMARK alpha beta gamma',
  noteBody: 'SYNTHMARK-NOTE-BODY',
  totpSecret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
};
export const RFC_URI = `otpauth://totp/SynthIssuer:synth?secret=${M.totpSecret}&issuer=SynthIssuer&digits=8`;

export function assertNoMarkers(bytes: Buffer, what: string): void {
  const text = bytes.toString('utf8');
  const lower = text.toLowerCase();
  for (const [name, value] of Object.entries(M)) {
    expect(lower.includes(value.toLowerCase()), `${what} leaked ${name}`).toBe(false);
  }
  expect(text.startsWith('{'), `${what} is the JSON envelope`).toBe(true);
  expect(text).toContain('"format": "keymesh.vault"');
}

export async function storedBytes(page: Page): Promise<Buffer> {
  const arr = await page.evaluate(
    () =>
      new Promise<number[]>((resolve, reject) => {
        const r = indexedDB.open('keymesh-demo', 1);
        r.onerror = () => reject(r.error);
        r.onsuccess = () => {
          const g = r.result.transaction('vault').objectStore('vault').get('primary');
          g.onerror = () => reject(g.error);
          g.onsuccess = () => {
            resolve(g.result ? Array.from(g.result.bytes as Uint8Array) : []);
            r.result.close();
          };
        };
      }),
  );
  return Buffer.from(arr);
}

export async function browserStorageSummary(page: Page) {
  return page.evaluate(async () => ({
    dbs: (await indexedDB.databases()).map((d) => d.name),
    local: localStorage.length,
    session: sessionStorage.length,
    cookies: document.cookie,
  }));
}

export async function start(page: Page, mode: 'ephemeral' | 'synthetic-fixture') {
  await page.goto('/');
  await expect(page.getByTestId('demo-banner')).toContainText(en['demo.label']);
  await page.locator(`input[name=mode][value=${mode}]`).check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', mode);
}

export async function newItem(page: Page, kind: string) {
  await page.getByTestId('new-item').click();
  await page.locator(`[role=menuitem][data-kind=${kind}]`).click();
}

/** Accept the in-app confirmation dialog. */
export async function confirmDialog(page: Page) {
  await page.getByTestId('confirm-accept').click();
}

/** Select a category in the desktop sidebar ('' = all items). */
export async function category(page: Page, kind: string) {
  await page.getByTestId(`category-${kind || 'all'}`).click();
}

export const field = (page: Page, label: string) => page.getByLabel(label, { exact: true });

export async function create(page: Page, title: string) {
  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.locator('#detail-title')).toHaveText(title);
}

/** Auto-retrying locator for list titles (never snapshot the DOM). */
export const titles = (page: Page) => page.locator('.item-list .title');

export async function openItem(page: Page, title: string) {
  await page.locator('.item-list button', { hasText: title }).first().click();
  await expect(page.locator('#detail-title')).toHaveText(title);
}

