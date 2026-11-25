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

/** Stored envelope bytes (empty if none); never creates the database. */
export async function storedBytes(page: Page, db = 'keymesh-demo'): Promise<Buffer> {
  const arr = await page.evaluate(
    (name) =>
      new Promise<number[]>((resolve, reject) => {
        let missing = false;
        const r = indexedDB.open(name, 1);
        r.onupgradeneeded = () => {
          missing = true;
          r.transaction?.abort();
        };
        r.onerror = () => (missing ? resolve([]) : reject(r.error));
        r.onsuccess = () => {
          const g = r.result.transaction('vault').objectStore('vault').get('primary');
          g.onerror = () => reject(g.error);
          g.onsuccess = () => {
            resolve(g.result ? Array.from(g.result.bytes as Uint8Array) : []);
            r.result.close();
          };
        };
      }),
    db,
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

/** One item of every kind, with planted markers in every secret field. */
export async function createAllKinds(page: Page) {
  // Login with secrets, notes, recovery code and a concealed custom field.
  await newItem(page, 'login');
  await field(page, 'Title').fill(M.loginTitle);
  await field(page, 'Username').fill('synth-user');
  await field(page, 'Password').fill(M.password);
  await field(page, 'URLs').fill(M.url);
  await field(page, 'Recovery codes').fill(M.recovery);
  await field(page, 'Tags').fill('synthetic, e2e');
  await field(page, 'Notes').fill(M.notes);
  await page.getByRole('button', { name: 'Add custom field' }).click();
  await field(page, 'Label').fill('backup pin');
  await field(page, 'Value').fill(M.customSecret);
  await field(page, 'Concealed').check();
  await create(page, M.loginTitle);

  await newItem(page, 'secret');
  await field(page, 'Title').fill('Synthetic API credential');
  await field(page, 'Secret / API credential').fill(M.secret);
  await field(page, 'Service').fill('api.example.test');
  await create(page, 'Synthetic API credential');

  await newItem(page, 'contact');
  await field(page, 'Title').fill('Synthetic contact');
  await field(page, 'Full name').fill(M.contactName);
  await field(page, 'Organization').fill('Example Org');
  await field(page, 'Emails').fill(`work | ${M.email}\nhome@example.test`);
  await field(page, 'Phones').fill('+1 555 0100\nmobile | +1 555 0199');
  await create(page, 'Synthetic contact');
  await expect(page.locator('.detail')).toContainText(M.email);
  await expect(page.locator('.detail')).toContainText('+1 555 0199');

  await newItem(page, 'crypto_wallet');
  await field(page, 'Title').fill('Synthetic wallet');
  await field(page, 'Network').fill('testnet');
  await field(page, 'Wallet addresses').fill('synthetic-addr-1');
  await field(page, 'Recovery phrase').fill(M.walletPhrase);
  await create(page, 'Synthetic wallet');

  await newItem(page, 'secure_note');
  await field(page, 'Title').fill('Synthetic note');
  await field(page, 'Note').fill(M.noteBody);
  await create(page, 'Synthetic note');

  await newItem(page, 'totp');
  await field(page, 'Title').fill('Synthetic TOTP');
  await field(page, 'otpauth:// URI or Base32 secret').fill(RFC_URI);
  await create(page, 'Synthetic TOTP');

  await newItem(page, 'ed25519_key');
  await field(page, 'Title').fill('Synthetic Ed25519');
  await field(page, 'Comment').fill('synthetic@e2e');
  await create(page, 'Synthetic Ed25519');
  await expect(page.locator('.detail')).toContainText('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5');
}

/**
 * The app on a NON-loopback name (mapped to 127.0.0.1 by the browser's
 * host-resolver rule), on the configured test port: a plain-HTTP origin that
 * is not a secure context, like the LAN/VPN previews.
 */
export function insecureOrigin(baseURL: string | undefined): string {
  return `http://keymesh-http.test:${new URL(baseURL ?? 'http://127.0.0.1:4310').port}/`;
}

/**
 * Expand "More options" on the locked password-vault screen, where delete, the
 * demo vault, restore, the overview and the limits are collapsed by default.
 */
export async function openMore(page: Page): Promise<void> {
  const more = page.getByTestId('more-options');
  if ((await more.getAttribute('open')) === null) await page.getByTestId('more-options-toggle').click();
  await expect(more).toHaveAttribute('open', '');
}
