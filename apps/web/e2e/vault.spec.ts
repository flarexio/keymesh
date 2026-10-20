/**
 * End-to-end tests against the production build and the real compiled
 * Rust/WASM core in headless Chromium. SYNTHETIC DATA ONLY. No request
 * interception, no mocked crypto. Time is controlled with Playwright's clock.
 */
import { expect, Page, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

/** Planted markers: must never appear in storage or exported bytes. */
const M = {
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
const RFC_URI = `otpauth://totp/SynthIssuer:synth?secret=${M.totpSecret}&issuer=SynthIssuer&digits=8`;

function assertNoMarkers(bytes: Buffer, what: string): void {
  const text = bytes.toString('utf8');
  const lower = text.toLowerCase();
  for (const [name, value] of Object.entries(M)) {
    expect(lower.includes(value.toLowerCase()), `${what} leaked ${name}`).toBe(false);
  }
  expect(text.startsWith('{'), `${what} is the JSON envelope`).toBe(true);
  expect(text).toContain('"format": "keymesh.vault"');
}

async function storedBytes(page: Page): Promise<Buffer> {
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

async function browserStorageSummary(page: Page) {
  return page.evaluate(async () => ({
    dbs: (await indexedDB.databases()).map((d) => d.name),
    local: localStorage.length,
    session: sessionStorage.length,
    cookies: document.cookie,
  }));
}

async function start(page: Page, mode: 'ephemeral' | 'synthetic-fixture') {
  await page.goto('/');
  await expect(page.getByTestId('demo-banner')).toContainText('NOT PRODUCTION');
  await page.locator(`input[name=mode][value=${mode}]`).check();
  await page.getByRole('button', { name: 'Start demo vault' }).click();
  await expect(page.getByTestId('key-mode')).toContainText(mode);
}

async function newItem(page: Page, kind: string) {
  await page.getByTestId('new-item').selectOption(kind);
}

const field = (page: Page, label: string) => page.getByLabel(label, { exact: true });

async function create(page: Page, title: string) {
  await page.getByRole('button', { name: 'Create' }).click();
  await expect(page.locator('#detail-title')).toHaveText(title);
}

/** Auto-retrying locator for list titles (never snapshot the DOM). */
const titles = (page: Page) => page.locator('.item-list .title');

async function openItem(page: Page, title: string) {
  await page.locator('.item-list button', { hasText: title }).first().click();
  await expect(page.locator('#detail-title')).toHaveText(title);
}

async function createAllKinds(page: Page) {
  // Login with secrets, notes, recovery code and a concealed custom field.
  await newItem(page, 'login');
  await field(page, 'Title').fill(M.loginTitle);
  await field(page, 'Username').fill('synth-user');
  await field(page, 'Password').fill(M.password);
  await field(page, 'URLs (one per line)').fill(M.url);
  await field(page, 'Recovery codes (one per line)').fill(M.recovery);
  await field(page, 'Tags (comma separated)').fill('synthetic, e2e');
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
  await field(page, 'Addresses (one per line)').fill('synthetic-addr-1');
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

test('full vault flow: create, generate, edit, search, lock, unlock, persist, backup, restore', async ({
  page,
  context,
}, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const requests: string[] = [];
  page.on('request', (r) => requests.push(r.url()));

  await start(page, 'synthetic-fixture');
  await createAllKinds(page);
  await expect(titles(page)).toHaveCount(7);

  // Masked by default, explicit reveal, copy without rendering.
  await openItem(page, M.loginTitle);
  await expect(page.locator('.detail')).not.toContainText(M.password);
  const pwRow = page.locator('km-secret-field', { hasText: 'Password' });
  await pwRow.getByRole('button', { name: 'Copy' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(M.password);
  await expect(page.locator('.detail')).not.toContainText(M.password);
  await pwRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(pwRow).toContainText(M.password);
  const pinRow = page.locator('km-secret-field', { hasText: 'backup pin' });
  await pinRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(pinRow).toContainText(M.customSecret);
  // Secrets never land in DOM attributes.
  const attrs = await page.evaluate(() =>
    Array.from(document.querySelectorAll('*')).flatMap((el) =>
      Array.from(el.attributes).map((a) => a.value),
    ),
  );
  expect(attrs.some((v) => v.includes('SYNTHMARK-PW') || v.includes('SYNTHMARK-CUSTOM'))).toBe(false);

  // Generators: values created inside WASM and stored as encrypted items.
  await page.getByRole('button', { name: 'Generators' }).click();
  await page.getByRole('button', { name: 'Generate & save as Secret' }).first().click();
  await expect(page.locator('#detail-title')).toHaveText('Generated password');
  await expect(page.locator('.detail')).toContainText('generated locally (not provider-issued)');
  const genRow = page.locator('km-secret-field', { hasText: 'Secret' });
  await genRow.getByRole('button', { name: 'Reveal' }).click();
  // Revealed: exactly 24 non-space characters (default profile).
  await expect(genRow.getByTestId('secret-value')).toHaveText(/^\s*\S{24}\s*$/);
  await page.getByRole('button', { name: 'Generators' }).click();
  await page.getByRole('button', { name: 'Generate & save as Secret' }).nth(1).click();
  await expect(page.locator('#detail-title')).toHaveText('Generated secret');
  const hexRow = page.locator('km-secret-field', { hasText: 'Secret' });
  await hexRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(hexRow.getByTestId('secret-value')).toHaveText(/^\s*[0-9a-f]{64}\s*$/);
  await page.getByRole('button', { name: 'Generators' }).click();
  await expect(page.getByRole('button', { name: 'Generate passphrase' })).toBeDisabled();
  await page.getByRole('button', { name: 'Generate & save key' }).click();
  await expect(page.locator('#detail-title')).toHaveText('Generated Ed25519 key');
  await expect(page.locator('.detail')).toContainText('ssh-ed25519 ');
  await expect(titles(page)).toHaveCount(10);

  // Edit (blank secret keeps the stored value) and search.
  await openItem(page, M.loginTitle);
  await page.getByRole('button', { name: 'Edit' }).click();
  await field(page, 'Title').fill(`${M.loginTitle} edited`);
  await field(page, 'Username').fill('synth-user-2');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.locator('#detail-title')).toHaveText(`${M.loginTitle} edited`);
  await expect(page.locator('.detail')).toContainText('Revision 2');
  const pw2 = page.locator('km-secret-field', { hasText: 'Password' });
  await pw2.getByRole('button', { name: 'Reveal' }).click();
  await expect(pw2).toContainText(M.password);
  await page.getByTestId('search').fill('synthmark-url');
  await expect(titles(page)).toHaveText([`${M.loginTitle} edited`]);
  await page.getByTestId('search').fill('');
  await page.getByTestId('kind-filter').selectOption('secret');
  await expect(titles(page)).toHaveCount(3);
  await page.getByTestId('kind-filter').selectOption('');

  // Delete.
  await openItem(page, 'Synthetic note');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.locator('.item-list')).not.toContainText('Synthetic note');
  await expect(titles(page)).toHaveCount(9);

  // Storage holds only the encrypted envelope.
  assertNoMarkers(await storedBytes(page), 'IndexedDB');
  const storage = await browserStorageSummary(page);
  expect(storage).toEqual({ dbs: ['keymesh-demo'], local: 0, session: 0, cookies: '' });

  // Screenshot of the running UI with synthetic data.
  await openItem(page, 'Synthetic TOTP');
  await page.setViewportSize({ width: 1280, height: 860 });
  const shot = process.env['KEYMESH_SCREENSHOT'] ?? testInfo.outputPath('keymesh-ui.png');
  await page.screenshot({ path: shot, fullPage: true });
  // Phone width: no horizontal page scroll.
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.screenshot({ path: shot.replace(/\.png$/, '-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1280, height: 860 });

  // Lock: secrets and titles leave the DOM; operations are unavailable.
  await openItem(page, `${M.loginTitle} edited`);
  await page.locator('km-secret-field', { hasText: 'Password' }).getByRole('button', { name: 'Reveal' }).click();
  await expect(page.locator('.detail')).toContainText(M.password);
  await page.getByTestId('lock').click();
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  const lockedHtml = await page.content();
  for (const v of [M.password, M.loginTitle, 'Synthetic wallet', 'synth-user']) {
    expect(lockedHtml.includes(v), `locked DOM contains ${v}`).toBe(false);
  }
  await expect(page.getByTestId('search')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Generators' })).toHaveCount(0);

  // Demo unlock (test-provider transition, not app identity).
  await page.getByRole('button', { name: 'Unlock demo session' }).click();
  await expect(titles(page)).toHaveCount(9);

  // A mutation started immediately before lock is rejected, not applied.
  await newItem(page, 'secure_note');
  await field(page, 'Title').fill('SYNTHMARK-RACE');
  await field(page, 'Note').fill('race');
  await page.evaluate(() => {
    (document.querySelector('form.item-form button[type=submit]') as HTMLButtonElement).click();
    (document.querySelector('[data-testid=lock]') as HTMLButtonElement).click();
  });
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await page.getByRole('button', { name: 'Unlock demo session' }).click();
  await expect(page.locator('.item-list')).not.toContainText('SYNTHMARK-RACE');
  await expect(titles(page)).toHaveCount(9);

  // Persistence across reload (synthetic fixture key reopens).
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Stored demo vault found' })).toBeVisible();
  await page.getByRole('button', { name: 'Open with synthetic fixture key (test harness)' }).click();
  await expect(titles(page)).toHaveCount(9);

  // TOTP shows the code for the (controlled) current time.
  await page.clock.setFixedTime(new Date(59_000));
  await openItem(page, 'Synthetic TOTP');
  await expect(page.getByTestId('totp-code')).toHaveText('94287082');
  await expect(page.getByTestId('totp-remaining')).toHaveText('1s remaining');
  await page.clock.setFixedTime(new Date(1_111_111_109_000));
  await expect(page.getByTestId('totp-code')).toHaveText('07081804', { timeout: 5000 });

  // Encrypted backup download.
  await page.getByRole('button', { name: 'Backup' }).click();
  const [dl] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download encrypted backup' }).click(),
  ]);
  const backupPath = testInfo.outputPath('backup.keymesh');
  await dl.saveAs(backupPath);
  const backup = await readFile(backupPath);
  assertNoMarkers(backup, 'backup');
  expect(backup.equals(await storedBytes(page))).toBe(true);

  // Change the vault after the backup, then restore it.
  await page.getByRole('button', { name: 'Items' }).click();
  await openItem(page, 'Synthetic wallet');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.locator('.item-list')).not.toContainText('Synthetic wallet');
  const afterDelete = await storedBytes(page);

  // Malformed / truncated / unknown restores are refused without data loss.
  await page.getByRole('button', { name: 'Backup' }).click();
  const input = page.getByTestId('restore-input');
  for (const [name, buffer] of [
    ['truncated.keymesh', backup.subarray(0, backup.length / 2)],
    ['garbage.keymesh', Buffer.from('not a vault at all')],
    ['unknown.keymesh', Buffer.from(backup.toString('utf8').replace('"version": 1', '"version": 9'))],
  ] as const) {
    await input.setInputFiles({ name, mimeType: 'application/octet-stream', buffer });
    await expect(page.getByTestId('backup-error')).toContainText('Backup rejected, nothing was changed');
    expect((await storedBytes(page)).equals(afterDelete), `${name} must not overwrite`).toBe(true);
  }
  await page.getByRole('button', { name: 'Items' }).click();
  await expect(page.locator('.item-list')).not.toContainText('Synthetic wallet');

  // Valid restore brings the deleted item back; the core decrypts markers.
  await page.getByRole('button', { name: 'Backup' }).click();
  await page.getByTestId('restore-input').setInputFiles(backupPath);
  await expect(page.getByTestId('backup-status')).toHaveText('Backup restored.');
  await page.getByRole('button', { name: 'Items' }).click();
  await openItem(page, 'Synthetic wallet');
  const phrase = page.locator('km-secret-field', { hasText: 'Recovery phrase' });
  await phrase.getByRole('button', { name: 'Reveal' }).click();
  await expect(phrase).toContainText(M.walletPhrase);
  expect((await storedBytes(page)).equals(backup)).toBe(true);

  // Only same-origin requests were made.
  const origin = new URL(page.url()).origin;
  expect(requests.filter((u) => !u.startsWith(origin) && !u.startsWith('blob:'))).toEqual([]);
  expect(errors).toEqual([]);
});

test('second tab cannot clobber newer data', async ({ context }) => {
  const a = await context.newPage();
  await start(a, 'synthetic-fixture');
  await newItem(a, 'secure_note');
  await field(a, 'Title').fill('Note from tab A');
  await field(a, 'Note').fill('a');
  await create(a, 'Note from tab A');

  const b = await context.newPage();
  await b.goto('/');
  await b.getByRole('button', { name: 'Open with synthetic fixture key (test harness)' }).click();
  await expect(titles(b)).toHaveText(['Note from tab A']);

  // A writes; B is told its copy is stale and cannot write over it.
  await newItem(a, 'secure_note');
  await field(a, 'Title').fill('Second note from tab A');
  await field(a, 'Note').fill('a2');
  await create(a, 'Second note from tab A');
  await expect(b.getByRole('alert').filter({ hasText: 'changed elsewhere' })).toBeVisible();
  await newItem(b, 'secure_note');
  await field(b, 'Title').fill('Note from stale tab B');
  await field(b, 'Note').fill('b');
  await b.getByRole('button', { name: 'Create' }).click();
  await expect(b.locator('form .error')).toContainText('changed elsewhere');

  // Storage still has A's data; B reloads and sees it.
  await b.getByRole('button', { name: 'Reload from storage' }).click();
  await expect(titles(b)).toHaveText(['Note from tab A', 'Second note from tab A']);
  await a.reload();
  await a.getByRole('button', { name: 'Open with synthetic fixture key (test harness)' }).click();
  await expect(titles(a)).toHaveText(['Note from tab A', 'Second note from tab A']);
});

test('second tab writing without the broadcast is rejected by compare-and-swap', async ({ context }) => {
  const a = await context.newPage();
  await start(a, 'synthetic-fixture');
  const b2 = await context.newPage();
  await b2.addInitScript(() => {
    // Disable cross-tab messages entirely in this tab.
    (window as unknown as { BroadcastChannel: unknown }).BroadcastChannel = undefined;
  });
  await b2.goto('/');
  await b2.getByRole('button', { name: 'Open with synthetic fixture key (test harness)' }).click();

  await newItem(a, 'secure_note');
  await field(a, 'Title').fill('Written by A');
  await field(a, 'Note').fill('a');
  await create(a, 'Written by A');

  await newItem(b2, 'secure_note');
  await field(b2, 'Title').fill('Written by stale B');
  await field(b2, 'Note').fill('b');
  await b2.getByRole('button', { name: 'Create' }).click();
  await expect(b2.locator('form .error')).toContainText('changed elsewhere');
  await expect(b2.getByRole('alert').filter({ hasText: 'changed elsewhere' }).first()).toBeVisible();
  await b2.getByRole('button', { name: 'Reload from storage' }).click();
  await expect(titles(b2)).toHaveText(['Written by A']);
});

test('wrong-key backup is refused and ephemeral vaults are not recoverable after reload', async ({
  browser,
}, testInfo) => {
  // Make a backup under an ephemeral key in an isolated context.
  const eph = await browser.newContext();
  const p = await eph.newPage();
  await start(p, 'ephemeral');
  await newItem(p, 'secure_note');
  await field(p, 'Title').fill('Ephemeral note');
  await field(p, 'Note').fill('x');
  await create(p, 'Ephemeral note');
  await p.getByRole('button', { name: 'Backup' }).click();
  const [dl] = await Promise.all([
    p.waitForEvent('download'),
    p.getByRole('button', { name: 'Download encrypted backup' }).click(),
  ]);
  const ephBackup = testInfo.outputPath('ephemeral.keymesh');
  await dl.saveAs(ephBackup);

  // After reload the ephemeral key is gone: honest message, no open button.
  await p.reload();
  await expect(p.getByRole('alert')).toContainText('can no longer be decrypted');
  await expect(p.getByRole('button', { name: /Open with synthetic fixture key/ })).toHaveCount(0);
  await eph.close();

  // A fixture-key vault refuses the ephemeral backup and keeps its data.
  const fx = await browser.newContext();
  const q = await fx.newPage();
  await start(q, 'synthetic-fixture');
  await newItem(q, 'secure_note');
  await field(q, 'Title').fill('Fixture note');
  await field(q, 'Note').fill('y');
  await create(q, 'Fixture note');
  const before = await storedBytes(q);
  await q.getByRole('button', { name: 'Backup' }).click();
  await q.getByTestId('restore-input').setInputFiles(ephBackup);
  await expect(q.getByTestId('backup-error')).toContainText('Backup rejected');
  expect((await storedBytes(q)).equals(before)).toBe(true);
  await q.getByRole('button', { name: 'Items' }).click();
  await expect(titles(q)).toHaveText(['Fixture note']);
  await fx.close();
});
