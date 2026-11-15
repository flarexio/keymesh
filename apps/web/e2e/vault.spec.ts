/**
 * End-to-end tests against the production build and the real compiled
 * Rust/WASM core in headless Chromium. SYNTHETIC DATA ONLY. No request
 * interception, no mocked crypto. Time is controlled with Playwright's clock.
 */
import { expect, Page, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { en } from '../src/app/core/i18n/en';
import {
  M,
  RFC_URI,
  assertNoMarkers,
  browserStorageSummary,
  createAllKinds,
  category,
  confirmDialog,
  create,
  field,
  newItem,
  openItem,
  start,
  storedBytes,
  titles,
} from './helpers';

test('full vault flow: create, generate, edit, search, lock, unlock, persist, backup, restore', async ({
  page,
  context,
}, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  // This flow jumps the clock decades forward (RFC 6238 vector) with the
  // vault open: start at the fixed early time and opt out of the idle
  // limit through the app's own auto-lock setting (M5 C2). The clock only
  // moves forward, so the backwards-clock rule stays active.
  await page.clock.setFixedTime(new Date(59_000));
  await page.addInitScript(() => localStorage.setItem('keymesh.autolock.v1', '{"idleMinutes":0,"hideSeconds":30}'));
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

  // Generators: values created inside WASM; Save stores the shown preview.
  await page.getByRole('button', { name: 'Generators' }).click();
  await page.getByTestId('generate-password').click();
  await page.getByTestId('save-password').click();
  await expect(page.locator('#detail-title')).toHaveText('Generated password');
  await expect(page.locator('.detail')).toContainText(en['detail.originGenerated']);
  const genRow = page.locator('km-secret-field', { hasText: 'Secret' });
  await genRow.getByRole('button', { name: 'Reveal' }).click();
  // Revealed: exactly 24 non-space characters (default profile).
  await expect(genRow.getByTestId('secret-value')).toHaveText(/^\s*\S{24}\s*$/);
  await page.getByRole('button', { name: 'Generators' }).click();
  await page.getByTestId('generate-secret').click();
  await page.getByTestId('save-secret').click();
  await expect(page.locator('#detail-title')).toHaveText('Generated secret');
  const hexRow = page.locator('km-secret-field', { hasText: 'Secret' });
  await hexRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(hexRow.getByTestId('secret-value')).toHaveText(/^\s*[0-9a-f]{64}\s*$/);
  await page.getByRole('button', { name: 'Generators' }).click();
  await expect(page.getByTestId('generate-passphrase')).toBeEnabled();
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
  await expect(page.getByTestId('item-meta')).toHaveAttribute('data-rev', '2');
  const pw2 = page.locator('km-secret-field', { hasText: 'Password' });
  await pw2.getByRole('button', { name: 'Reveal' }).click();
  await expect(pw2).toContainText(M.password);
  await page.getByTestId('search').fill('synthmark-url');
  await expect(titles(page)).toHaveText([`${M.loginTitle} edited`]);
  await page.getByTestId('search').fill('');
  await category(page, 'secret');
  await expect(titles(page)).toHaveCount(3);
  await category(page, '');

  // Delete.
  await openItem(page, 'Synthetic note');
  await page.getByRole('button', { name: 'Delete' }).click();
  await confirmDialog(page);
  await expect(page.locator('.item-list')).not.toContainText('Synthetic note');
  await expect(titles(page)).toHaveCount(9);

  // Storage holds only the encrypted envelope.
  assertNoMarkers(await storedBytes(page), 'IndexedDB');
  const storage = await browserStorageSummary(page);
  // The only Web Storage entry is this test's non-secret auto-lock setting.
  expect(storage).toEqual({ dbs: ['keymesh-demo'], local: 1, session: 0, cookies: '' });
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual(['keymesh.autolock.v1']);

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
  await page.getByRole('button', { name: en['start.locked.unlock'], exact: true }).click();
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
  await page.getByRole('button', { name: en['start.locked.unlock'], exact: true }).click();
  await expect(page.locator('.item-list')).not.toContainText('SYNTHMARK-RACE');
  await expect(titles(page)).toHaveCount(9);

  // Persistence across reload (synthetic fixture key reopens).
  await page.reload();
  await expect(page.getByRole('heading', { name: en['start.stored.title'] })).toBeVisible();
  await page.getByRole('button', { name: en['start.stored.open'] }).click();
  await expect(titles(page)).toHaveCount(9);

  // TOTP shows the code for the (controlled) current time.
  await page.clock.setFixedTime(new Date(59_000));
  await openItem(page, 'Synthetic TOTP');
  await expect(page.getByTestId('totp-code')).toHaveText('94287082');
  // Last 5 s: text (not only colour) and the ring flag the coming change.
  await expect(page.getByTestId('totp-remaining')).toHaveText('1s left — new code soon');
  await expect(page.getByTestId('totp-ring')).toHaveAttribute('data-warn', 'true');
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
  await page.getByRole('button', { name: 'Delete' }).click();
  await confirmDialog(page);
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
    await expect(page.getByTestId('backup-error')).toContainText(en['errors.backupRejected']);
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
  await b.getByRole('button', { name: en['start.stored.open'] }).click();
  await expect(titles(b)).toHaveText(['Note from tab A']);

  // A writes; B is told its copy is stale and cannot write over it.
  await newItem(a, 'secure_note');
  await field(a, 'Title').fill('Second note from tab A');
  await field(a, 'Note').fill('a2');
  await create(a, 'Second note from tab A');
  await expect(b.getByRole('alert').filter({ hasText: 'changed in another tab or window' })).toBeVisible();
  await newItem(b, 'secure_note');
  await field(b, 'Title').fill('Note from stale tab B');
  await field(b, 'Note').fill('b');
  await b.getByRole('button', { name: 'Create' }).click();
  await expect(b.getByTestId('form-error')).toContainText('changed in another tab or window');

  // Storage still has A's data; B reloads and sees it.
  await b.getByRole('button', { name: en['shell.reload'] }).click();
  await expect(titles(b)).toHaveText(['Note from tab A', 'Second note from tab A']);
  await a.reload();
  await a.getByRole('button', { name: en['start.stored.open'] }).click();
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
  await b2.getByRole('button', { name: en['start.stored.open'] }).click();

  await newItem(a, 'secure_note');
  await field(a, 'Title').fill('Written by A');
  await field(a, 'Note').fill('a');
  await create(a, 'Written by A');

  await newItem(b2, 'secure_note');
  await field(b2, 'Title').fill('Written by stale B');
  await field(b2, 'Note').fill('b');
  await b2.getByRole('button', { name: 'Create' }).click();
  await expect(b2.getByTestId('form-error')).toContainText('changed in another tab or window');
  await expect(b2.getByRole('alert').filter({ hasText: 'changed in another tab or window' }).first()).toBeVisible();
  await b2.getByRole('button', { name: en['shell.reload'] }).click();
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
  await expect(p.getByRole('alert')).toContainText('can no longer be opened and cannot be recovered');
  await expect(p.getByTestId('open-fixture')).toHaveCount(0);
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
  await expect(q.getByTestId('backup-error')).toContainText(en['errors.backupRejected']);
  expect((await storedBytes(q)).equals(before)).toBe(true);
  await q.getByRole('button', { name: 'Items' }).click();
  await expect(titles(q)).toHaveText(['Fixture note']);
  await fx.close();
});

// --- M2 review 1: restore vs lock, stale tabs, revision reuse ---------------

async function downloadBackup(page: Page, path: string): Promise<Buffer> {
  await page.getByRole('button', { name: 'Backup' }).click();
  const [dl] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download encrypted backup' }).click(),
  ]);
  await dl.saveAs(path);
  await page.getByRole('button', { name: 'Items' }).click();
  return readFile(path);
}

async function addNote(page: Page, title: string) {
  await newItem(page, 'secure_note');
  await field(page, 'Title').fill(title);
  await field(page, 'Note').fill('n');
  await create(page, title);
}

async function openFixture(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: en['start.stored.open'] }).click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
}

/** A tab that never receives cross-tab notifications. */
async function deafPage(context: import('@playwright/test').BrowserContext) {
  const p = await context.newPage();
  await p.addInitScript(() => {
    (window as unknown as { BroadcastChannel: unknown }).BroadcastChannel = undefined;
  });
  return p;
}

test('lock during a pending restore wins: nothing installed or persisted', async ({ page }, testInfo) => {
  await start(page, 'synthetic-fixture');
  await addNote(page, 'Kept note');
  const backupPath = testInfo.outputPath('before-delete.keymesh');
  await downloadBackup(page, backupPath);
  await page.getByRole('button', { name: 'Delete' }).click();
  await confirmDialog(page);
  await expect(titles(page)).toHaveCount(0);
  const before = await storedBytes(page);

  // Hold the backup file read open until the test releases it.
  await page.evaluate(() => {
    const w = window as unknown as { __release: () => void };
    const gate = new Promise<void>((r) => (w.__release = r));
    const orig = Blob.prototype.arrayBuffer;
    Blob.prototype.arrayBuffer = async function (this: Blob) {
      await gate;
      return orig.call(this);
    };
  });
  await page.getByRole('button', { name: 'Backup' }).click();
  await page.getByTestId('restore-input').setInputFiles(backupPath);
  await page.getByTestId('lock').click();
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await page.evaluate(() => (window as unknown as { __release: () => void }).__release());

  // Still locked, nothing revealed, storage unchanged.
  await page.waitForTimeout(500);
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  expect(await page.content()).not.toContain('Kept note');
  expect((await storedBytes(page)).equals(before)).toBe(true);
  await page.getByRole('button', { name: en['start.locked.unlock'], exact: true }).click();
  await expect(titles(page)).toHaveCount(0);
});

test('stale tab restore is rejected (notification delivered)', async ({ context }, testInfo) => {
  const a = await context.newPage();
  await start(a, 'synthetic-fixture');
  const b = await context.newPage();
  await openFixture(b);
  const backupPath = testInfo.outputPath('old.keymesh');
  await downloadBackup(b, backupPath);

  await addNote(a, 'Newer note from A');
  await expect(b.getByRole('alert').filter({ hasText: 'changed in another tab or window' })).toBeVisible();
  const afterA = await storedBytes(a);
  await b.getByRole('button', { name: 'Backup' }).click();
  await b.getByTestId('restore-input').setInputFiles(backupPath);
  await expect(b.getByTestId('backup-error')).toContainText('out of date');
  expect((await storedBytes(a)).equals(afterA)).toBe(true);
  await a.reload();
  await a.getByRole('button', { name: en['start.stored.open'] }).click();
  await expect(titles(a)).toHaveText(['Newer note from A']);
});

test('stale tab restore is rejected by compare-and-swap (notification missed)', async ({ context }, testInfo) => {
  const a = await context.newPage();
  await start(a, 'synthetic-fixture');
  const b = await deafPage(context);
  await openFixture(b);
  const backupPath = testInfo.outputPath('old.keymesh');
  await downloadBackup(b, backupPath);

  await addNote(a, 'Newer note from A');
  const afterA = await storedBytes(a);
  // B never heard about A's write and still looks editable.
  await expect(b.getByRole('alert').filter({ hasText: 'changed in another tab or window' })).toHaveCount(0);
  await b.getByRole('button', { name: 'Backup' }).click();
  await b.getByTestId('restore-input').setInputFiles(backupPath);
  await expect(b.getByTestId('backup-error')).toContainText('changed in another tab or window');
  expect((await storedBytes(a)).equals(afterA)).toBe(true);
  await expect(b.getByRole('alert').filter({ hasText: 'changed in another tab or window' }).first()).toBeVisible();
});

test('reused revision after a restore cannot be clobbered by a deaf stale tab', async ({ context }, testInfo) => {
  const a = await context.newPage();
  await start(a, 'synthetic-fixture'); // revision 1
  const rev1 = testInfo.outputPath('rev1.keymesh');
  await downloadBackup(a, rev1);
  await addNote(a, 'X'); // revision 2 (bytes R)

  const b = await deafPage(context);
  await openFixture(b); // B holds revision 2, bytes R
  await expect(b.getByTestId('key-mode')).toHaveAttribute('data-revision', '2');

  await a.getByRole('button', { name: 'Backup' }).click();
  await a.getByTestId('restore-input').setInputFiles(rev1); // back to revision 1
  await expect(a.getByTestId('backup-status')).toHaveText('Backup restored.');
  await a.getByRole('button', { name: 'Items' }).click();
  await addNote(a, 'Y'); // revision 2 again, different bytes
  await expect(a.getByTestId('key-mode')).toHaveAttribute('data-revision', '2');
  const afterA = await storedBytes(a);

  // Same vault id and revision as B's view — only exact bytes differ.
  await newItem(b, 'secure_note');
  await field(b, 'Title').fill('Z from stale B');
  await field(b, 'Note').fill('z');
  await b.getByRole('button', { name: 'Create' }).click();
  await expect(b.getByTestId('form-error')).toContainText('changed in another tab or window');
  expect((await storedBytes(a)).equals(afterA)).toBe(true);
  await b.getByRole('button', { name: en['shell.reload'] }).click();
  await expect(titles(b)).toHaveText(['Y']);
});

test('initial restore into empty storage', async ({ browser }, testInfo) => {
  const src = await browser.newContext();
  const p = await src.newPage();
  await start(p, 'synthetic-fixture');
  await addNote(p, 'Restored note');
  const path = testInfo.outputPath('initial.keymesh');
  await downloadBackup(p, path);
  await src.close();

  const dst = await browser.newContext();
  const q = await dst.newPage();
  await q.goto('/');
  // Malformed first: nothing is written, still empty.
  await q.getByTestId('initial-restore-input').setInputFiles({
    name: 'bad.keymesh',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('garbage'),
  });
  await expect(q.getByRole('alert')).toContainText(en['errors.backupRejected']);
  expect((await storedBytes(q)).length).toBe(0);
  await q.getByTestId('initial-restore-input').setInputFiles(path);
  await expect(titles(q)).toHaveText(['Restored note']);
  await dst.close();
});
