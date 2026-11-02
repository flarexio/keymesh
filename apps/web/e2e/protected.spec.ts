/**
 * Password vault (envelope v2) end to end: production build, real compiled
 * WASM core and the real Argon2id worker in Chromium. SYNTHETIC DATA ONLY.
 *
 * Recovery codes are read from the page into test variables and typed back;
 * they are never printed, and screenshots mask them. The only interception
 * used is holding the KDF worker *script* (to make lock/stale-tab races
 * deterministic); crypto is never mocked.
 */
import { Page, Route, chromium, expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import { en } from '../src/app/core/i18n/en';
import { M, assertNoMarkers, createAllKinds, openItem, storedBytes, titles } from './helpers';

const PW = 'synthetic e2e passphrase one';
const PW2 = 'synthetic e2e passphrase two';
const PDB = 'keymesh-vault';

const vectors = JSON.parse(
  readFileSync(join(__dirname, '../../../tests/fixtures/v2/vectors.json'), 'utf8'),
) as { envelope: { json: string; password: string; recovery_code: string; titles: string[] } };

async function readCode(page: Page): Promise<string> {
  const code = await page
    .getByTestId('recovery-code')
    .evaluate((el) => Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'));
  expect(code).toMatch(/^([A-Z2-7]{4}-){13}[A-Z2-7]{4}$/);
  return code;
}

/** Create a password vault; returns its recovery code. */
async function createVault(page: Page, pw = PW): Promise<string> {
  await page.goto('/');
  await expect(page.getByTestId('protected-section')).toBeVisible();
  await page.getByTestId('create-password').fill(pw);
  await page.getByTestId('create-password-confirm').fill(pw);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const code = await readCode(page);
  // Nothing is stored before the code is confirmed.
  expect((await storedBytes(page, PDB)).length).toBe(0);
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  return code;
}

async function unlock(page: Page, pw: string): Promise<void> {
  await page.getByTestId('unlock-password').fill(pw);
  await page.getByTestId('unlock-protected').click();
}

async function lock(page: Page): Promise<void> {
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock-password')).toBeVisible();
}

/** Every place a page could leave a secret behind (regression check, not proof). */
async function assertNothingLeaked(page: Page, secrets: string[], consoleLines: string[]): Promise<void> {
  const dump = await page.evaluate(async () => {
    const out: string[] = [location.href, document.cookie];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      out.push(k, localStorage.getItem(k) ?? '');
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i)!;
      out.push(k, sessionStorage.getItem(k) ?? '');
    }
    out.push(...(await indexedDB.databases()).map((d) => d.name ?? ''));
    return out.join('\n');
  });
  const bytes = Buffer.concat([await storedBytes(page, PDB), await storedBytes(page)]).toString('utf8');
  const haystacks = [dump, bytes, consoleLines.join('\n')].map((h) => h.toLowerCase());
  for (const s of secrets) {
    const forms = [s, s.replace(/-/g, '')].map((x) => x.toLowerCase());
    for (const h of haystacks) for (const f of forms) expect(h.includes(f), 'a planted secret leaked').toBe(false);
  }
}

/**
 * Hold the KDF worker script for one page so its next derivation cannot
 * finish until released (other pages are unaffected).
 */
async function holdWorker(page: Page): Promise<{ held: Promise<void>; release: () => Promise<void> }> {
  let routeRef: Route | null = null;
  let signal!: () => void;
  const held = new Promise<void>((r) => (signal = r));
  const pattern = /\/worker-[A-Z0-9]+\.js$/;
  await page.route(pattern, (route) => {
    routeRef = route;
    signal();
  });
  return {
    held,
    release: async () => {
      await page.unroute(pattern);
      await (routeRef as Route | null)?.continue().catch(() => undefined);
    },
  };
}

test('create → confirm recovery → all kinds → backup → lock → reload → unlock with password', async ({ page }, testInfo) => {
  const consoleLines: string[] = [];
  page.on('console', (m) => consoleLines.push(m.text()));
  const requests: string[] = [];
  page.on('request', (r) => requests.push(r.url()));

  await page.goto('/');
  // Weak passwords are refused before any key derivation.
  await page.getByTestId('create-password').fill('too short');
  await page.getByTestId('create-password-confirm').fill('too short');
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.passwordShort']);
  await page.getByTestId('create-password').fill(PW);
  await page.getByTestId('create-password-confirm').fill(PW2);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('protected-error')).toContainText(en['protected.mismatch']);

  await page.getByTestId('create-password-confirm').fill(PW);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const code = await readCode(page);
  expect((await storedBytes(page, PDB)).length).toBe(0);
  // A wrong confirmation is refused; the vault is still not stored.
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code.replace(/^A/, 'B'));
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('protected-error')).toBeVisible();
  expect((await storedBytes(page, PDB)).length).toBe(0);
  await page.getByTestId('recovery-confirm-input').fill(code.toLowerCase().replace(/-/g, ' '));
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await expect(page.getByTestId('demo-banner')).toContainText(en['demo.label']);

  await createAllKinds(page);
  await expect(titles(page)).toHaveCount(7);
  const backupPath = testInfo.outputPath('protected.keymesh');
  await page.getByTestId('nav-backup').click();
  const dl = page.waitForEvent('download');
  await page.getByTestId('backup-download').click();
  await (await dl).saveAs(backupPath);
  const backup = readFileSync(backupPath);
  assertNoMarkers(backup, 'backup');
  expect(JSON.parse(backup.toString('utf8')).version).toBe(2);

  // Lock, then a full page reload (process restart for the browser side).
  await lock(page);
  await page.reload();
  await expect(page.getByTestId('unlock-password')).toBeVisible();
  await unlock(page, 'synthetic wrong passphrase');
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await expect(page.getByTestId('lock')).toHaveCount(0);
  // No fallback: a failed unlock never opens or creates a demo vault.
  expect((await storedBytes(page)).length).toBe(0);
  await expect(page.getByTestId('key-mode')).toHaveCount(0);
  // The recovery code is not a password.
  await unlock(page, code);
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });

  const t0 = Date.now();
  await unlock(page, PW);
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  const unlockMs = Date.now() - t0;
  testInfo.annotations.push({ type: 'unlock-ms (UI, incl. Argon2id 64 MiB t=3 in worker)', description: String(unlockMs) });
  console.log(`[measure] password unlock in Chromium on this host: ${unlockMs} ms`);
  await expect(titles(page)).toHaveCount(7);
  await openItem(page, M.loginTitle);
  const pwRow = page.locator('km-secret-field', { hasText: 'Password' });
  await pwRow.getByRole('button', { name: 'Reveal' }).click();
  await expect(pwRow).toContainText(M.password);
  await openItem(page, 'Synthetic TOTP');
  await openItem(page, 'Synthetic Ed25519');
  await expect(page.locator('.detail')).toContainText('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5');

  assertNoMarkers(await storedBytes(page, PDB), 'IndexedDB (password vault)');
  await assertNothingLeaked(page, [PW, code, ...Object.values(M)], consoleLines);
  // Same-origin only (the worker and the WASM module included).
  const origin = new URL(page.url()).origin;
  expect(requests.every((u) => u.startsWith(origin) || u.startsWith('blob:') || u.startsWith('data:'))).toBe(true);
  expect(requests.some((u) => /\/worker-[A-Z0-9]+\.js$/.test(u))).toBe(true);
});

test('clean profile: restore from backup with the recovery code, set a new password, restart, unlock', async ({ browser }, testInfo) => {
  const src = await browser.newContext();
  const p = await src.newPage();
  const code = await createVault(p);
  await createAllKinds(p);
  await p.getByTestId('nav-backup').click();
  const dl = p.waitForEvent('download');
  await p.getByTestId('backup-download').click();
  const path = testInfo.outputPath('to-recover.keymesh');
  await (await dl).saveAs(path);
  await src.close();

  const dst = await browser.newContext();
  const q = await dst.newPage();
  const consoleLines: string[] = [];
  q.on('console', (m) => consoleLines.push(m.text()));
  await q.goto('/');
  await q.getByTestId('protected-restore-input').setInputFiles(path);
  await q.getByTestId('restore-with-recovery').click();
  // Typo: caught by the check digits before anything is decrypted.
  await q.getByTestId('restore-code').fill(code.slice(0, -1) + (code.endsWith('A') ? 'B' : 'A'));
  await q.getByTestId('restore-new-password').fill(PW2);
  await q.getByTestId('protected-restore').click();
  await expect(q.getByTestId('protected-restore-error')).toBeVisible();
  expect((await storedBytes(q, PDB)).length).toBe(0);
  await q.getByTestId('restore-code').fill(code);
  await q.getByTestId('protected-restore').click();
  await expect(q.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await expect(titles(q)).toHaveCount(7);

  await q.reload();
  // Documented semantics: this browser's copy now opens with the NEW
  // password; the old password no longer opens it; the recovery code is
  // unchanged by a password reset.
  await unlock(q, PW);
  await expect(q.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await unlock(q, PW2);
  await expect(q.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await expect(titles(q)).toHaveCount(7);
  await lock(q);
  // Forgot the new password too: reset again with the same recovery code.
  await q.getByTestId('forgot-password').click();
  await q.getByTestId('reset-code').fill(code);
  await q.getByTestId('reset-password').fill(PW);
  await q.getByTestId('reset-password-confirm').fill(PW);
  await q.getByTestId('reset-submit').click();
  await expect(q.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await assertNothingLeaked(q, [PW, PW2, code, ...Object.values(M)], consoleLines);
  await dst.close();
});

test('shared v2 vector opens in the browser with its password and with its recovery code', async ({ browser }, testInfo) => {
  const path = testInfo.outputPath('vector.keymesh');
  await writeFile(path, vectors.envelope.json);
  for (const method of ['password', 'recovery'] as const) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('/');
    await page.getByTestId('protected-restore-input').setInputFiles(path);
    if (method === 'password') {
      await page.getByTestId('restore-password').fill(vectors.envelope.password);
    } else {
      await page.getByTestId('restore-with-recovery').click();
      await page.getByTestId('restore-code').fill(vectors.envelope.recovery_code);
      await page.getByTestId('restore-new-password').fill(PW);
    }
    await page.getByTestId('protected-restore').click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
    await expect(titles(page)).toHaveText(vectors.envelope.titles);
    if (method === 'password') {
      // Restored as is: the stored bytes are exactly the vector file.
      expect((await storedBytes(page, PDB)).toString('utf8')).toBe(vectors.envelope.json);
    }
    await ctx.close();
  }
});

test('hostile or broken backups are refused and leave the stored vault usable', async ({ page }, testInfo) => {
  const code = await createVault(page);
  await page.getByTestId('nav-backup').click();
  const before = await storedBytes(page, PDB);
  const base = JSON.parse(vectors.envelope.json);
  const variants: [string, string | Buffer][] = [
    ['truncated', vectors.envelope.json.slice(0, vectors.envelope.json.length / 2)],
    ['garbage', Buffer.from('not a vault at all')],
    ['huge memory cost', JSON.stringify({ ...base, slots: [{ ...base.slots[0], kdf: { ...base.slots[0].kdf, m_kib: 4194304 } }, base.slots[1]] })],
    ['huge time cost', JSON.stringify({ ...base, slots: [{ ...base.slots[0], kdf: { ...base.slots[0].kdf, t: 1000000 } }, base.slots[1]] })],
    ['weakened cost', JSON.stringify({ ...base, slots: [{ ...base.slots[0], kdf: { ...base.slots[0].kdf, m_kib: 1024, t: 1 } }, base.slots[1]] })],
    ['tampered cost (in bounds)', JSON.stringify({ ...base, slots: [{ ...base.slots[0], kdf: { ...base.slots[0].kdf, t: 4 } }, base.slots[1]] })],
    ['duplicate slot', JSON.stringify({ ...base, slots: [base.slots[0], base.slots[0], base.slots[1]] })],
    ['removed recovery slot', JSON.stringify({ ...base, slots: [base.slots[0]] })],
    ['unknown version', JSON.stringify({ ...base, version: 3 })],
    ['relabelled as demo', JSON.stringify({ ...base, version: 1 })],
    // Raw duplicate members (cannot be built with JSON.stringify).
    ['duplicate version member', vectors.envelope.json.replace('"version": 2,', '"version": 999, "version": 2,')],
    ['duplicate KDF member', vectors.envelope.json.replace('"m_kib": 65536,', '"m_kib": 4294967295, "m_kib": 65536,')],
  ];
  for (const [name, content] of variants) {
    const path = testInfo.outputPath(`${name.replace(/\W+/g, '-')}.keymesh`);
    await writeFile(path, content);
    await page.getByTestId('protected-restore-input').setInputFiles(path);
    await page.getByTestId('restore-password').fill(vectors.envelope.password);
    const t0 = Date.now();
    await page.getByTestId('protected-restore').click();
    await expect(page.getByTestId('protected-restore-error'), name).toBeVisible({ timeout: 30_000 });
    // Rejected by bounds before any key derivation for hostile costs.
    if (name.startsWith('huge')) expect(Date.now() - t0, `${name} rejected quickly`).toBeLessThan(5_000);
    expect((await storedBytes(page, PDB)).equals(before), `${name}: storage unchanged`).toBe(true);
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected');
  }
  // Oversized file: refused before it is read.
  const big = testInfo.outputPath('oversized.keymesh');
  await writeFile(big, Buffer.alloc(64 * 1024 * 1024 + 1, 0x20));
  await page.getByTestId('protected-restore-input').setInputFiles(big);
  await page.getByTestId('restore-password').fill(PW);
  await page.getByTestId('protected-restore').click();
  await expect(page.getByTestId('protected-restore-error')).toContainText(en['errors.backupTooLarge']);
  expect((await storedBytes(page, PDB)).equals(before)).toBe(true);
  // A real demo (v1) backup cannot replace a password vault.
  const demoCtx = await page.context().browser()!.newContext();
  const d = await demoCtx.newPage();
  await d.goto('/');
  await d.locator('input[name=mode][value=synthetic-fixture]').check();
  await d.getByTestId('start-vault').click();
  await d.getByTestId('nav-backup').click();
  const dl = d.waitForEvent('download');
  await d.getByTestId('backup-download').click();
  const demoPath = testInfo.outputPath('demo.keymesh');
  await (await dl).saveAs(demoPath);
  await demoCtx.close();
  await page.getByTestId('protected-restore-input').setInputFiles(demoPath);
  await page.getByTestId('restore-password').fill(PW);
  await page.getByTestId('protected-restore').click();
  await expect(page.getByTestId('protected-restore-error')).toContainText(en['errors.demoBackup']);
  // The vault and both credentials still work after all of that.
  await lock(page);
  await unlock(page, PW);
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await lock(page);
  await page.getByTestId('forgot-password').click();
  await page.getByTestId('reset-code').fill(code);
  await page.getByTestId('reset-password').fill(PW2);
  await page.getByTestId('reset-password-confirm').fill(PW2);
  await page.getByTestId('reset-submit').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('lock during a password change (KDF held) cancels it; the old password still opens the vault', async ({ page }) => {
  await createVault(page);
  await page.getByTestId('nav-backup').click();
  const before = await storedBytes(page, PDB);
  const gate = await holdWorker(page);
  await page.getByTestId('change-current').fill(PW);
  await page.getByTestId('change-new').fill(PW2);
  await page.getByTestId('change-confirm').fill(PW2);
  await page.getByTestId('change-password').click();
  await gate.held; // the derivation cannot complete: its worker script is held
  await expect(page.getByTestId('change-password')).toBeDisabled();
  await page.getByTestId('lock').click();
  await gate.release();
  await expect(page.getByTestId('unlock-password')).toBeVisible();
  expect((await storedBytes(page, PDB)).equals(before)).toBe(true);
  await unlock(page, PW2);
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await unlock(page, PW);
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('stale tab: a password change elsewhere wins; this tab’s change is refused by exact-byte CAS', async ({ context }) => {
  const a = await context.newPage();
  await createVault(a);
  const b = await context.newPage();
  await b.goto('/');
  await unlock(b, PW);
  await expect(b.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await a.getByTestId('nav-backup').click();
  await b.getByTestId('nav-backup').click();
  // B starts a change from the shared snapshot and is held inside its KDF.
  const gate = await holdWorker(b);
  await b.getByTestId('change-current').fill(PW);
  await b.getByTestId('change-new').fill('synthetic tab b passphrase');
  await b.getByTestId('change-confirm').fill('synthetic tab b passphrase');
  await b.getByTestId('change-password').click();
  await gate.held;
  // Meanwhile A changes the password completely.
  await a.getByTestId('change-current').fill(PW);
  await a.getByTestId('change-new').fill(PW2);
  await a.getByTestId('change-confirm').fill(PW2);
  await a.getByTestId('change-password').click();
  await expect(a.getByTestId('backup-status')).toContainText(en['security.changed'], { timeout: 30_000 });
  const afterA = await storedBytes(a, PDB);
  // B continues from the old snapshot: refused, storage keeps A's change.
  await gate.release();
  await expect(b.getByTestId('backup-error')).toBeVisible({ timeout: 30_000 });
  expect((await storedBytes(b, PDB)).equals(afterA)).toBe(true);
  await a.close();
  await b.reload();
  await unlock(b, 'synthetic tab b passphrase');
  await expect(b.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await unlock(b, PW);
  await expect(b.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await unlock(b, PW2);
  await expect(b.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('a second unlock click while the KDF runs starts no second derivation', async ({ page }) => {
  await createVault(page);
  await lock(page);
  let workers = 0;
  page.on('request', (r) => {
    if (/\/worker-[A-Z0-9]+\.js$/.test(r.url())) workers++;
  });
  const gate = await holdWorker(page);
  await page.getByTestId('unlock-password').fill(PW);
  await page.getByTestId('unlock-protected').click();
  await gate.held;
  await expect(page.getByTestId('unlock-protected')).toBeDisabled();
  await page.getByTestId('unlock-password').press('Enter');
  await gate.release();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  expect(workers).toBe(1);
});

test('new recovery code: needs the current password and the code back; the old code stops working', async ({ page }) => {
  const oldCode = await createVault(page);
  await page.getByTestId('nav-backup').click();
  await expect(page.getByTestId('rotation-note')).toContainText(en['security.rotation']);
  await page.getByTestId('recovery-current').fill(PW2);
  await page.getByTestId('begin-recovery-change').click();
  await expect(page.getByTestId('backup-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await page.getByTestId('recovery-current').fill(PW);
  await page.getByTestId('begin-recovery-change').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const newCode = await readCode(page);
  expect(newCode).not.toBe(oldCode);
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(oldCode);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('backup-error')).toContainText(en['errors.recoveryMismatch']);
  await page.getByTestId('recovery-confirm-input').fill(newCode);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('backup-status')).toContainText(en['security.recovery.done']);
  await lock(page);
  await page.getByTestId('forgot-password').click();
  await page.getByTestId('reset-code').fill(oldCode);
  await page.getByTestId('reset-password').fill(PW2);
  await page.getByTestId('reset-password-confirm').fill(PW2);
  await page.getByTestId('reset-submit').click();
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.wrongRecovery']);
  await page.getByTestId('reset-code').fill(newCode);
  await page.getByTestId('reset-submit').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('plain-HTTP non-loopback origin: password vaults refused, demo still usable', async () => {
  // A hostname mapped to loopback is NOT potentially trustworthy (W3C Secure
  // Contexts), unlike 127.0.0.1 itself, so this reproduces the LAN/VPN
  // preview's insecure context without binding any other interface.
  const browser = await chromium.launch({ args: ['--host-resolver-rules=MAP keymesh-http.test 127.0.0.1'] });
  try {
    const page = await browser.newPage();
    await page.goto('http://keymesh-http.test:4310/');
    expect(await page.evaluate(() => isSecureContext)).toBe(false);
    await expect(page.getByTestId('insecure-notice')).toContainText(en['protected.insecure.body']);
    await expect(page.getByTestId('create-password')).toHaveCount(0);
    await expect(page.getByTestId('protected-restore-input')).toHaveCount(0);
    await expect(page.getByTestId('unlock-password')).toHaveCount(0);
    // The password-vault database is never even opened.
    expect(await page.evaluate(async () => (await indexedDB.databases()).map((d) => d.name))).not.toContain(PDB);
    // Demo still works.
    await page.locator('input[name=mode][value=synthetic-fixture]').check();
    await page.getByTestId('start-vault').click();
    await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    await expect(page.getByTestId('demo-banner')).toContainText(en['demo.label']);
  } finally {
    await browser.close();
  }
});

test('a demo vault stays a demo vault next to a password vault (no conversion)', async ({ page }) => {
  await page.goto('/');
  // Ephemeral: its key exists only in this page's memory.
  await page.locator('input[name=mode][value=ephemeral]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'ephemeral');
  const demoBefore = await storedBytes(page);
  await page.getByTestId('lock').click();
  // A password vault is created fresh, in its own database.
  await page.getByTestId('create-password').fill(PW);
  await page.getByTestId('create-password-confirm').fill(PW);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const code = await readCode(page);
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await expect(titles(page)).toHaveCount(0);
  const prot = JSON.parse((await storedBytes(page, PDB)).toString('utf8'));
  const demo = JSON.parse(demoBefore.toString('utf8'));
  expect(prot.version).toBe(2);
  expect(prot.vault_id).not.toBe(demo.vault_id);
  // The demo envelope is untouched and still opens as a demo.
  expect((await storedBytes(page)).equals(demoBefore)).toBe(true);
  // The demo key survived the password session: the demo still unlocks.
  await page.getByTestId('lock').click();
  await page.getByTestId('unlock').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'ephemeral');
});

for (const withDemo of [true, false]) {
  test(`stale password vault: "Load latest version" returns to password entry and never opens the demo (demo ${withDemo ? 'present' : 'absent'})`, async ({ context }, testInfo) => {
    const a = await context.newPage();
    const consoleLines: string[] = [];
    a.on('console', (m) => consoleLines.push(m.text()));
    let demoBefore: Buffer = Buffer.alloc(0);
    if (withDemo) {
      await a.goto('/');
      await a.locator('input[name=mode][value=synthetic-fixture]').check();
      await a.getByTestId('start-vault').click();
      await expect(a.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
      await a.getByTestId('lock').click();
      demoBefore = await storedBytes(a);
      expect(demoBefore.length).toBeGreaterThan(0);
    }
    const code = await createVault(a);
    await a.getByTestId('nav-backup').click();

    // Tab B replaces the password vault with a different valid backup.
    const b = await context.newPage();
    await b.goto('/');
    await unlock(b, PW);
    await expect(b.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
    await b.getByTestId('nav-backup').click();
    const path = testInfo.outputPath('replacement.keymesh');
    await writeFile(path, vectors.envelope.json);
    await b.getByTestId('protected-restore-input').setInputFiles(path);
    await b.getByTestId('restore-password').fill(vectors.envelope.password);
    await b.getByTestId('protected-restore').click();
    await expect(b.getByTestId('backup-status')).toContainText(en['backup.restored'], { timeout: 30_000 });
    const current = await storedBytes(b, PDB);

    // Tab A is stale; its reload must stay on the password vault.
    await expect(a.locator('.callout.stale')).toBeVisible({ timeout: 30_000 });
    await a.locator('.callout.stale button').click();
    await expect(a.getByTestId('unlock-password')).toBeVisible();
    await expect(a.getByTestId('protected-reloaded')).toContainText(en['protected.reloaded']);
    await expect(a.getByTestId('key-mode')).toHaveCount(0); // nothing is open
    await expect(a.getByTestId('start-error')).toHaveCount(0);
    expect((await storedBytes(a)).equals(demoBefore), 'demo vault untouched').toBe(true);
    expect((await storedBytes(a, PDB)).equals(current), 'stale tab wrote nothing').toBe(true);

    // The old password no longer opens the CURRENT copy; the new copy's does.
    await unlock(a, PW);
    await expect(a.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
    await unlock(a, vectors.envelope.password);
    await expect(a.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
    await expect(titles(a)).toHaveText(vectors.envelope.titles);
    await assertNothingLeaked(a, [PW, code, vectors.envelope.recovery_code], consoleLines);
    if (withDemo) {
      // The demo is still there and still a demo, opened only on request.
      await a.getByTestId('lock').click();
      await a.locator('[data-testid=unlock], [data-testid=open-fixture]').click();
      await expect(a.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
    }
  });
}
