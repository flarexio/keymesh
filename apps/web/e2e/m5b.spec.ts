/**
 * M5 Phase B end to end: production build, real Rust/WASM core and the real
 * Argon2id worker in Chromium. SYNTHETIC DATA ONLY.
 *
 * * Ed25519: raw Base58 public key, signing exact bytes, and strict
 *   verification. Signatures are checked independently with Node's
 *   OpenSSL Ed25519, and RFC 8032 vectors are verified through the app.
 * * Passphrases: words come from the vendored EFF list; Save stores exactly
 *   the preview.
 * * Password vault: suggested passphrase, emergency kit (password never
 *   printed; code only on request), and data-key rotation (new credentials
 *   only; the old backup keeps opening with the old ones).
 *
 * Generated secrets and recovery codes are read into variables, never printed.
 */
import { Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { M, assertNoMarkers, field, newItem, openItem, storedBytes, titles, create } from './helpers';

// Deterministic vault flows; the installed-app worker is covered in pwa.spec.ts.
test.use({ serviceWorkers: 'block' });

function shot(testInfo: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return testInfo.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/** Independent Base58 decode (big integer), not the app's code. */
function b58decode(s: string): Buffer {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error('not base58');
    n = n * 58n + BigInt(i);
  }
  const hex = n === 0n ? '' : n.toString(16).padStart(Math.ceil(n.toString(16).length / 2) * 2, '0');
  const zeros = s.length - s.replace(/^1+/, '').length;
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
}

function nodeEd25519Verify(pub: Buffer, msg: Buffer, sig: Buffer): boolean {
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]);
  return nodeVerify(null, msg, createPublicKey({ key: spki, format: 'der', type: 'spki' }), sig);
}

const EFF = new Set(
  readFileSync(join(__dirname, '../../../src/wordlists/eff_large_wordlist.txt'), 'utf8')
    .trim()
    .split('\n')
    .map((l) => l.split('\t')[1]),
);

/** Click Reveal and read the value only once it is actually shown (not the mask). */
async function revealed(scope: import('@playwright/test').Locator): Promise<string> {
  await scope.getByRole('button', { name: en['secret.reveal'] }).click();
  const v = scope.getByTestId('generated-value');
  await expect(v).not.toContainText('•');
  return (await v.textContent())!.trim();
}

async function demoVault(page: Page) {
  await page.goto('/');
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('lock')).toBeVisible();
}

test('Ed25519: Base58 key, exact-byte signing, and strict verification (independently checked)', async ({ page }, testInfo) => {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await demoVault(page);
  await newItem(page, 'ed25519_key');
  await field(page, 'Title').fill('Synthetic signer');
  await create(page, 'Synthetic signer');

  const tools = page.getByTestId('ed25519-tools');
  const b58 = (await tools.getByTestId('pubkey-base58').textContent())!.trim();
  const hexRow = page.locator('.field-row', { hasText: en['field.publicKeyHex'] }).locator('dd');
  const pubHex = (await hexRow.textContent())!.trim();
  // Base58 is the raw 32 key bytes: decodes (independently) to the hex key.
  expect(b58decode(b58).toString('hex')).toBe(pubHex);
  expect(b58decode(b58)).toHaveLength(32);

  // UTF-8 exactly as typed: a trailing space and a combining accent count.
  const message = 'synthetic message café ';
  await tools.getByTestId('sign-message').fill(message);
  await expect(tools.getByTestId('sign-preview')).toContainText(
    en['sign.bytes'].replace('{n}', String(Buffer.byteLength(message, 'utf8'))),
  );
  await expect(tools.getByTestId('sign-preview')).toContainText(Buffer.from(message, 'utf8').toString('hex'));
  await tools.getByTestId('sign-button').click();
  const sigHex = (await tools.getByTestId('signature-hex').textContent())!.trim();
  const sigB58 = (await tools.getByTestId('signature-base58').textContent())!.trim();
  expect(sigHex).toMatch(/^[0-9a-f]{128}$/);
  expect(b58decode(sigB58).toString('hex')).toBe(sigHex);
  const pub = Buffer.from(pubHex, 'hex');
  expect(nodeEd25519Verify(pub, Buffer.from(message, 'utf8'), Buffer.from(sigHex, 'hex'))).toBe(true);
  expect(nodeEd25519Verify(pub, Buffer.from(message.trim(), 'utf8'), Buffer.from(sigHex, 'hex'))).toBe(false);
  await tools.scrollIntoViewIfNeeded();
  await page.screenshot({ path: shot(testInfo, 'm5b-ed25519-sign-desktop.png'), fullPage: true });
  // Editing the message drops the old signature.
  await tools.getByTestId('sign-message').fill(message + 'x');
  await expect(tools.getByTestId('signature-result')).toHaveCount(0);

  // Hex mode: same bytes → the same (deterministic) signature.
  await tools.getByTestId('sign-enc-hex').check();
  await tools.getByTestId('sign-message').fill('zz');
  await expect(tools.getByTestId('sign-preview-error')).toBeVisible();
  await expect(tools.getByTestId('sign-button')).toBeDisabled();
  await tools.getByTestId('sign-message').fill(Buffer.from(message, 'utf8').toString('hex'));
  await tools.getByTestId('sign-button').click();
  await expect(tools.getByTestId('signature-hex')).toHaveText(sigHex);

  // Verify tool (generators page): valid, tampered, wrong formats.
  await page.getByTestId('nav-generators').click();
  const v = page.getByTestId('verify-card');
  const run = async (key: string, msg: string, sig: string) => {
    await v.getByTestId('verify-key').fill(key);
    await v.getByTestId('verify-message').fill(msg);
    await v.getByTestId('verify-signature').fill(sig);
    await v.getByTestId('verify-button').click();
    return v.getByTestId('verify-result').getAttribute('data-verdict');
  };
  expect(await run(b58, message, sigHex)).toBe('valid');
  expect(await run(pubHex, message, sigB58)).toBe('valid');
  expect(await run(b58, message.trim(), sigHex)).toBe('invalid');
  const flipped = (parseInt(sigHex[0], 16) ^ 1).toString(16) + sigHex.slice(1);
  expect(await run(b58, message, flipped)).toBe('invalid');
  // '0' is not in the Base58 alphabet; a 33-byte hex value is the wrong length.
  // (Dropping a character is NOT a format error: 43 Base58 characters can
  // still be a valid, different 32-byte key, which then verifies as invalid.)
  expect(await run('0' + b58.slice(1), message, sigHex)).toBe('bad_public_key');
  expect(await run(pubHex + '00', message, sigHex)).toBe('bad_public_key');
  expect(await run(b58, message, sigHex.slice(2))).toBe('bad_signature');
  // RFC 8032 §7.1 TEST 2 through the app's strict verifier.
  await v.getByTestId('verify-enc-hex').check();
  expect(
    await run(
      '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
      '72',
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
    ),
  ).toBe('valid');
  await v.scrollIntoViewIfNeeded();
  await page.screenshot({ path: shot(testInfo, 'm5b-verify-valid-desktop.png'), fullPage: true });
  // Small-order public key (identity point) is refused by strict verification.
  expect(
    await run(
      '0100000000000000000000000000000000000000000000000000000000000000',
      '72',
      '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
    ),
  ).toBe('invalid');
  expect(errors).toEqual([]);
});

test('passphrase generator: EFF words, strength shown, Save stores exactly the preview', async ({ page }, testInfo) => {
  await demoVault(page);
  await page.getByTestId('nav-generators').click();
  const card = page.getByTestId('passphrase-card');
  await expect(card.getByTestId('passphrase-strength')).toContainText('77.5');
  await card.getByTestId('passphrase-words').selectOption('5');
  await expect(card.getByTestId('passphrase-strength')).toHaveClass(/field-error/);
  await card.getByTestId('passphrase-words').selectOption('8');
  await card.getByTestId('passphrase-separator').selectOption('period');
  await card.getByTestId('generate-passphrase').click();
  const shown = await revealed(card);
  await card.scrollIntoViewIfNeeded();
  await page.screenshot({ path: shot(testInfo, 'm5b-passphrase-desktop.png'), mask: [card.getByTestId('generated-value')] });
  const words = shown.split('.');
  expect(words).toHaveLength(8);
  expect(words.every((w) => EFF.has(w))).toBe(true);
  await card.getByTestId('save-passphrase').click();
  await page.getByTestId('nav-items').click();
  await openItem(page, en['gen.passphrase.defaultTitle']);
  await page.locator('.detail').getByRole('button', { name: en['secret.reveal'] }).first().click();
  await expect(page.locator('.detail').getByTestId('secret-value').first()).toHaveText(shown);
});

const PW = 'synthetic m5b passphrase one';

/** Create a password vault, using a suggested passphrase; returns it and the code. */
async function createWithSuggestion(page: Page): Promise<{ pw: string; code: string }> {
  await page.goto('/');
  await expect(page.getByTestId('protected-section')).toBeVisible();
  const suggest = page.getByTestId('protected-section').getByTestId('passphrase-suggest');
  await suggest.getByTestId('suggest-passphrase').click();
  const pw = await revealed(suggest);
  expect(pw.split(' ')).toHaveLength(7);
  expect(pw.split(' ').every((w) => EFF.has(w))).toBe(true);
  await expect(suggest.getByTestId('suggest-use')).toBeDisabled();
  await suggest.getByTestId('suggest-stored').check();
  await suggest.getByTestId('suggest-use').click();
  await expect(page.getByTestId('create-password')).toHaveValue(pw);
  await expect(page.getByTestId('create-password-confirm')).toHaveValue(pw);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const code = await readCode(page);
  return { pw, code };
}

async function readCode(page: Page): Promise<string> {
  const code = await page
    .getByTestId('recovery-code')
    .evaluate((el) => Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'));
  expect(code).toMatch(/^([A-Z2-7]{4}-){13}[A-Z2-7]{4}$/);
  return code;
}

async function confirmCode(page: Page, code: string) {
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code);
  await page.getByTestId('recovery-confirm').click();
}

test('emergency kit: printed sheet never holds the password; the code only when asked', async ({ page }) => {
  // Record what is on the sheet when print() is called, instead of printing.
  await page.addInitScript(() => {
    (window as unknown as { __kit: string[] }).__kit = [];
    window.print = () => {
      const sheet = document.querySelector('[data-testid=kit-sheet]');
      (window as unknown as { __kit: string[] }).__kit.push(sheet ? (sheet.textContent ?? '') : '<none>');
    };
  });
  const { pw, code } = await createWithSuggestion(page);
  const kit = page.getByTestId('emergency-kit');
  await kit.locator('summary').click();
  await kit.getByTestId('kit-print').click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { __kit: string[] }).__kit.length)).toBe(1);
  await kit.getByTestId('kit-include-code').check();
  await kit.getByTestId('kit-print').click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { __kit: string[] }).__kit.length)).toBe(2);
  const [plain, withCode] = await page.evaluate(() => (window as unknown as { __kit: string[] }).__kit);
  for (const sheet of [plain, withCode]) {
    expect(sheet).toContain(en['kit.sheetTitle']);
    expect(sheet).toContain(en['kit.sheetNeedCredential'].slice(0, 30));
    expect(sheet.includes(pw)).toBe(false);
  }
  expect(plain.includes(code)).toBe(false);
  expect(withCode.includes(code)).toBe(true);
  // The sheet is removed again after printing.
  await expect(page.getByTestId('kit-sheet')).toHaveCount(0);
  await confirmCode(page, code);
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('data-key rotation: new credentials only; the old backup keeps its old ones', async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  // Create with a typed password (the suggestion flow is covered above).
  await page.goto('/');
  await page.getByTestId('create-password').fill(PW);
  await page.getByTestId('create-password-confirm').fill(PW);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const oldCode = await readCode(page);
  await confirmCode(page, oldCode);
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await newItem(page, 'secure_note');
  await field(page, 'Title').fill('Synthetic rotated note');
  await page.getByLabel('Note', { exact: true }).fill(M.noteBody);
  await create(page, 'Synthetic rotated note');

  // Old backup.
  await page.getByTestId('nav-backup').click();
  const oldPath = testInfo.outputPath('before-rotation.keymesh');
  const dl = page.waitForEvent('download');
  await page.getByTestId('backup-download').click();
  await (await dl).saveAs(oldPath);
  const before = await storedBytes(page, 'keymesh-vault');

  // Rotate: same password refused; then a suggested new passphrase.
  const r = page.getByTestId('rotate-section');
  await r.getByTestId('rotate-current').fill(PW);
  await r.getByTestId('rotate-new').fill(PW);
  await r.getByTestId('rotate-confirm').fill(PW);
  await r.getByTestId('begin-rotation').click();
  await expect(page.getByTestId('backup-error')).toContainText(en['errors.samePassword']);
  const suggest = r.getByTestId('passphrase-suggest');
  await suggest.getByTestId('suggest-passphrase').click();
  const newPw = await revealed(suggest);
  await suggest.getByTestId('suggest-stored').check();
  await suggest.getByTestId('suggest-use').click();
  await r.scrollIntoViewIfNeeded();
  await page.screenshot({ path: shot(testInfo, 'm5b-rotation-form-desktop.png'), fullPage: true, mask: [r.getByTestId('generated-value')] });
  await r.getByTestId('begin-rotation').click();
  await expect(r.getByTestId('recovery-step')).toBeVisible({ timeout: 60_000 });
  await page.screenshot({ path: shot(testInfo, 'm5b-rotation-code-desktop.png'), fullPage: true, mask: [page.getByTestId('recovery-code')] });
  const newCode = await readCode(page);
  expect(newCode).not.toBe(oldCode);
  // The old code typed back is refused; nothing stored yet.
  await r.getByTestId('recovery-saved').check();
  await r.getByTestId('recovery-confirm-input').fill(oldCode);
  await r.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('backup-error')).toContainText(en['errors.recoveryMismatch']);
  expect(Buffer.from(await storedBytes(page, 'keymesh-vault')).equals(Buffer.from(before))).toBe(true);
  await r.getByTestId('recovery-confirm-input').fill(newCode);
  await r.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('backup-status')).toContainText(en['security.rotate.done'], { timeout: 30_000 });
  await page.screenshot({ path: shot(testInfo, 'm5b-rotation-done-desktop.png'), fullPage: true });

  const after = await storedBytes(page, 'keymesh-vault');
  assertNoMarkers(Buffer.from(after), 'rotated vault');
  const [jb, ja] = [JSON.parse(Buffer.from(before).toString()), JSON.parse(Buffer.from(after).toString())];
  expect(ja.vault_id).toBe(jb.vault_id);
  expect(ja.revision).toBe(jb.revision + 1);
  expect(ja.items[0].id).toBe(jb.items[0].id);
  expect(ja.items[0].sealed.ct).not.toBe(jb.items[0].sealed.ct);
  expect(ja.slots.map((s: { id: string }) => s.id)).not.toEqual(jb.slots.map((s: { id: string }) => s.id));

  // Lock, reload: the old password is refused, the new one opens it.
  await page.getByTestId('lock').click();
  await page.reload();
  await page.getByTestId('unlock-password').fill(PW);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  await page.getByTestId('unlock-password').fill(newPw);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await expect(titles(page)).toHaveText(['Synthetic rotated note']);

  // The old recovery code no longer resets it; the new one would (checked on
  // the reset form's error only, to keep the vault as is).
  await page.getByTestId('lock').click();
  await page.getByTestId('forgot-password').click();
  await page.getByTestId('reset-code').fill(oldCode);
  await page.getByTestId('reset-password').fill('synthetic m5b passphrase three');
  await page.getByTestId('reset-password-confirm').fill('synthetic m5b passphrase three');
  await page.getByTestId('reset-submit').click();
  await expect(page.getByTestId('protected-error')).toContainText(en['errors.wrongRecovery'], { timeout: 30_000 });

  // The OLD backup still opens with the OLD password: restore it over the
  // vault (after unlocking with the new one), then unlock needs PW again.
  await page.reload();
  await page.getByTestId('unlock-password').fill(newPw);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await page.getByTestId('nav-backup').click();
  await page.getByTestId('protected-restore-input').setInputFiles(oldPath);
  await page.getByTestId('restore-password').fill(PW);
  await page.getByTestId('protected-restore').click();
  await expect(page.getByTestId('backup-status')).toContainText(en['backup.restored'], { timeout: 30_000 });
  expect(Buffer.from(await storedBytes(page, 'keymesh-vault')).equals(readFileSync(oldPath))).toBe(true);
  expect(errors).toEqual([]);
});

test('mobile, 中文: signing panel and rotation card fit the narrow layout', async ({ browser }, testInfo) => {
  const ctx = await browser.newContext({ locale: 'zh-TW', viewport: { width: 390, height: 844 }, isMobile: true, serviceWorkers: 'block' });
  const page = await ctx.newPage();
  await demoVault(page);
  await newItem(page, 'ed25519_key');
  await page.getByLabel('標題', { exact: true }).fill('Synthetic signer');
  await page.getByRole('button', { name: '建立' }).click();
  const tools = page.getByTestId('ed25519-tools');
  await tools.getByTestId('sign-message').fill('synthetic message');
  await tools.getByTestId('sign-button').click();
  await expect(tools.getByTestId('signature-hex')).toHaveText(/^[0-9a-f]{128}$/);
  // No horizontal page scroll from the long key/signature values.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await tools.scrollIntoViewIfNeeded();
  await page.screenshot({ path: shot(testInfo, 'm5b-ed25519-sign-mobile-zh-TW.png'), fullPage: true });
  await ctx.close();
});
