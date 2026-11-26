/**
 * Quick unlock with a WebAuthn PRF passkey (M5 C1), production build, real
 * Rust/WASM. The authenticator is Chromium's DevTools VIRTUAL authenticator
 * (CTAP2.1, internal, user verification, PRF/hmac-secret). This is evidence
 * about Keymesh's handling only: NOT TouchID, FaceID, Windows Hello, Android
 * or iOS, and not any real security key. WebAuthn needs a domain RP id, so
 * the page is opened on http://localhost (a secure context).
 * SYNTHETIC DATA ONLY.
 */
import { CDPSession, Page, TestInfo, expect, test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { en } from '../src/app/core/i18n/en';
import { M, assertNoMarkers, field, newItem, create, storedBytes } from './helpers';

test.use({ serviceWorkers: 'block' });

function shot(testInfo: TestInfo, name: string): string {
  const dir = process.env['KEYMESH_SCREENSHOT_DIR'];
  if (!dir) return testInfo.outputPath(name);
  mkdirSync(dir, { recursive: true });
  return join(dir, name);
}

const PW = 'synthetic quick unlock passphrase one';
const PW2 = 'synthetic quick unlock passphrase two';

async function authenticator(page: Page, opts: { prf?: boolean; uv?: boolean } = {}): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: opts.uv ?? true,
      hasPrf: opts.prf ?? true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, id: authenticatorId };
}

function localhost(baseURL: string | undefined): string {
  return (baseURL ?? 'http://127.0.0.1:4310').replace('127.0.0.1', 'localhost');
}

async function readCode(page: Page): Promise<string> {
  return page.getByTestId('recovery-code').last().evaluate((el) => Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'));
}

async function createVault(page: Page, origin: string) {
  await page.goto(origin + '/');
  await page.getByTestId('create-password').fill(PW);
  await page.getByTestId('create-password-confirm').fill(PW);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  const code = await readCode(page);
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  return code;
}

async function enrol(page: Page, label: string) {
  await page.getByTestId('nav-backup').click();
  const q = page.getByTestId('quick-unlock-section');
  await q.getByTestId('qu-current').fill(PW);
  await q.getByTestId('qu-label').fill(label);
  await q.getByTestId('qu-add').click();
}

test('enrol, lock, reload, unlock with the passkey; ciphertext only; remove; master password still works', async ({ page, baseURL }, testInfo) => {
  test.setTimeout(150_000);
  const origin = localhost(baseURL);
  const { cdp, id } = await authenticator(page);
  await createVault(page, origin);
  await newItem(page, 'secure_note');
  await field(page, 'Title').fill('Synthetic passkey note');
  await page.getByLabel('Note', { exact: true }).fill(M.noteBody);
  await create(page, 'Synthetic passkey note');
  await enrol(page, 'Synthetic laptop');
  await expect(page.getByTestId('backup-status')).toContainText(en['qu.added'], { timeout: 30_000 });
  await expect(page.getByTestId('qu-item')).toHaveCount(1);
  await expect(page.getByTestId('qu-item')).toHaveAttribute('data-be', 'false');
  // The sync status is stated per passkey: a badge and a note (this virtual one is device-bound).
  await expect(page.getByTestId('qu-sync')).toHaveText(en['qu.badge.be0']);
  await expect(page.getByTestId('qu-sync-note')).toHaveText(en['qu.be0']);
  await page.getByTestId('quick-unlock-section').scrollIntoViewIfNeeded();
  await page.screenshot({ path: shot(testInfo, 'm5c-quick-unlock-card-en.png'), fullPage: true });
  const stored = Buffer.from(await storedBytes(page, 'keymesh-vault'));
  assertNoMarkers(stored, 'vault with passkey slot');
  const slot = JSON.parse(stored.toString()).slots.find((s: { kind: string }) => s.kind === 'webauthn-prf');
  expect(slot.kdf.alg).toBe('webauthn-prf-hkdf');
  expect(slot.kdf.rp_id).toBe('localhost');
  expect(slot.kdf.label).toBe('Synthetic laptop');
  const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId: id });
  expect(creds.credentials).toHaveLength(1);

  await page.getByTestId('lock').click();
  await page.reload();
  await expect(page.getByTestId('unlock-passkey')).toBeVisible();
  // Lock screen: the passkey button is focused, but nothing starts without the
  // user's click (this virtual authenticator would answer a ceremony at once).
  await expect(page.getByTestId('unlock-passkey')).toBeFocused();
  await page.waitForTimeout(1_000);
  await expect(page.getByTestId('key-mode')).toHaveCount(0);
  await expect(page.getByTestId('delete-protected')).toBeHidden();
  // Passkey first: the master password waits behind "Use master password".
  await expect(page.getByTestId('passkey-hero')).toBeVisible();
  const toggle = page.getByTestId('use-password');
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(page.getByTestId('unlock-password')).toBeHidden();
  await expect(page.getByTestId('forgot-password')).toBeHidden();
  await page.screenshot({ path: shot(testInfo, 'm5c-locked-passkey-button-en.png'), fullPage: true });
  // Keyboard: Tab reaches the toggle, Enter expands it and focus lands in the field.
  await page.keyboard.press('Tab');
  await expect(toggle).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(page.getByTestId('unlock-password')).toBeFocused();
  await expect(page.getByTestId('forgot-password')).toBeVisible();
  await page.screenshot({ path: shot(testInfo, 'm5c-locked-passkey-expanded-en.png'), fullPage: true });
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(page.getByTestId('unlock-password')).toBeHidden();
  await expect(page.getByTestId('key-mode')).toHaveCount(0);
  await page.getByTestId('unlock-passkey').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  await expect(page.locator('.item-list')).toContainText('Synthetic passkey note');

  // Remove it (master password needed); then the passkey button disappears.
  await page.getByTestId('nav-backup').click();
  const q = page.getByTestId('quick-unlock-section');
  await q.getByTestId('qu-current').fill(PW);
  await q.getByTestId('qu-remove').click();
  await expect(page.getByTestId('backup-status')).toContainText(en['qu.removed'], { timeout: 30_000 });
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock-passkey')).toHaveCount(0);
  await page.getByTestId('unlock-password').fill(PW);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('an authenticator without PRF cannot enrol: nothing written, the orphan is reported', async ({ page, baseURL }) => {
  test.setTimeout(120_000);
  const origin = localhost(baseURL);
  await authenticator(page, { prf: false });
  await createVault(page, origin);
  const before = Buffer.from(await storedBytes(page, 'keymesh-vault'));
  await enrol(page, 'No PRF');
  await expect(page.getByTestId('backup-error')).toBeVisible({ timeout: 30_000 });
  const msg = await page.getByTestId('backup-error').textContent();
  expect([en['errors.quickUnlockUnsupported'], en['errors.quickUnlockOrphan']].some((m) => msg?.includes(m))).toBe(true);
  expect(Buffer.from(await storedBytes(page, 'keymesh-vault')).equals(before)).toBe(true);
});

test('wrong master password at enrolment: refused before any passkey is created', async ({ page, baseURL }) => {
  test.setTimeout(120_000);
  const origin = localhost(baseURL);
  const { cdp, id } = await authenticator(page);
  await createVault(page, origin);
  await page.getByTestId('nav-backup').click();
  const q = page.getByTestId('quick-unlock-section');
  await q.getByTestId('qu-current').fill('synthetic wrong passphrase here');
  await q.getByTestId('qu-add').click();
  await expect(page.getByTestId('backup-error')).toContainText(en['errors.wrongPassword'], { timeout: 30_000 });
  const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId: id });
  expect(creds.credentials).toHaveLength(0); // no orphan: checked before create()
  const stored = JSON.parse(Buffer.from(await storedBytes(page, 'keymesh-vault')).toString());
  expect(stored.slots.some((s: { kind: string }) => s.kind === 'webauthn-prf')).toBe(false);
});

test('rotation with a passkey: refused until revocation is confirmed; afterwards the passkey no longer unlocks', async ({ page, baseURL }) => {
  test.setTimeout(180_000);
  const origin = localhost(baseURL);
  await authenticator(page);
  await createVault(page, origin);
  await enrol(page, 'Synthetic phone');
  await expect(page.getByTestId('backup-status')).toContainText(en['qu.added'], { timeout: 30_000 });
  const r = page.getByTestId('rotate-section');
  await r.getByTestId('rotate-current').fill(PW);
  await r.getByTestId('rotate-new').fill(PW2);
  await r.getByTestId('rotate-confirm').fill(PW2);
  await r.getByTestId('begin-rotation').click();
  await expect(page.getByTestId('backup-error')).toContainText(en['errors.quickUnlockRevokeRequired'], { timeout: 30_000 });
  await r.getByTestId('rotate-current').fill(PW);
  await r.getByTestId('rotate-new').fill(PW2);
  await r.getByTestId('rotate-confirm').fill(PW2);
  await r.getByTestId('rotate-revoke-quick-unlock').check();
  await r.getByTestId('begin-rotation').click();
  await expect(r.getByTestId('recovery-step')).toBeVisible({ timeout: 60_000 });
  const code = await readCode(page);
  await r.getByTestId('recovery-saved').check();
  await r.getByTestId('recovery-confirm-input').fill(code);
  await r.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('backup-status')).toContainText(en['security.rotate.done'], { timeout: 30_000 });
  await expect(page.getByTestId('qu-none')).toBeVisible();
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock-passkey')).toHaveCount(0);
});

test('lock during the passkey ceremony: aborted, never unlocked by a late result', async ({ page, baseURL }) => {
  test.setTimeout(120_000);
  const origin = localhost(baseURL);
  const { cdp, id } = await authenticator(page);
  await createVault(page, origin);
  await enrol(page, 'Synthetic key');
  await expect(page.getByTestId('backup-status')).toContainText(en['qu.added'], { timeout: 30_000 });
  await page.getByTestId('lock').click();
  // Hold the ceremony: the virtual authenticator stops answering presence.
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: id, enabled: false });
  await page.getByTestId('unlock-passkey').click();
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: id, enabled: true });
  // The cancelled operation has settled (button usable again), and it did not unlock.
  await expect(page.getByTestId('unlock-passkey')).toBeEnabled();
  await expect(page.getByTestId('key-mode')).toHaveCount(0);
  await expect(page.getByTestId('unlock-password')).toBeVisible();
});

test('中文 mobile dark: an orphan passkey is explained on the LOCKED screen with its label and time', async ({ browser, baseURL }, testInfo) => {
  test.setTimeout(150_000);
  const ctx = await browser.newContext({ locale: 'zh-TW', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, colorScheme: 'dark', serviceWorkers: 'block' });
  const page = await ctx.newPage();
  const origin = localhost(baseURL);
  const { cdp, id } = await authenticator(page, { prf: false });
  await createVault(page, origin);
  await page.getByTestId('bnav-backup').click();
  const q = page.getByTestId('quick-unlock-section');
  await q.getByTestId('qu-current').fill(PW);
  await q.getByTestId('qu-label').fill('合成測試金鑰');
  await q.getByTestId('qu-add').click();
  await expect(page.getByTestId('backup-error')).toBeVisible({ timeout: 30_000 });
  // The authenticator really made a credential that is not in the vault.
  expect((await cdp.send('WebAuthn.getCredentials', { authenticatorId: id })).credentials).toHaveLength(1);
  const stored = JSON.parse(Buffer.from(await storedBytes(page, 'keymesh-vault')).toString());
  expect(stored.slots.some((s: { kind: string }) => s.kind === 'webauthn-prf')).toBe(false);
  await page.getByTestId('lock').click();
  const notice = page.getByTestId('credential-notice');
  await expect(notice).toHaveAttribute('data-code', 'quickUnlockOrphan');
  await expect(page.getByTestId('credential-notice-passkey')).toContainText('合成測試金鑰');
  await expect(page.getByTestId('unlock-password')).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: shot(testInfo, 'm5c-orphan-notice-zh-TW-mobile-dark.png'), fullPage: true });
  await ctx.close();
});

/**
 * Review fix (m5c P2): the idle deadline must be checked on async
 * continuations, not only by the best-effort timer. Model: auto-lock's 5 s
 * timer never runs (as on a frozen/background page), getClientCapabilities()
 * is held, and the wall clock passes the 5-minute idle deadline meanwhile.
 * Releasing the capability must LOCK the vault: no passkey ceremony and no
 * enrolment write. Virtual authenticator; not a real frozen-page proof.
 */
async function expiredDuringEnrolment(page: Page, baseURL: string | undefined, holdAt: 'capability' | 'ceremony') {
  await page.clock.install({ time: new Date('2026-11-16T10:00:00Z') });
  await page.addInitScript((at) => {
    const w = window as unknown as Record<string, unknown>;
    const interval = window.setInterval.bind(window);
    window.setInterval = ((h: TimerHandler, ms?: number, ...a: unknown[]) => (ms === 5000 ? 0 : interval(h, ms, ...a))) as typeof setInterval;
    let release!: (v: Record<string, boolean>) => void;
    const pending = new Promise<Record<string, boolean>>((r) => (release = r));
    w['__entered'] = false;
    w['__release'] = () => release({ 'extension:prf': true });
    if (at === 'capability') {
      (PublicKeyCredential as unknown as { getClientCapabilities: () => Promise<Record<string, boolean>> }).getClientCapabilities = () => {
        w['__entered'] = true;
        return pending;
      };
    } else {
      // The REAL create() runs (the virtual authenticator makes a
      // credential); only its return to the app is held.
      const create = navigator.credentials.create.bind(navigator.credentials);
      navigator.credentials.create = async (o?: CredentialCreationOptions) => {
        const result = await create(o);
        w['__entered'] = true;
        await pending;
        return result;
      };
    }
  }, holdAt);
  const { cdp, id } = await authenticator(page);
  const origin = localhost(baseURL);
  await createVault(page, origin);
  await page.getByTestId('nav-backup').click();
  const q = page.getByTestId('quick-unlock-section');
  await q.getByTestId('qu-current').fill(PW);
  await q.getByTestId('qu-label').fill('Synthetic deadline probe');
  const before = Buffer.from(await storedBytes(page, 'keymesh-vault'));
  await q.getByTestId('qu-add').click();
  await expect.poll(() => page.evaluate(() => (window as unknown as Record<string, unknown>)['__entered'])).toBe(true);
  const now = await page.evaluate(() => Date.now());
  await page.clock.setSystemTime(new Date(now + 301_000)); // past the 5-minute idle deadline, no input
  await page.evaluate(() => (window as unknown as Record<string, () => void>)['__release']());
  await expect(page.getByTestId('lock')).toHaveCount(0, { timeout: 30_000 }); // locked
  await expect(page.getByTestId('autolock-reason')).toHaveAttribute('data-reason', 'idle');
  expect(Buffer.from(await storedBytes(page, 'keymesh-vault')).equals(before)).toBe(true); // nothing written
  const creds = (await cdp.send('WebAuthn.getCredentials', { authenticatorId: id })).credentials;
  if (holdAt === 'capability') {
    expect(creds).toHaveLength(0); // no ceremony
    return;
  }
  // A credential exists that is not in the vault: the LOCKED screen must say so.
  expect(creds).toHaveLength(1);
  await expect(page.getByTestId('credential-notice')).toHaveAttribute('data-code', 'quickUnlockOrphan');
  await expect(page.getByTestId('credential-notice-passkey')).toContainText('Synthetic deadline probe');
  // The original password still opens the unchanged vault; the guidance stays until acknowledged.
  await page.getByTestId('unlock-password').fill(PW);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
  expect(Buffer.from(await storedBytes(page, 'keymesh-vault')).equals(before)).toBe(true);
  await expect(page.getByTestId('credential-notice')).toHaveAttribute('data-code', 'quickUnlockOrphan');
}

test('idle deadline passes while the real create() result is held: locked, no write, orphan guidance on the locked screen (real WASM)', async ({ page, baseURL }) => {
  test.setTimeout(150_000);
  await expiredDuringEnrolment(page, baseURL, 'ceremony');
});

/** Real IndexedDB boundaries of the enrolment write (from the independent review's probes). */
for (const boundary of ['preput-deadline', 'postput-pagehide'] as const) {
  test(`enrolment write boundary ${boundary}: exact persistence and the right locked-screen notice`, async ({ page, baseURL }) => {
    test.setTimeout(150_000);
    const { cdp, id } = await authenticator(page);
    await createVault(page, localhost(baseURL));
    const before = Buffer.from(await storedBytes(page, 'keymesh-vault'));
    await page.evaluate((at) => {
      const w = window as unknown as Record<string, unknown>;
      w['__puts'] = 0;
      w['__hit'] = false;
      const get = IDBObjectStore.prototype.get;
      const put = IDBObjectStore.prototype.put;
      IDBObjectStore.prototype.get = function (this: IDBObjectStore, key: IDBValidKey | IDBKeyRange) {
        const r = get.call(this, key);
        if (at === 'preput-deadline' && this.transaction.db.name === 'keymesh-vault' && this.transaction.mode === 'readwrite') {
          r.addEventListener('success', () => {
            w['__hit'] = true;
            const later = Date.now() + 301_000; // the deadline passes between the CAS read and put
            Date.now = () => later;
          });
        }
        return r;
      };
      IDBObjectStore.prototype.put = function (this: IDBObjectStore, ...a: Parameters<IDBObjectStore['put']>) {
        const r = put.apply(this, a);
        if (this.transaction.db.name === 'keymesh-vault') {
          w['__puts'] = (w['__puts'] as number) + 1;
          if (at === 'postput-pagehide') {
            r.addEventListener('success', () => {
              w['__hit'] = true;
              dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
            });
          }
        }
        return r;
      };
    }, boundary);
    await page.getByTestId('nav-backup').click();
    const q = page.getByTestId('quick-unlock-section');
    await q.getByTestId('qu-current').fill(PW);
    await q.getByTestId('qu-label').fill('Synthetic ' + boundary);
    await q.getByTestId('qu-add').click();
    await expect.poll(() => page.evaluate(() => (window as unknown as Record<string, unknown>)['__hit']), { timeout: 30_000 }).toBe(true);
    const pre = boundary === 'preput-deadline';
    // Saved while locked: the passkey is offered first (password behind the toggle); not saved: password only.
    if (pre) await expect(page.getByTestId('unlock-password')).toBeVisible();
    else await expect(page.getByTestId('use-password')).toBeVisible();
    await expect(page.getByTestId('credential-notice')).toHaveAttribute('data-code', pre ? 'quickUnlockOrphan' : 'quickUnlockSavedWhileLocked', { timeout: 30_000 });
    const after = Buffer.from(await storedBytes(page, 'keymesh-vault'));
    expect(after.equals(before)).toBe(pre);
    expect(await page.evaluate(() => (window as unknown as Record<string, unknown>)['__puts'])).toBe(pre ? 0 : 1);
    expect(JSON.parse(after.toString()).slots.filter((s: { kind: string }) => s.kind === 'webauthn-prf')).toHaveLength(pre ? 0 : 1);
    expect((await cdp.send('WebAuthn.getCredentials', { authenticatorId: id })).credentials).toHaveLength(1);
  });
}

test('idle deadline passes while getClientCapabilities() is pending: locks, no ceremony, no write', async ({ page, baseURL }) => {
  test.setTimeout(150_000);
  await expiredDuringEnrolment(page, baseURL, 'capability');
});

test('passkey gone from the authenticator: the error shows and the master password opens by itself', async ({ page, baseURL }, testInfo) => {
  test.setTimeout(150_000);
  const origin = localhost(baseURL);
  const { cdp, id } = await authenticator(page);
  await createVault(page, origin);
  await enrol(page, 'Synthetic removed key');
  await expect(page.getByTestId('backup-status')).toContainText(en['qu.added'], { timeout: 30_000 });
  await page.getByTestId('lock').click();
  // The user deleted the passkey on the device; the vault still lists its slot.
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId: id });
  await expect(page.getByTestId('use-password')).toHaveAttribute('aria-expanded', 'false');
  await page.getByTestId('unlock-passkey').click();
  await expect(page.getByTestId('protected-error')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId('use-password')).toHaveAttribute('aria-expanded', 'true');
  await expect(page.getByTestId('use-password')).toHaveClass(/attention/);
  await expect(page.getByTestId('unlock-password')).toBeFocused();
  await expect(page.getByTestId('key-mode')).toHaveCount(0);
  await page.screenshot({ path: shot(testInfo, 'passkey-failed-password-offered-en.png'), fullPage: true });
  await page.getByTestId('unlock-password').fill(PW);
  await page.getByTestId('unlock-protected').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
});

test('reduced motion: the passkey screen does not animate', async ({ page, baseURL }) => {
  test.setTimeout(120_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const origin = localhost(baseURL);
  await authenticator(page);
  await createVault(page, origin);
  await enrol(page, 'Synthetic calm key');
  await expect(page.getByTestId('backup-status')).toContainText(en['qu.added'], { timeout: 30_000 });
  await page.getByTestId('lock').click();
  const btn = page.getByTestId('unlock-passkey');
  await expect(btn).toBeVisible();
  expect(await btn.evaluate((el) => getComputedStyle(el).animationName)).toBe('none');
  await btn.hover();
  expect(await btn.evaluate((el) => getComputedStyle(el).transform)).toBe('none');
  const panel = page.getByTestId('password-panel');
  expect(await panel.evaluate((el) => getComputedStyle(el).transitionProperty)).toBe('none');
  await page.getByTestId('use-password').click();
  await expect(page.getByTestId('unlock-password')).toBeFocused();
});

for (const v of [
  { name: 'desktop-en-light', locale: 'en-US', colorScheme: 'light' as const, viewport: { width: 1280, height: 900 }, mobile: false },
  { name: 'phone-zh-TW-dark', locale: 'zh-TW', colorScheme: 'dark' as const, viewport: { width: 390, height: 844 }, mobile: true },
]) {
  test(`passkey-first lock screen screenshots: ${v.name}, collapsed and expanded`, async ({ browser, baseURL }, testInfo) => {
    test.setTimeout(150_000);
    const ctx = await browser.newContext({ locale: v.locale, colorScheme: v.colorScheme, viewport: v.viewport, isMobile: v.mobile, hasTouch: v.mobile, serviceWorkers: 'block' });
    const page = await ctx.newPage();
    await authenticator(page);
    await createVault(page, localhost(baseURL));
    await page.getByTestId(v.mobile ? 'bnav-backup' : 'nav-backup').click();
    const q = page.getByTestId('quick-unlock-section');
    await q.getByTestId('qu-current').fill(PW);
    await q.getByTestId('qu-label').fill('Synthetic key');
    await q.getByTestId('qu-add').click();
    await expect(page.getByTestId('qu-item')).toHaveCount(1, { timeout: 30_000 });
    await q.scrollIntoViewIfNeeded();
    await page.screenshot({ path: shot(testInfo, `backup-passkey-sync-${v.name}.png`), fullPage: true });
    await page.getByTestId('lock').click();
    await expect(page.getByTestId('passkey-hero')).toBeVisible();
    await page.waitForTimeout(600); // entrance animation done
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: shot(testInfo, `lock-passkey-${v.name}-collapsed.png`), fullPage: true });
    await page.getByTestId('use-password').click();
    await expect(page.getByTestId('unlock-password')).toBeFocused();
    await page.waitForTimeout(400); // expand transition done
    await page.screenshot({ path: shot(testInfo, `lock-passkey-${v.name}-expanded.png`), fullPage: true });
    await ctx.close();
  });
}
