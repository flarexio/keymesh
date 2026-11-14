/**
 * Start-screen orientation, demo-mode disclosure, mobile bottom clearance and
 * secondary-text contrast (M4 visual follow-ups). Production build, real
 * WASM, Chromium on 127.0.0.1. SYNTHETIC DATA ONLY.
 *
 * Measurements here are Chromium layout/colour checks, not a real-device or
 * full accessibility audit.
 */
import { Browser, Page, TestInfo, expect, test } from '@playwright/test';
import { en } from '../src/app/core/i18n/en';
import { zhTW } from '../src/app/core/i18n/zh-tw';
import { field, newItem, start } from './helpers';

const PW = 'synthetic orientation passphrase';

/**
 * Review screenshots (test-results/, git-ignored). A recovery code is never
 * captured: its text is made transparent by injected CSS *and* masked, because
 * a mask rectangle alone was observed to miss part of the code on a full-page
 * mobile capture.
 */
const HIDE_CODE = '[data-testid=recovery-code], [data-testid=recovery-code] * { color: transparent !important; text-shadow: none !important; }';
async function shot(page: Page, info: TestInfo, name: string, fullPage = true): Promise<void> {
  await page.screenshot({ path: info.outputPath(name), fullPage, style: HIDE_CODE, mask: [page.getByTestId('recovery-code')], maskColor: '#ff00ff' });
}

async function mobile(browser: Browser, locale = 'en-US', colorScheme: 'light' | 'dark' = 'light') {
  const ctx = await browser.newContext({ locale, colorScheme, hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
  return { ctx, page: await ctx.newPage() };
}

async function top(page: Page, testid: string): Promise<number> {
  const box = await page.getByTestId(testid).boundingBox();
  expect(box, `${testid} rendered`).not.toBeNull();
  return box!.y;
}

/** Create and confirm a password vault (recovery code read, never printed). */
async function createPasswordVault(page: Page, info?: TestInfo): Promise<void> {
  await page.getByTestId('create-password').fill(PW);
  await page.getByTestId('create-password-confirm').fill(PW);
  await page.getByTestId('create-protected').click();
  await expect(page.getByTestId('recovery-step')).toBeVisible({ timeout: 30_000 });
  if (info) {
    await page.getByTestId('recovery-code').scrollIntoViewIfNeeded();
    await shot(page, info, 'mobile-zh-TW-recovery-masked.png', false);
  }
  const code = await page
    .getByTestId('recovery-code')
    .evaluate((el) => Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'));
  await page.getByTestId('recovery-saved').check();
  await page.getByTestId('recovery-confirm-input').fill(code);
  await page.getByTestId('recovery-confirm').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'protected', { timeout: 30_000 });
}

test('mobile: an existing locked demo vault comes first and the overview names both vault kinds', async ({ browser }, info) => {
  const { ctx, page } = await mobile(browser);
  await page.goto('/');
  // Nothing stored yet: both kinds listed as not created.
  const overview = page.getByTestId('vault-overview');
  await expect(overview).toBeVisible();
  await expect(page.getByTestId('overview-protected')).toContainText(en['start.overview.state.none']);
  await expect(page.getByTestId('overview-demo')).toContainText(en['start.overview.state.none']);

  await start(page, 'synthetic-fixture');
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock')).toBeVisible();
  // Locked demo: the overview is in the first screen and the demo card is above password-vault creation.
  await expect(overview).toBeInViewport();
  await expect(page.getByTestId('overview-demo')).toContainText(en['start.overview.state.locked']);
  await expect(page.getByTestId('overview-demo')).toContainText(en['start.overview.demoNote']);
  await expect(page.getByTestId('overview-protected')).toContainText(en['start.overview.state.none']);
  expect(await top(page, 'demo-section')).toBeLessThan(await top(page, 'protected-section'));
  await shot(page, info, 'mobile-en-locked-demo-first.png');

  // After a reload the test-key vault is "saved" and still offered first.
  await page.reload();
  await expect(page.getByTestId('open-fixture')).toBeVisible();
  await expect(page.getByTestId('overview-demo')).toContainText(en['start.overview.state.stored']);
  expect(await top(page, 'demo-section')).toBeLessThan(await top(page, 'protected-section'));

  // The overview's jump button reaches the other card.
  await page.getByTestId('overview-protected').getByRole('button').click();
  await expect(page.locator('#protected-title')).toBeInViewport();
  await ctx.close();
});

test('password vault present: it is listed and shown first, through reload and lock, and the demo never opens', async ({ browser }, info) => {
  const { ctx, page } = await mobile(browser, 'zh-TW');
  await page.goto('/');
  // A demo vault exists too (locked), so both kinds compete for the screen.
  await page.locator('input[name=mode][value=synthetic-fixture]').check();
  await page.getByTestId('start-vault').click();
  await expect(page.getByTestId('key-mode')).toHaveAttribute('data-key-mode', 'synthetic-fixture');
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock')).toBeVisible();
  await createPasswordVault(page, info);
  await expect(page.getByTestId('demo-mode-notice')).toHaveCount(0);
  await page.getByTestId('lock').click();
  await expect(page.getByTestId('unlock-password')).toBeVisible();
  for (const step of ['locked', 'reloaded'] as const) {
    if (step === 'reloaded') {
      await page.reload();
      await expect(page.getByTestId('unlock-password')).toBeVisible();
    }
    await expect(page.getByTestId('overview-protected'), step).toContainText(zhTW['start.overview.state.locked']);
    expect(await top(page, 'protected-section'), step).toBeLessThan(await top(page, 'demo-section'));
    await expect(page.getByTestId('key-mode')).toHaveCount(0);
  }
  await shot(page, info, 'mobile-zh-TW-password-unlock-first.png');
  await ctx.close();
});

for (const [mode, key] of [
  ['synthetic-fixture', 'vault.demoNotice.fixture'],
  ['ephemeral', 'vault.demoNotice.ephemeral'],
] as const) {
  test(`${mode} demo vault says it is not confidential, on desktop and on mobile detail`, async ({ page, browser }, info) => {
    await page.setViewportSize({ width: 1280, height: 860 });
    await start(page, mode);
    await expect(page.getByTestId('demo-mode-notice')).toBeInViewport();
    await expect(page.getByTestId('demo-mode-notice')).toHaveText(en[key]);
    await shot(page, info, `desktop-en-light-${mode}-notice.png`);

    const { ctx, page: m } = await mobile(browser, 'zh-TW', 'dark');
    await m.goto('/');
    await m.locator(`input[name=mode][value=${mode}]`).check();
    await m.getByTestId('start-vault').click();
    await expect(m.getByTestId('key-mode')).toHaveAttribute('data-key-mode', mode);
    await newItem(m, 'secure_note');
    await m.getByLabel(zhTW['field.title'], { exact: true }).fill('Synthetic note');
    await m.locator('form.item-form button[type=submit]').click();
    await expect(m.locator('#detail-title')).toHaveText('Synthetic note');
    await m.evaluate(() => window.scrollTo(0, 0));
    await expect(m.getByTestId('demo-mode-notice')).toBeInViewport();
    await expect(m.getByTestId('demo-mode-notice')).toHaveText(zhTW[key]);
    await m.screenshot({ path: info.outputPath(`mobile-zh-TW-dark-${mode}-notice.png`) });
    await ctx.close();
  });
}

test('mobile: the fixed bottom navigation never covers the end of a long detail (scroll + hit test)', async ({ browser }) => {
  const { ctx, page } = await mobile(browser);
  await start(page, 'synthetic-fixture');
  await newItem(page, 'login');
  await field(page, 'Title').fill('Synthetic long login');
  await field(page, 'Username').fill('synth-user');
  await field(page, 'URLs').fill('https://a.example.test\nhttps://b.example.test\nhttps://c.example.test');
  await field(page, 'Notes').fill(Array.from({ length: 30 }, (_, i) => `synthetic line ${i}`).join('\n'));
  await page.locator('form.item-form button[type=submit]').click();
  await expect(page.locator('#detail-title')).toHaveText('Synthetic long login');
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  const r = await page.evaluate(() => {
    const nav = document.querySelector('.bottom-nav')!.getBoundingClientRect();
    const meta = document.querySelector('.detail [data-testid=item-meta]')!;
    const box = meta.getBoundingClientRect();
    const hit = document.elementFromPoint(box.left + 4, box.bottom - 2);
    return { navTop: nav.top, bottom: box.bottom, hitInside: !!hit && meta.contains(hit), scrollable: document.documentElement.scrollHeight > innerHeight };
  });
  expect(r.scrollable).toBe(true);
  expect(r.bottom, 'last detail line sits above the bottom navigation').toBeLessThanOrEqual(r.navTop);
  expect(r.hitInside, 'last detail line receives the pointer, not the navigation').toBe(true);
  // The Delete action (end of the action row) is reachable too.
  await page.evaluate(() => window.scrollTo(0, 0));
  await expect(page.getByTestId('delete')).toBeInViewport();
  await ctx.close();
});

for (const scheme of ['light', 'dark'] as const) {
  test(`${scheme}: secondary and status text keeps at least 4.5:1 contrast`, async ({ browser }, info) => {
    const ctx = await browser.newContext({ colorScheme: scheme, viewport: { width: 1280, height: 860 } });
    const page = await ctx.newPage();
    await page.goto('/');
    await expect(page.getByTestId('protected-section')).toBeVisible();
    await shot(page, info, `desktop-en-${scheme}-start.png`);
    const startRatios = await ratios(page, ['.start-card .lead', '.start-card .hint', '.start-card .eyebrow', '.vault-overview .overview-note', '.choice-text']);
    await start(page, 'synthetic-fixture');
    await newItem(page, 'secure_note');
    await field(page, 'Title').fill('Synthetic note');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.locator('#detail-title')).toHaveText('Synthetic note');
    const shellRatios = await ratios(page, ['.status-meta', '.status-line', '.item-meta', '.item-list .subtitle', '.list-title .muted', '.demo-mode-notice', '.nav-heading']);
    // Measured values, recorded for review (Chromium computed colours; not a full audit).
    console.log(`contrast ${scheme} ${JSON.stringify({ ...startRatios, ...shellRatios })}`);
    for (const [sel, v] of Object.entries({ ...startRatios, ...shellRatios })) {
      expect(v, `${scheme} ${sel} contrast`).toBeGreaterThanOrEqual(4.5);
    }
    await ctx.close();
  });
}

/** WCAG contrast of each selector's text colour against its effective opaque background. */
async function ratios(page: Page, selectors: string[]): Promise<Record<string, number>> {
  return page.evaluate((sels) => {
    const parse = (c: string) => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) throw new Error(`unparsed colour ${c}`);
      const [r, g, b, a = '1'] = m[1].split(/[ ,/]+/).filter(Boolean);
      return [Number(r), Number(g), Number(b), Number(a)];
    };
    const lum = ([r, g, b]: number[]) => {
      const f = (v: number) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    const bg = (el: Element | null): number[] => {
      for (let e = el; e; e = e.parentElement) {
        const c = parse(getComputedStyle(e).backgroundColor);
        if (c[3] >= 1) return c;
      }
      return parse(getComputedStyle(document.body).backgroundColor);
    };
    const out: Record<string, number> = {};
    for (const s of sels) {
      const el = document.querySelector(s);
      if (!el) throw new Error(`missing ${s}`);
      const fg = parse(getComputedStyle(el).color);
      const b = bg(el);
      // Composite a translucent text colour over its background.
      const mix = fg.slice(0, 3).map((v, i) => v * fg[3] + b[i] * (1 - fg[3]));
      const [l1, l2] = [lum(mix), lum(b)].sort((x, y) => y - x);
      out[s] = Math.round(((l1 + 0.05) / (l2 + 0.05)) * 100) / 100;
    }
    return out;
  }, selectors);
}
