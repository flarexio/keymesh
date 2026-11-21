// Regenerates the PWA icons in public/icons/ from the app's own logo
// (src/app/shared/icon.ts `logo`: same paths, drawn here at icon scale).
// Rasterised with the Playwright Chromium already used for E2E; no network.
//   node scripts/make-icons.mjs
// The PNGs are committed; rerun only when the logo or accent colour changes.
import { chromium } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const out = fileURLToPath(new URL('../public/icons/', import.meta.url));
const ACCENT = '#4b43c4'; // --accent (light)
const FG = '#ffffff'; // --accent-fg (light)
// Logo paths (24x24 viewBox), copied from icon.ts.
const circle = (cx, cy, r) => `M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
const LOGO = ['M12 2.5l8.5 4.9v9.2L12 21.5l-8.5-4.9V7.4z', circle(12, 10.5, 2.3), 'M12 12.8v3.7'];

/**
 * `any` icons: rounded tile with the logo filling most of it.
 * `maskable`: full-bleed background; the logo stays inside the 80% safe zone
 * (W3C manifest "maskable" purpose), so any platform mask keeps it whole.
 */
function svg(size, { maskable }) {
  const inner = maskable ? 0.5 : 0.62; // logo box as a fraction of the icon
  const s = (size * inner) / 24;
  const off = (size - 24 * s) / 2;
  const radius = maskable ? 0 : size * 0.22;
  const paths = LOGO.map((d) => `<path d="${d}"/>`).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
  <rect width="${size}" height="${size}" rx="${radius}" fill="${ACCENT}"/>
  <g transform="translate(${off} ${off}) scale(${s})" fill="none" stroke="${FG}" stroke-width="1.8"
     stroke-linecap="round" stroke-linejoin="round">${paths}</g>
</svg>`;
}

const targets = [
  { file: 'icon-192.png', size: 192, maskable: false },
  { file: 'icon-512.png', size: 512, maskable: false },
  { file: 'maskable-512.png', size: 512, maskable: true },
  // iOS home screen: opaque, square; iOS applies its own corner mask.
  { file: 'apple-touch-icon.png', size: 180, maskable: true },
];

await mkdir(out, { recursive: true });
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  for (const t of targets) {
    await page.setViewportSize({ width: t.size, height: t.size });
    await page.setContent(`<html><body style="margin:0;background:transparent">${svg(t.size, t)}</body></html>`);
    const png = await page.locator('svg').screenshot({ omitBackground: true });
    await writeFile(out + t.file, png);
    console.log(`${t.file} ${t.size}x${t.size} ${png.length} bytes`);
  }
} finally {
  await browser.close();
}
