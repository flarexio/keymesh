# Keymesh web demo

An Angular 22 app running the real Keymesh Rust core, compiled to WebAssembly (`crates/keymesh-wasm`). Runtime language 繁體中文 (zh-TW) / English and System / Light / Dark appearance (M3).

> **Synthetic demo, not production.**
> - The key provider is development-only and memory-only.
> - There is no real unlock, recovery or account system.
> - Do not enter real secrets.

## Build and run (loopback only)

You need a Rust toolchain with the `wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.129 (must match the crate pin) and Node 24+.

```sh
npm ci
npm run build:wasm     # cargo build --target wasm32 + wasm-bindgen → src/app/core/wasm-pkg, public/wasm
npm run build          # production build → dist/web/browser (strict template type checking)
npm start              # serves dist/web/browser on http://127.0.0.1:4310 (loopback only)
```

## Checks

```sh
npm run typecheck      # app, unit-test and e2e TypeScript configs
npm test               # Vitest: forms, IndexedDB CAS, vault lock/restore races, preferences, i18n catalogs, error mapping
npx playwright install chromium   # once, user-local
npm run e2e            # Playwright, headless Chromium, real WASM, no request interception
```

`e2e/vault.spec.ts` holds the M2 vault and security regressions. `e2e/preferences.spec.ts` covers language and appearance:
- both locales × all three theme preferences under a controlled OS scheme, live OS changes, and reload;
- unsaved input, TOTP codes and keys preserved across switches, with unchanged vault bytes;
- keyboard use, narrow viewports (320–390 px), corrupt or blocked preference storage, and CSP;
- real pointer clicks on all seven New-item menu options (empty and one-item list, 1280×860/600/460, mobile) with clipping and hit-test checks, and ≥44px touch targets for the preference controls under touch emulation.

Screenshots: `KEYMESH_SCREENSHOT_DIR=/abs/dir npm run e2e` writes desktop screenshots for each locale × theme and mobile screenshots to that directory. `KEYMESH_SCREENSHOT=/abs/path.png` sets the M2 flow screenshot. Without these variables, screenshots go to the git-ignored `test-results/`. Keep screenshots out of the repository.

## What runs where

- **Rust/WASM:** item validation, encryption and decryption, the generators (password, random secret, Ed25519), TOTP, and search over decrypted items. The decrypted vault and the key exist only in WASM memory.
- **Angular:** UI state only. Item views it receives carry non-secret fields plus masked slots. A secret's plaintext reaches JS only on an explicit Reveal or Copy.
- **IndexedDB** (`keymesh-demo` / `vault` / `primary`): only the versioned encrypted envelope and its public header fields.
- **localStorage** (`keymesh.settings.v1`): only `{"locale", "theme"}`, written only when the user picks one. Nothing about the vault.

## Source map

| Path | Purpose |
|---|---|
| `src/app/core/vault.service.ts` | Vault lifecycle: lock generation, exact-snapshot CAS, restore rules (unchanged safety logic from M2) |
| `src/app/core/preferences.ts` | Language/appearance preferences, storage fallbacks, `<html lang>` and `data-theme` |
| `public/preferences-boot.js` | Same rules applied before first paint (same-origin script, no inline JS) |
| `src/app/core/i18n/` | `en.ts` (source, defines `MessageKey`), `zh-tw.ts`, `I18n` service |
| `src/app/core/errors.ts` | Error → localized message key; unknown errors never shown raw |
| `src/app/shared/` | Icons, display preferences control, confirmation dialog, toasts |
| `src/styles/` | Design tokens and global styles; see `docs/DESIGN.md` |

See `docs/ARCHITECTURE.md` (Browser demo) for key handling, locking, the cross-tab policy and limitations.
