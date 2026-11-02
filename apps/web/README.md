# Keymesh web app

An Angular 22 app running the real Keymesh Rust core, compiled to WebAssembly (`crates/keymesh-wasm`). Runtime language 繁體中文 (zh-TW) / English and System / Light / Dark appearance (M3).

> **Experimental, not production, not independently reviewed. Synthetic data only.**
> - **Password vaults** (master password + recovery code, M4) only work in a secure context (HTTPS or 127.0.0.1); see `docs/DELIVERY.md`.
> - **Demo vaults** use a development-only key (public fixture or memory-only ephemeral).
> - There is no account, sign-in, sync or reset service.
> - Do not enter real secrets.

## Build and run (loopback by default)

You need a Rust toolchain with the `wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.129 (must match the crate pin) and Node 24+.

```sh
npm ci
npm run build:wasm     # cargo build --target wasm32 + wasm-bindgen → src/app/core/wasm-pkg, public/wasm
npm run build          # production build → dist/web/browser (strict template type checking)
npm start              # serves dist/web/browser on http://127.0.0.1:4310 (loopback only)
```

### Optional LAN preview (explicit HOST, plain HTTP)

```sh
HOST=192.168.50.100 node scripts/serve.mjs 4310   # one literal IP; default stays 127.0.0.1
```

`HOST` must be a single literal IP address. Hostnames and wildcard binds (`0.0.0.0`, `::`) are refused. The security headers (CSP, `nosniff`, `no-referrer`, COOP, `frame-ancestors 'none'`, `no-store`) are unchanged. The server only serves static build files: it has no API, never runs `op` and holds no secrets.

`http://<LAN IP>` is **not a secure context**. Checked in Chromium against `http://192.168.50.100:4310`:

| Feature | Over plain-HTTP LAN |
|---|---|
| `isSecureContext` | `false`; browsers show "Not secure" |
| WebAssembly core, `crypto.getRandomValues` (generators, keys, encryption) | works |
| IndexedDB, localStorage (preferences), BroadcastChannel | work, but storage is per origin: a vault saved at `http://192.168.50.100:4310` is separate from one at `http://127.0.0.1:4310` |
| Clipboard API (Copy) | missing; Copy shows "The browser did not allow copying to the clipboard". Reveal still works |
| `Cross-Origin-Opener-Policy` | ignored by the browser on untrustworthy origins (a console error says so) |
| `crypto.subtle` | missing (not used by Keymesh) |
| Password vaults | **off**: create, unlock, reset and restore are refused, and their database is never opened; the start screen says so and offers the demo |

Traffic is unencrypted. Anyone on the network can read the served app and could modify it in transit, for example by injecting script that reads an unlocked vault. Vault data never leaves the browser, but use synthetic data only and treat a LAN preview as a UI check, not a security boundary. A VPN does not change this: `http://10.8.0.22` is still not a secure context.

### HTTPS (TLS mode)

```sh
TLS_CERT=/outside/repo/fullchain.pem TLS_KEY=/outside/repo/key.pem node scripts/serve.mjs 4443   # loopback by default
npm run tls-check   # throwaway CA on 127.0.0.1:4311: chain, hostname, TLS floor, headers, secure-context flow
```

`tls-check` proves TLS mechanics on loopback only. A certificate that client devices actually trust, and permission to run an HTTPS listener on a private address, are open decisions (`docs/DELIVERY.md` §4).

## Checks

```sh
npm run typecheck      # app, unit-test and e2e TypeScript configs
npm test               # Vitest: forms, IndexedDB CAS, vault lock/restore races, preferences, password settings, i18n catalogs, error mapping
npx playwright install chromium   # once, user-local
npm run e2e            # Playwright, headless Chromium, real WASM, no request interception
```

`e2e/vault.spec.ts` holds the M2 vault and security regressions. `e2e/password-options.spec.ts` covers password settings in both languages: presets → Custom, slider and number input, custom symbols, look-alike exclusion, friendly validation (weak, no type, bad symbols, length), real WASM output checked for exact length, allowed set and one of each type (as booleans, so failures never print a value), apply/cancel in the Login and Secret forms, an encrypted round trip, and phone widths. `e2e/preferences.spec.ts` covers language and appearance:
- both locales × all three theme preferences under a controlled OS scheme, live OS changes, and reload;
- unsaved input, TOTP codes and keys preserved across switches, with unchanged vault bytes;
- keyboard use, narrow viewports (320–390 px), corrupt or blocked preference storage, and CSP;
- real pointer clicks on all seven New-item menu options (empty and one-item list, 1280×860/600/460, mobile) with clipping and hit-test checks, and ≥44px touch targets for the preference controls under touch emulation.
- the Chinese option labelled 中文 (text, title and accessible name) in both locales, and Copy failing with a localized message when the Clipboard API is absent (plain-HTTP LAN origin).

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
| `src/app/core/password-options.ts` | Password settings model, Default/Strong presets, shared session settings |
| `src/app/shared/` | Icons, display preferences, password settings panel, masked generated value, confirmation dialog, toasts |
| `src/styles/` | Design tokens and global styles; see `docs/DESIGN.md` |

See `docs/ARCHITECTURE.md` (Browser demo) for key handling, locking, the cross-tab policy and limitations.
