# Keymesh web demo (M2)

An Angular 22 app running the real Keymesh Rust core, compiled to WebAssembly (`crates/keymesh-wasm`).

> **Synthetic demo, not production.**
> - The key provider is development-only and memory-only.
> - There is no real unlock, recovery or account system.
> - Do not enter real secrets.

## Build and run (loopback only)

You need a Rust toolchain with the `wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.129 (must match the crate pin) and Node 24+.

```sh
npm ci
npm run build:wasm     # cargo build --target wasm32 + wasm-bindgen → src/app/core/wasm-pkg, public/wasm
npm run build          # production build → dist/web/browser
npm start              # serves dist/web/browser on http://127.0.0.1:4310 (loopback only)
```

## Checks

```sh
npm run typecheck      # app, unit-test and e2e TypeScript configs
npm test               # Vitest unit tests (form mapping, IndexedDB compare-and-swap via fake-indexeddb)
npx playwright install chromium   # once, user-local
npm run e2e            # Playwright, headless Chromium, real WASM, no request interception
```

`KEYMESH_SCREENSHOT=/abs/path.png npm run e2e` also saves desktop and phone-width screenshots of the running UI.

## What runs where

- **Rust/WASM:** item validation, encryption and decryption, the generators (password, random secret, Ed25519), TOTP, and search over decrypted items. The decrypted vault and the key exist only in WASM memory.
- **Angular:** UI state only. Item views it receives carry non-secret fields plus masked slots. A secret's plaintext reaches JS only on an explicit Reveal or Copy.
- **IndexedDB** (`keymesh-demo` / `vault` / `primary`): only the versioned encrypted envelope and its public header fields.

See `docs/ARCHITECTURE.md` (Browser demo) for key handling, locking, the cross-tab policy and limitations.
