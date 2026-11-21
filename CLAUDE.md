# Keymesh — Claude development contract

Remote: `flarexio/keymesh` (**public**: everything committed, CI logs and summaries are world-readable). Supervisor: Jarvis; human: FlareX. Development and builds run in the `keymesh (macbook)` session; the Raspberry Pi session coordinates and deploys. Communicate technical work in English, milestone report in Traditional Chinese.

## Product and scope

Rust local-first encrypted vault core (`src/`, also the `keymesh` CLI) with a browser bridge (`crates/keymesh-wasm`) and an Angular web UI (`apps/web`) that runs the same core as WASM. See `docs/ARCHITECTURE.md` (system, data flow, product-copy mapping) and `docs/DESIGN.md` (UI). Two vault kinds:
* **Demo vaults** (envelope v1) use a public fixture key or a memory-only ephemeral key, so nothing they store is protected.
* **Password vaults** (envelope v2, M4) use a master password and an independent recovery code (`docs/adr/0002-envelope-v2.md`). They are real local-unlock mechanics but remain **experimental and synthetic-data only until Jarvis's independent acceptance**. They are allowed only in secure contexts (`docs/DELIVERY.md`).

Local decryption is not Keymesh login, and there is no account, escrow or support reset. Mandatory typed items: Login, Secret/API credential, Contact, CryptoWalletRecord, Ed25519Key, TOTP, SecureNote. Strong password/random-secret generators, Ed25519 key generation and TOTP are core features.

**M5 product rollout (authorized 2026-11-15, task `keymesh-product-rollout`):**
* **Phase A:** PWA/offline, TOTP QR import, TOTP countdown, local login icons.
* **Phase B:** Ed25519 Base58/sign/verify, DEK rotation, passphrases.
* **Phase C:** WebAuthn PRF quick unlock and auto-lock, optional favicon route.

These are implemented in that order with an independent review per phase. All stay experimental and synthetic-only; see `docs/ROADMAP.md` (M5 checklist). A browser-only custom PIN is not equivalent to a hardware PIN (ADR 0003).

**Own-app authentication, mnemonic login, image keycards, wallet/identity/KMS integration, NATS and blockchain integration are deferred.** Saving another wallet's recovery words as an encrypted field is data storage, not implementing our own mnemonic authentication. Ed25519 key generation is a vault feature, not our login mechanism. TOTP generates codes for external services, not Keymesh login.

## Safety

Use synthetic data only. Never access real password-manager accounts or vaults, credentials, ~/.hermes/.env, private keys or other repositories. No secrets in prompts, logs, stdout, URLs or git.

Core encryption accepts an explicit key-provider port (demo vaults) or v2 key slots (password vaults).
* Use an ephemeral synthetic test provider for v1 tests.
* Never store plaintext auto-unlock keys, KEKs, DEKs, passwords or recovery codes beside ciphertext, in Web Storage, logs, command arguments, URLs or test artifacts.
* Never convert or relabel a demo vault as a password vault, and never migrate data automatically.
* Keep password vaults disabled on plain-HTTP non-loopback origins and keep the "Preview version" banner.
* Don't lower KDF bounds for test speed.
* Mask recovery codes in screenshots, and never print them in logs. Clearly label demo APIs as not production ready. Crypto standards and maintained libraries only; no novel cryptography, modulo-biased generators or fallbacks to weak RNGs.

## Delivery

Work is directed by Jarvis through task contracts in `.supervision/` (local only, never committed): `supervisor.md` describes the current lane, and each task file (e.g. `generator-finish-task.md`) must be read entirely and acknowledged with `TASK_ACK <task-id> <sha256>` before implementation. The newest task contract supersedes earlier stop/idle instructions only within its stated scope; milestone files (`M1-task.md`…`M3-task.md`) and review/acceptance notes are history. Complete each task rather than stopping at planning/scaffolding, then report the ready-for-review marker the task names and stop; acceptance is Jarvis's independent decision. Stay within this repo; do not alter production services except through an authorized deploy. Use TDD and record real command outputs. A missing toolchain is a blocker to resolve safely, not permission to fabricate test results.

Commit verified changes on the task's feature branch and push (update its existing draft PR); merge, release or deploy only when FlareX asks, and never weaken CI. Report the actual CI state and retain local evidence. Jarvis independently reviews and verifies the milestone.

## Checks and previews

Native: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`; browser target: `cargo clippy -p keymesh -p keymesh-wasm --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings`; vectors: `node scripts/check-vectors.mjs`. Web (`apps/web`): `npm run build:wasm` (rebuild, never copy WASM from another worktree), `npm run typecheck`, `npm test`, `npm run build`, `npm run e2e` (real production build and WASM in Chromium on 127.0.0.1), `npm run tls-check` (loopback HTTPS with a throwaway CA; port 4311), `npm run test:serve` (static-root containment; port 4313). Keep build workers small on the Pi (`CARGO_BUILD_JOBS=2`). Cargo lives in `~/.cargo/bin`.

Deployment: CI builds the `keymesh-web` image (linux/arm64) and pushes it to Docker Hub on main; the Pi pulls it with `deploy/pull-deploy.sh <sha>`, which swaps only the web container (plain HTTP on 127.0.0.1:4320). TLS, certificates and routing for `keymesh.cloud` belong to the host's shared Traefik, which is outside this repo (`deploy/README.md`). Never commit ACME storage, private keys or host proxy configuration. Plain-HTTP previews on a LAN address are not a safe surface for real secrets, and the app keeps password vaults off there.
