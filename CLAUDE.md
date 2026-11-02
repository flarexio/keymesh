# Keymesh — Claude development contract

Canonical workspace: `/home/jarvis/workspaces/keymesh`. Remote: `flarexio/keymesh` (private). Supervisor: Jarvis; human: FlareX. Communicate technical work in English, milestone report in Traditional Chinese.

## Product and scope

Rust local-first encrypted vault core (`src/`, also the `keymesh` CLI) with a browser bridge (`crates/keymesh-wasm`) and an Angular web UI (`apps/web`) that runs the same core as WASM. See `docs/ARCHITECTURE.md` (system, data flow, product-copy mapping) and `docs/DESIGN.md` (UI). Two vault kinds:
* **Demo vaults** (envelope v1) use a public fixture key or a memory-only ephemeral key, so nothing they store is protected.
* **Password vaults** (envelope v2, M4) use a master password and an independent recovery code (`docs/adr/0002-envelope-v2.md`). They are real local-unlock mechanics but remain **experimental and synthetic-data only until Jarvis's independent acceptance**. They are allowed only in secure contexts (`docs/DELIVERY.md`).

Local decryption is not Keymesh login, and there is no account, escrow or support reset. Mandatory typed items: Login, Secret/API credential, Contact, CryptoWalletRecord, Ed25519Key, TOTP, SecureNote. Strong password/random-secret generators, Ed25519 key generation, TOTP and import FROM 1Password through the `op` CLI are core features.

**Own-app authentication, mnemonic login, image keycards, wallet/identity/KMS integration, NATS and blockchain integration are deferred.** Saving another wallet's recovery words as an encrypted field is data storage, not implementing our own mnemonic authentication. Ed25519 key generation is a vault feature, not our login mechanism. TOTP generates codes for external services, not Keymesh login.

## Safety

Use synthetic data only. Never access real op accounts/vaults/secrets, credentials, ~/.hermes/.env, private keys or other repositories. `op --help` / subcommand help / version are allowed; fetching actual items is NOT authorized for development. Test the importer with a fake executable fixture and injected process runner. No real imports without a separately authorized user action later. No secrets in prompts, logs, stdout, URLs or git. Never delete or mutate source 1Password records.

Core encryption accepts an explicit key-provider port (demo vaults) or v2 key slots (password vaults).
* Use an ephemeral synthetic test provider for v1 tests.
* Never store plaintext auto-unlock keys, KEKs, DEKs, passwords or recovery codes beside ciphertext, in Web Storage, logs, command arguments, URLs or test artifacts.
* Never convert or relabel a demo vault as a password vault, and never migrate data automatically.
* Keep password vaults disabled on plain-HTTP non-loopback origins and keep the "Preview version" banner.
* Don't lower KDF bounds for test speed.
* Mask recovery codes in screenshots, and never print them in logs. Clearly label demo APIs as not production ready. Crypto standards and maintained libraries only; no novel cryptography, modulo-biased generators or fallbacks to weak RNGs.

## Delivery

Work is directed by Jarvis through task contracts in `.supervision/` (local only, never committed): `supervisor.md` describes the current lane, and each task file (e.g. `generator-finish-task.md`) must be read entirely and acknowledged with `TASK_ACK <task-id> <sha256>` before implementation. The newest task contract supersedes earlier stop/idle instructions only within its stated scope; milestone files (`M1-task.md`…`M3-task.md`) and review/acceptance notes are history. Complete each task rather than stopping at planning/scaffolding, then report the ready-for-review marker the task names and stop; acceptance is Jarvis's independent decision. Stay within this repo; do not alter other Claude sessions or production services. Use TDD and record real command outputs. A missing toolchain is a blocker to resolve safely, not permission to fabricate test results.

Commit verified changes on the task's feature branch and push (update its existing draft PR); no merge/release/deploy, no weakening CI, no public visibility change. Private CI may be unavailable due to account/billing; report actual state and retain local evidence. Jarvis independently reviews and verifies the milestone.

## Checks and previews

Native: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`; browser target: `cargo clippy -p keymesh -p keymesh-wasm --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings`; vectors: `node scripts/check-vectors.mjs`. Web (`apps/web`): `npm run build:wasm` (rebuild, never copy WASM from another worktree), `npm run typecheck`, `npm test`, `npm run build`, `npm run e2e` (real production build and WASM in Chromium on 127.0.0.1), `npm run tls-check` (loopback HTTPS with a throwaway CA; port 4311). Keep build workers small on the Pi (`CARGO_BUILD_JOBS=2`). Cargo lives in `~/.cargo/bin`.

Static previews run by Jarvis serve `apps/web/dist` from tmux sessions `keymesh-preview` (192.168.50.100:4310) and `keymesh-vpn-preview` (10.8.0.22:4310). Rebuilding `dist` refreshes them; never stop them, start a competing server on those addresses, or broaden a binding. They are plain HTTP: not a safe surface for real secrets, and the app keeps password vaults off there. Any HTTPS listener on a private address needs the concrete operation presented and approved first (`docs/DELIVERY.md`).
