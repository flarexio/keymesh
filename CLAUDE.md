# Keymesh — Claude development contract

Canonical workspace: `/home/jarvis/workspaces/keymesh`. Remote: `flarexio/keymesh` (private). Supervisor: Jarvis; human: FlareX. Communicate technical work in English, milestone report in Traditional Chinese.

## Product and scope

Rust local-first encrypted vault core (`src/`, also the `keymesh` CLI) with a browser bridge (`crates/keymesh-wasm`) and an Angular web UI (`apps/web`) that runs the same core as WASM. See `docs/ARCHITECTURE.md` (system, data flow, product-copy mapping) and `docs/DESIGN.md` (UI). The web app is a synthetic-data preview: its vault keys are a public fixture key or a memory-only ephemeral key, so nothing it stores is protected for real use; unlock/recovery are design-only (`docs/adr/`). Mandatory typed items: Login, Secret/API credential, Contact, CryptoWalletRecord, Ed25519Key, TOTP, SecureNote. Strong password/random-secret generators, Ed25519 key generation, TOTP and import FROM 1Password through the `op` CLI are core features.

**Own-app authentication, mnemonic login, image keycards, wallet/identity/KMS integration, NATS and blockchain integration are deferred.** Saving another wallet's recovery words as an encrypted field is data storage, not implementing our own mnemonic authentication. Ed25519 key generation is a vault feature, not our login mechanism. TOTP generates codes for external services, not Keymesh login.

## Safety

Use synthetic data only. Never access real op accounts/vaults/secrets, credentials, ~/.hermes/.env, private keys or other repositories. `op --help` / subcommand help / version are allowed; fetching actual items is NOT authorized for development. Test the importer with a fake executable fixture and injected process runner. No real imports without a separately authorized user action later. No secrets in prompts, logs, stdout, URLs or git. Never delete or mutate source 1Password records.

Core encryption accepts an explicit key-provider port. Use an ephemeral synthetic test provider, never plaintext auto-unlock keys stored beside ciphertext. Clearly label demo APIs as not production ready. Crypto standards and maintained libraries only; no novel cryptography, modulo-biased generators or fallbacks to weak RNGs.

## Delivery

Work is directed by Jarvis through task contracts in `.supervision/` (local only, never committed): `supervisor.md` describes the current lane, and each task file (e.g. `generator-finish-task.md`) must be read entirely and acknowledged with `TASK_ACK <task-id> <sha256>` before implementation. The newest task contract supersedes earlier stop/idle instructions only within its stated scope; milestone files (`M1-task.md`…`M3-task.md`) and review/acceptance notes are history. Complete each task rather than stopping at planning/scaffolding, then report the ready-for-review marker the task names and stop; acceptance is Jarvis's independent decision. Stay within this repo; do not alter other Claude sessions or production services. Use TDD and record real command outputs. A missing toolchain is a blocker to resolve safely, not permission to fabricate test results.

Commit verified changes on the task's feature branch and push (update its existing draft PR); no merge/release/deploy, no weakening CI, no public visibility change. Private CI may be unavailable due to account/billing; report actual state and retain local evidence. Jarvis independently reviews and verifies the milestone.

## Checks and previews

Native: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features`; browser target: `cargo clippy -p keymesh -p keymesh-wasm --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings`. Web (`apps/web`): `npm run build:wasm` (rebuild, never copy WASM from another worktree), `npm run typecheck`, `npm test`, `npm run build`, `npm run e2e` (real production build and WASM in Chromium on 127.0.0.1). Keep build workers small on the Pi (`CARGO_BUILD_JOBS=2`). Cargo lives in `~/.cargo/bin`.

Static previews run by Jarvis serve `apps/web/dist` from tmux sessions `keymesh-preview` (192.168.50.100:4310) and `keymesh-vpn-preview` (10.8.0.22:4310). Rebuilding `dist` refreshes them; never stop them, start a competing server on those addresses, or broaden a binding. They are plain HTTP: not a safe surface for real secrets.
