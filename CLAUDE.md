# Keymesh — Claude development contract

Canonical workspace: `/home/jarvis/workspaces/keymesh`. Remote: `flarexio/keymesh` (private). Supervisor: Jarvis; human: FlareX. Communicate technical work in English, milestone report in Traditional Chinese.

## Product and scope

Rust local-first encrypted vault core, Angular UI later. Mandatory typed items: Login, Secret/API credential, Contact, CryptoWalletRecord, Ed25519Key, TOTP, SecureNote. Strong password/random-secret generators, Ed25519 key generation, TOTP and import FROM 1Password through the `op` CLI are core features.

**Own-app authentication, mnemonic login, image keycards, wallet/identity/KMS integration, NATS and blockchain integration are deferred.** Saving another wallet's recovery words as an encrypted field is data storage, not implementing our own mnemonic authentication. Ed25519 key generation is a vault feature, not our login mechanism. TOTP generates codes for external services, not Keymesh login.

## Safety

Use synthetic data only. Never access real op accounts/vaults/secrets, credentials, ~/.hermes/.env, private keys or other repositories. `op --help` / subcommand help / version are allowed; fetching actual items is NOT authorized for development. Test the importer with a fake executable fixture and injected process runner. No real imports without a separately authorized user action later. No secrets in prompts, logs, stdout, URLs or git. Never delete or mutate source 1Password records.

Core encryption accepts an explicit key-provider port. Use an ephemeral synthetic test provider, never plaintext auto-unlock keys stored beside ciphertext. Clearly label demo APIs as not production ready. Crypto standards and maintained libraries only; no novel cryptography, modulo-biased generators or fallbacks to weak RNGs.

## Delivery

Read `.supervision/M1-task.md` entirely and acknowledge its SHA-256 before implementation. Complete M1 rather than stopping at planning/scaffolding. Stay within this repo; do not alter other Claude sessions or production services. Use TDD and record real command outputs. A missing toolchain is a blocker to resolve safely, not permission to fabricate test results.

Commit verified changes on a feature branch and push; no merge/release/deploy, no weakening CI, no public visibility change. Private CI may be unavailable due to account/billing; report actual state and retain local evidence. Jarvis independently reviews and verifies the milestone.
