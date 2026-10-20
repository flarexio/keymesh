# keymesh

Local-first encrypted vault core in Rust. An Angular UI is planned for later.

> **Status: M1 foundation — NOT production ready.** The only key providers are synthetic/demo ones. Real unlock, recovery, Keymesh's own authentication and the UI don't exist yet. Use synthetic data only.

## Capability matrix (M1)

| Area | State | Notes |
|---|---|---|
| Typed items: Login, Secret/API credential, Contact, CryptoWalletRecord, Ed25519Key, TOTP, SecureNote | ✅ | Validation rules; multi-value contact fields; custom fields; Login → TOTP reference and recovery codes |
| AEAD encryption (XChaCha20-Poly1305), versioned envelope, AAD binding | ✅ | KEK → random DEK; per-item records plus an encrypted manifest; see `docs/ARCHITECTURE.md` |
| Key-provider port | ✅ | Ephemeral (tests) and **synthetic demo** (CLI env var) only |
| Atomic local persistence, load/edit/save, encrypted backup/restore | ✅ | Fails closed on a wrong key, corruption, truncation or an unknown format; lost-update guard |
| Password generator (24 default / 32 strong, custom allowlist, unbiased sampling) | ✅ | |
| Random 256-bit secrets (hex / base64url / base32) | ✅ | Local random values, not provider-issued credentials |
| Passphrase generator | ⏳ pending | No reviewed, versioned wordlist bundled |
| Ed25519 generation, storage, RFC 8032 vectors, OpenSSH public-key line | ✅ | No signing API; no private-key export formats |
| RFC 6238 TOTP (SHA1/256/512, 6/8 digits), Base32 and `otpauth://totp` import | ✅ | HOTP and custom modes rejected |
| TOTP QR decode | ⏳ deferred | Future UI adapter |
| Import from 1Password via `op` CLI (explicit item or `op://` ref) | ✅ (fixtures only) | Tested only with a fake `op` and synthetic fixtures; not yet run against a real account |
| WASM build of core (`--no-default-features`) | ✅ compiles | Not yet exercised in a browser |
| Production unlock / recovery | ❌ not started | |
| Keymesh login (mnemonic, image keycards), wallet/identity/KMS, NATS, blockchain | ❌ deferred | Out of M1 scope |
| Angular UI, sync | ❌ deferred | |

## Build and test

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Synthetic demo (CLI harness)

The CLI reads the vault key from `KEYMESH_DEMO_KEY`: 64 hex characters, used only by the synthetic demo provider. The key is never written to disk. Don't put real secrets in a demo vault.

```sh
export KEYMESH_DEMO_KEY=$(cargo run -q -- gen secret --bytes 32 --encoding hex)
export KEYMESH_VAULT=./demo.keymesh
cargo run -q -- init
cargo run -q -- add login --title "Example" --username demo --url https://example.test --generate
printf 'otpauth://totp/Example:demo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example' \
  | cargo run -q -- add totp --title "Example TOTP"
cargo run -q -- add ed25519 --title "Demo key"
cargo run -q -- list
cargo run -q -- show <id>              # secrets redacted; add --reveal to print them
cargo run -q -- totp <id> --at 59
cargo run -q -- backup --to ./demo.bak
```

Secret values (passwords, note bodies, recovery phrases, TOTP URIs) come in on stdin, never as arguments.

### 1Password import

```sh
cargo run -q -- import-op preview --op-vault "<vault>" --item "<item>"   # no writes
cargo run -q -- import-op apply   --op-vault "<vault>" --item "<item>"
cargo run -q -- import-op preview --ref "op://<vault>/<item>/<field>"
```

The importer:

- uses your already-authenticated `op` session and never asks for 1Password credentials
- doesn't enumerate accounts or vaults
- never modifies the source records
- prints a report that contains only source ids, statuses and counts

**During development, run it only against the fake `op` in `tests/fixtures/fake-op`. Importing from a real account needs a separate, explicit authorization.**

## Layout

```
src/             crypto, model, generate, ed25519, totp, vault, storage, import/{op,process}, bin/keymesh
tests/           op_import.rs (fake runner + fake executable), cli.rs (binary smoke tests), fixtures/
docs/            ARCHITECTURE.md (formats, key hierarchy, decisions, limitations)
```
