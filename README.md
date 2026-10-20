# keymesh

Local-first encrypted vault core in Rust, with an Angular browser demo running the same core compiled to WebAssembly.

> **Status: M2 synthetic demo — NOT production ready.** The only key providers are synthetic/demo ones, development-only. Real unlock, recovery and Keymesh's own authentication don't exist yet. Use synthetic data only.

## Capability matrix (M1 core + M2 browser slice)

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
| WASM bridge (`crates/keymesh-wasm`, wasm-bindgen 0.2.129) | ✅ runs in browser | Validation, encryption, generators, Ed25519 and TOTP execute in headless Chromium (Playwright E2E) |
| Angular 22 app (`apps/web`): list/search/filter/create/edit/delete all 7 item types | ✅ | Per-type forms; secrets masked, explicit reveal/copy; responsive; accessible labels; "synthetic demo" banner |
| Browser generators → encrypted items | ✅ | Password, random secret, Ed25519 generated inside WASM and stored directly; passphrase still pending |
| Browser TOTP: live code + remaining time, otpauth URI / Base32 entry | ✅ | Clock injectable (E2E uses Playwright's clock); QR/camera scanning ❌ not implemented |
| IndexedDB persistence of the encrypted envelope only | ✅ | No plaintext, key or search index stored; E2E checks that planted markers are absent |
| Browser lock / demo unlock | ✅ | Lock drops the decrypted vault in WASM, bumps an epoch so work started earlier is discarded; unlock is a demo-key transition, not identity |
| Encrypted backup download / verified restore | ✅ | Restore must decrypt with the current demo key before anything is written; size limit 64 MiB |
| Cross-tab writes | ✅ rejected | Compare-and-swap on the stored revision plus a BroadcastChannel stale notice; stale tabs must reload |
| Offline startup (service worker / PWA) | ⏳ deferred | No service worker; the app needs its origin to load |
| 1Password import in the browser | ❌ by design | Native CLI only; no endpoint runs `op`; the browser shows CLI instructions |
| Production unlock / recovery | ❌ not started | Lost ephemeral demo key ⇒ demo ciphertext is unrecoverable |
| Keymesh login (mnemonic, image keycards), wallet/identity/KMS, NATS, blockchain | ❌ deferred | Out of scope |
| Sync between devices; CLI ↔ browser vault transfer | ❌ deferred | |

## Known limitations

- **Demo key provider only:** the CLI key comes from `KEYMESH_DEMO_KEY`. Real unlock and recovery aren't designed yet.
- **Single writer:** `save` refuses when the file changed since it was loaded, but there is no file lock. Two writers racing during the save can still conflict.
- **Whole-file rollback** to an older valid vault file can't be detected without external state.
- **Size limit:** vault files are limited to 64 MiB for both reading and writing. A save that would exceed it is refused and leaves the old file intact.
- **Browser key handling (M2):** the demo key provider lives in WASM memory only.
  - With the *ephemeral* key, a reload loses the key, and the stored demo ciphertext becomes permanently inaccessible.
  - The *synthetic fixture* key is public: anyone can decrypt data stored under it.
- **Browser memory:** JavaScript and WASM cannot guarantee zeroization. Revealed or copied values, form inputs and the clipboard are outside Keymesh's control. Lock removes decrypted vault state in WASM, but the browser may still retain copies.

## Build and test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo clippy -p keymesh-wasm --target wasm32-unknown-unknown -- -D warnings
```

Browser demo: see [`apps/web/README.md`](apps/web/README.md). In short:

```sh
cd apps/web && npm ci && npm run build:wasm && npm run build && npm start   # http://127.0.0.1:4310
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
cargo run -q -- import-op preview --account "<account>" --ref "op://<vault>/<item>/<field>"   # --account required
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
crates/keymesh-wasm/  wasm-bindgen browser bridge (logic in bridge.rs, natively unit-tested)
apps/web/        Angular 22 demo app, Vitest unit tests, Playwright E2E (e2e/)
scripts/         build-wasm.sh (cargo wasm32 build + wasm-bindgen into apps/web)
docs/            ARCHITECTURE.md (formats, key hierarchy, browser demo, decisions, limitations)
```
