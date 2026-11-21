# keymesh

Local-first encrypted vault core in Rust, with an Angular browser demo running the same core compiled to WebAssembly.

> **Status: M4 local unlock + M5 phases A, B and C, experimental. NOT production ready; synthetic data only.**
> * **Password vaults** (master password + independent recovery code, envelope v2, `docs/adr/0002-envelope-v2.md`) work natively and in the browser, but stay **synthetic-data only until independent acceptance**. Demo vaults keep their public fixture or ephemeral keys.
> * **M5 phase A** (installable offline app, TOTP from QR, TOTP countdown, local login icons): independently accepted for experimental, synthetic-only use, and privately deployed to `keymesh.cloud` (commit `7079932`).
> * **M5 phase B** (Ed25519 Base58/sign/verify, data-key rotation, EFF passphrases, emergency kit): independently accepted (commit `4e65efb`) and privately deployed to `keymesh.cloud` on 2026-11-16.
> * **M5 phase C** (WebAuthn PRF quick unlock and deadline-based auto-lock): independently accepted (commit `88dee8b`) and privately deployed to `keymesh.cloud` on 2026-11-16.
>   * **Testing scope:** passkeys were tested only with Chromium's **virtual authenticator**.
>   * **Website icons:** the optional route is in the image but **OFF**; outbound fetching is not approved.
> * **Not verified:** real hardware (TouchID, FaceID, Windows Hello, phones, security keys), Safari and Firefox, and client-device trust.
> * **Not offered:** a custom short Keymesh PIN is deliberately blocked. See `docs/ROADMAP.md`.
> * **Not built:** Keymesh's own authentication, accounts and sync.
> * **Private HTTPS:** a private HTTPS endpoint (`https://keymesh.cloud` on the VPN, internal CA) runs, but no real client device has yet been verified to trust it (gate C, `docs/DELIVERY.md`).

## Capability matrix (M1 core, M2 browser slice, M3 UI, M4 local unlock, M5 phases A and B)

| Area | State | Notes |
|---|---|---|
| Typed items: Login, Secret/API credential, Contact, CryptoWalletRecord, Ed25519Key, TOTP, SecureNote | ✅ | Validation rules; multi-value contact fields; custom fields; Login → TOTP reference and recovery codes |
| AEAD encryption (XChaCha20-Poly1305), versioned envelope, AAD binding | ✅ | KEK → random DEK; per-item records plus an encrypted manifest; see `docs/ARCHITECTURE.md` |
| Key-provider port (v1 demo vaults) | ✅ | Ephemeral (tests) and **synthetic demo** (CLI env var) only |
| Password vault (envelope v2): master password + recovery code key slots | ✅ experimental | Argon2id 64 MiB/t=3/p=1 → HKDF-SHA256; 256-bit recovery code (Base32, version + check digits) confirmed before first save; bounds checked before derivation; shared vectors checked natively, in WASM and independently with Node/OpenSSL |
| Password change, reset with recovery code, new recovery code | ✅ experimental | Need proof of authority verified by the core; **rewraps, not rotation**: earlier backups keep earlier credentials |
| Data-key rotation (M5 B) | ✅ experimental, accepted (`4e65efb`), deployed | New random data key, every item re-encrypted, new password **and** new recovery code (typed back first); same envelope format. Browser: exact-byte CAS with read-back reconciliation; native: check-then-rename, single writer. Older backups still open with the old credentials; copies can't be revoked. `keymesh rotate-key` in the CLI |
| Native CLI unlock | ✅ experimental | `init`, `passwd [--recovery]`, `new-recovery-code`, `rotate-key`, `recover`; masked terminal input or `--password-stdin`; `init --demo` keeps the v1 demo |
| Browser password vault | ✅ experimental | Secure contexts only (HTTPS or loopback); Argon2id in a worker; one credential operation at a time; lock cancels it; refused on plain-HTTP LAN/VPN origins, where the demo stays usable |
| HTTPS serving | ✅ experimental | `serve.mjs` TLS mode (`npm run tls-check`, throwaway CA). A private deployment serves `keymesh.cloud` with an internal-CA certificate: `deploy/` ships the web container, and the host's shared Traefik (not in this repo) terminates TLS. Chain and headers are verified on the Pi; **a real client device trusting it (gate C) is unverified** (`docs/DELIVERY.md`) |
| Atomic local persistence, load/edit/save, encrypted backup/restore | ✅ | Fails closed on a wrong key, corruption, truncation or an unknown format; lost-update guard |
| Password generator (24 default / 32 strong presets, custom length 8–128, character types, custom ASCII-punctuation symbol set, look-alike exclusion, one-of-each-type; unbiased sampling) | ✅ | Same 64-bit floor for custom settings, checked against the generator's exact min-entropy |
| Random 256-bit secrets (hex / base64url / base32) | ✅ | Local random values, not provider-issued credentials |
| Passphrase generator (M5 B) | ✅ experimental, accepted (`4e65efb`), deployed | EFF Long Wordlist (7776 words, CC BY 3.0 US), vendored and SHA-256 pinned; each word uniform from the OS CSPRNG (≈ 12.9 bits/word; 6 words by default). Also offered as a master-password suggestion, with an "I stored it" confirmation, and a printable emergency kit that never prints the password |
| Ed25519 generation, storage, RFC 8032 vectors, OpenSSH public-key line | ✅ | No private-key export formats |
| Ed25519 raw Base58 public key, signing, strict verification (M5 B) | ✅ experimental, accepted (`4e65efb`), deployed | Base58 = the raw 32 bytes, Bitcoin alphabet, no prefix or checksum. Signs exactly the shown UTF-8 or hex bytes (≤ 64 KiB) on an unlocked vault; `verify_strict` for any key. No chain RPC, transactions or login |
| RFC 6238 TOTP (SHA1/256/512, 6/8 digits), Base32 and `otpauth://totp` import | ✅ | HOTP and custom modes rejected |
| TOTP QR decode | ✅ experimental (browser) | Image upload/paste anywhere the app runs; live camera only in secure contexts. Decoded locally (zxing-wasm in a worker, self-hosted). Only `otpauth://totp/` is used, and the core validates it on save. Chromium fake-camera tested; **no real camera hardware tested** |
| Import from 1Password via `op` CLI (explicit item or `op://` ref) | ✅ (fixtures only) | Tested only with a fake `op` and synthetic fixtures; not yet run against a real account |
| WASM bridge (`crates/keymesh-wasm`, wasm-bindgen 0.2.129) | ✅ runs in browser | Validation, encryption, generators, Ed25519 and TOTP execute in headless Chromium (Playwright E2E) |
| Angular 22 app (`apps/web`): list/search/filter/create/edit/delete all 7 item types | ✅ | Per-type forms with inline validation; secrets masked, explicit reveal/copy; in-app confirmation for destructive actions; persistent "synthetic demo" warning |
| UI design system (M3) | ✅ | Semantic tokens, local icon set, system fonts; desktop sidebar + list/detail, mobile single column with bottom navigation; keyboard and screen-reader labels, visible focus, reduced motion; see `docs/DESIGN.md` |
| Runtime language: 繁體中文 (zh-TW) / English | ✅ | Typed catalogs (missing key = build error); default from browser language; explicit choice persisted; switching keeps form input and never writes the vault; localized, secret-free error messages |
| Appearance: System / Light / Dark | ✅ | System follows the OS live; explicit choice overrides it; applied before first paint without inline script; only `{locale, theme}` stored, under `keymesh.settings.v1` |
| Browser generators → encrypted items | ✅ | Password, passphrase, random secret and Ed25519 generated inside WASM and stored directly |
| Browser TOTP: live code + circular countdown, otpauth URI / Base32 / QR entry | ✅ | Clock injectable (E2E uses Playwright's clock). The last 5 s are flagged by colour **and** text; reduced motion respected |
| Login icons | ✅ local only | 81 bundled brand marks (Simple Icons, no per-icon licence; trademarks of their owners) by reviewed domain; server icon for private hosts; category or letter otherwise. No network. **Not a security or origin indicator** |
| IndexedDB persistence of the encrypted envelope only | ✅ | No plaintext, key or search index stored; E2E checks that planted markers are absent |
| Browser lock / demo unlock | ✅ | Lock drops the decrypted vault in WASM, bumps an epoch so work started earlier is discarded; unlock is a demo-key transition, not identity |
| Encrypted backup download / verified restore | ✅ | Restore must decrypt with the current demo key before anything is written; a lock at any point wins; 64 MiB limit enforced on open and seal |
| Cross-tab writes | ✅ rejected | Exact-snapshot compare-and-swap on every write (mutation, restore, discard) plus a BroadcastChannel stale notice; stale tabs cannot edit or restore until they reload |
| Installable app / offline startup (PWA) | ✅ experimental | Angular service worker in secure contexts only (HTTPS or loopback; not the plain-HTTP previews). After one online visit it reopens offline and unlocks the vault stored in that browser. Updates are offered, never forced. A failed update keeps the open tab working but prevents offline reopening until a retry succeeds. Damaged cached app files can be repaired online (vault data untouched). Not native autofill or an app store; vaults stay per browser. **Install on real phones/Safari untested** (`docs/DELIVERY.md` §6) |
| 1Password import in the browser | ❌ by design | Native CLI only; no endpoint runs `op`; the browser shows CLI instructions |
| Production use of password vaults | ⏳ pending review | Experimental until independent acceptance; lost password **and** recovery code ⇒ data unrecoverable (no escrow, no reset); lost ephemeral demo key ⇒ demo ciphertext unrecoverable |
| Quick unlock with a WebAuthn PRF passkey (M5 C) | ✅ experimental, accepted (`88dee8b`), deployed | `webauthn-prf` slot (ADR 0003 §4.1.1). The master password is needed to enrol or remove a passkey, and stays a fallback with the recovery code. Unlock checks rpIdHash, UP and UV in the core. Orphan and uncertain outcomes are reconciled. Tested with Chromium's **virtual authenticator only**; no TouchID, FaceID or Windows Hello proof |
| Auto-lock (M5 C) | ✅ experimental, accepted (`88dee8b`), deployed | Idle (5 min default) and hidden (30 s desktop, immediate on touch) deadlines, checked before access. `pagehide` locks. Monotonic plus wall clock; a clock moved backwards locks |
| Optional website icons (M5 C) | ⏸ implemented, deployed **OFF** (dormant) | Same-process `/api/favicon`, off unless `KEYMESH_FAVICON=1` and the user opts in.<br>• **Hosts:** public only (address allowlist, pinned connection, normal TLS checks).<br>• **Images:** PNG decoded and re-encoded.<br>• **Storage:** no result cache; `no-store`.<br>• **Not hard limits:** DNS lookups can't be cancelled, and the decode is synchronous; late results are discarded.<br>Live outbound use is not approved yet |
| Custom short Keymesh PIN | ⛔ blocked | A browser-only PIN does not resist a copied profile (ADR 0003 §3, D2). Use a passkey whose device unlock is a PIN instead |
| Device slots, mnemonic or keycard encodings | ❌ deferred | ADR 0001 |
| Keymesh login (mnemonic, image keycards), wallet/identity/KMS, NATS, blockchain | ❌ deferred | Out of scope |
| Sync between devices; CLI ↔ browser vault transfer | ❌ deferred | |

## Known limitations

- **Experimental password vaults:** implemented to a reviewed-format proposal (ADR 0002); partially reviewed, not independently accepted. Synthetic data only.
- **Rewrap vs rotation:** changing the password or recovery code doesn't revoke older backups or data already read. Rotation (M5 B; accepted and deployed) replaces the data key for the stored vault, but older backups still open with their old credentials and anything already copied can't be taken back.
- **Weak passwords stay guessable offline:** anyone with the file can try passwords at about one Argon2id (64 MiB, t=3) per guess. Use a long passphrase; the recovery code itself cannot be guessed.
- **Single writer:** `save` refuses unless the file is byte for byte what was loaded, but there is no file lock. Two writers racing during the save can still conflict.
- **Durability:** if the system can't sync the directory after the new file is in place, the CLI exits with status 3 and says the change is in effect but durability is unconfirmed. A failure before that point leaves the old file untouched.
- **Whole-file rollback** to an older valid vault file can't be detected without external state.
- **Size limit:** vault files are limited to 64 MiB for both reading and writing. A save that would exceed it is refused and leaves the old file intact.
- **Browser key handling (M2):** the demo key provider lives in WASM memory only.
  - With the *ephemeral* key, a reload loses the key, and the stored demo ciphertext becomes permanently inaccessible.
  - The *synthetic fixture* key is public: anyone can decrypt data stored under it.
- **UI (M3, M5):** E2E runs in Chromium only; Firefox, Safari, real phones, real installs and real cameras are untested. Theme tokens use CSS `light-dark()`, which needs Chrome/Edge 123+, Firefox 120+ or Safari 17.5+. Chinese text uses whatever Traditional Chinese system font is installed (no bundled fonts). The zh-TW catalog was written and checked in-project, without a separate professional or native-speaker review.
- **Browser memory:** JavaScript and WASM cannot guarantee zeroization. The typed master password is a JavaScript string; revealed or copied values, form inputs and the clipboard are outside Keymesh's control. Lock removes decrypted vault state in WASM and terminates a running key derivation, but the browser may still retain copies.
- **KDF measurements** are from a Raspberry Pi 4 (native and Chromium WASM). No phone, laptop, Firefox or Safari was measured.

## Build and test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo clippy -p keymesh -p keymesh-wasm --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings
node scripts/check-vectors.mjs          # independent Node/OpenSSL check of the v2 vectors (Node >= 24.7)
cargo run --release --example kdf_bench # synthetic Argon2id timings
```

Browser demo: see [`apps/web/README.md`](apps/web/README.md). In short:

```sh
cd apps/web && npm ci && npm run build:wasm && npm run build && npm start   # http://127.0.0.1:4310
```

## Password vault (CLI, experimental, synthetic data only)

```sh
export KEYMESH_VAULT=./vault.keymesh
cargo run -q -- init                     # asks for a master password, shows the recovery code once, asks for it back
cargo run -q -- add ed25519 --title "Synthetic key"   # every command asks for the password
cargo run -q -- backup --to ./vault.bak
cargo run -q -- passwd                   # current password, then the new one (older backups keep the old one)
cargo run -q -- passwd --recovery        # forgot it: recovery code, then a new password
cargo run -q -- new-recovery-code        # current password; the new code must be typed back
cargo run -q -- --vault ./restored.keymesh recover --from ./vault.bak   # recovery code + new password
```

Passwords and recovery codes are read from the terminal without echo, or with `--password-stdin` one line each from stdin, followed by any other stdin input. They are never accepted as arguments or environment variables.

## Synthetic demo (CLI harness)

The CLI reads the demo vault key from `KEYMESH_DEMO_KEY`: 64 hex characters, used only by the synthetic demo provider. The key is never written to disk. Don't put real secrets in a demo vault.

```sh
export KEYMESH_DEMO_KEY=$(cargo run -q -- gen secret --bytes 32 --encoding hex)
export KEYMESH_VAULT=./demo.keymesh
cargo run -q -- init --demo
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
tests/           op_import.rs (fake runner + fake executable), cli.rs / cli_protected.rs (binary tests), v2_vectors.rs, fixtures/
crates/keymesh-wasm/  wasm-bindgen browser bridge (logic in bridge.rs, natively unit-tested)
apps/web/        Angular 22 demo app, Vitest unit tests, Playwright E2E (e2e/)
scripts/         build-wasm.sh (cargo wasm32 build + wasm-bindgen into apps/web), check-vectors.mjs
bench/kdf-wasm/  benchmark-only WASM crate (Argon2id timings in a browser; not part of the app)
docs/            ARCHITECTURE.md (formats, key hierarchy, browser app, decisions, limitations), DESIGN.md,
                 DELIVERY.md (HTTPS scope and decision), ROADMAP.md (backlog, gates, acceptance criteria),
                 adr/0001 (unlock/recovery design), adr/0002 (envelope v2), adr/0003 (quick unlock, proposed)
```
