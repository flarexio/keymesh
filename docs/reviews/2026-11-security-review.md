# Security review: v0.6.1 (2026-11)

* **Base:** `main` at `dc6e9f5` (tag `v0.6.1`), reviewed 2026-11-26.
* **Purpose:** an input to FlareX's decision on whether password vaults can leave "experimental, synthetic data only". This is a review only. No code was changed, and fixes will be separate PRs once FlareX picks them.
* **Method:** a manual read of the Rust core (`src/`), the WASM bridge (`crates/keymesh-wasm`), the web app (`apps/web`), CI and deploy.
  * Each finding below was checked by hand against the code at `dc6e9f5`.
  * The `/security-review` skill reviews a branch's pending diff, so it does not apply to a whole-tree review and was not used.
  * This is an internal review, not an independent audit.
* **Disclosure:** findings are descriptions only; there is no exploit code. All data used was synthetic.

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 10 |
| Info | 12 |

The cryptographic core holds up well:
* Argon2id bounds are checked before allocation.
* Every seal uses a fresh 192-bit random nonce.
* Slot AAD binds the vault, slot id, kind and KDF parameters.
* The manifest binds the exact slot list and every item.
* Duplicate JSON members are refused.
* The file chooses the version, so v2 cannot be downgraded to v1.
* Generators use rejection sampling and the OS CSPRNG only.

The medium findings are about the edges: deploy provenance, the clipboard, synced passkeys and secrets left in browser memory.

## Findings

Effort: **S** < ½ day, **M** 1–3 days, **L** > 3 days.

| ID | Sev | Area | Location | Description | Suggested fix | Effort |
|---|---|---|---|---|---|---|
| M-1 | medium | delivery | `deploy/pull-deploy.sh:164` | The provenance check fails open. With the default `KEYMESH_VERIFY_ATTESTATION=auto`, the build-attestation check runs only if `gh` is installed. Without `gh`, the deploy goes ahead and only logs "provenance NOT verified". The remaining checks are a digest match and the image's revision label, and anyone who can push to the Docker Hub repository controls both. | Make verification required by default. Keep `=0` as an explicit, logged opt-out, and fail if `gh` is missing or unauthenticated. | S |
| M-2 | medium | web | `features/secret-field.ts:77`, `shared/generated-password.ts:70`, `shared/recovery-confirm.ts:69`, `features/ed25519-tools.ts:23` | Copied secrets (passwords, generated values, the recovery code, Ed25519 output) stay in the system clipboard indefinitely. The app never clears them, so they can reach OS clipboard history and cross-device clipboard sync. Revealed values hide after 30 s, but copies don't. | Clear the clipboard after a short delay (e.g. 30–60 s) and on lock, as best effort. Say so in the toast. For the recovery code, discourage copying or warn about clipboard history. | S–M |
| M-3 | medium | web / product | `core/vault.service.ts:1234`; ADR 0003 §8 D1 | Backup-eligible (synced) passkeys are accepted for PRF slots (the BE flag is recorded and authenticated, not refused). A synced passkey with the stored ciphertext unlocks the vault. Its strength is then that of the passkey provider account and its recovery, not the device. D1 is still an open product decision. | Decide D1. Before real data, either restrict to device-bound (BE = 0) by default or show the disclosure at enrolment and in settings. | S (code) + decision |
| M-4 | medium | wasm / web | `crates/keymesh-wasm/src/lib.rs:380`, `:385`, `:182`; `core/kdf.ts:83` | Secrets in browser memory can't be erased:<br>• Revealed values, item inputs (JSON strings), the shown recovery code and the typed password are JS strings.<br>• wasm-bindgen copies string arguments and results through WASM linear memory, which is freed but not wiped.<br>• The KDF worker gets the password by structured clone.<br>After lock, plaintext fragments may remain in the JS heap and in linear memory until reused. Documented (`docs/ARCHITECTURE.md:254`, ADR 0002 §3) but unmitigated. | Keep the documented limit, and narrow it:<br>• On lock, drop and re-instantiate the WASM module so its old linear memory becomes unreachable.<br>• Have `reveal`/`shownRecoveryCode` wipe their Rust-side buffer (`Zeroizing`) before returning.<br>• Pass secret inputs as `Uint8Array` that JS zeroes after the call where an API allows it. | M |
| L-1 | low | web / headers | `apps/web/scripts/serve.mjs:50`, `src/index.html:9` | The CSP is good but not as tight as it could be:<br>• `style-src 'unsafe-inline'`;<br>• no `require-trusted-types-for 'script'`, even though the app has no HTML sinks;<br>• no `Permissions-Policy` or `Cross-Origin-Resource-Policy`. | Try Angular's CSP nonce or `autoCsp` for styles, enforce Trusted Types, and add `Permissions-Policy` (camera, microphone, geolocation, payment off) and `Cross-Origin-Resource-Policy: same-origin`. | S–M |
| L-2 | low | delivery | `apps/web/scripts/serve.mjs:57`, `deploy/README.md` | In production serve.mjs speaks plain HTTP behind the host's Traefik, so it never sends HSTS. Whether `keymesh.cloud` sends HSTS depends on proxy configuration outside this repo, and nothing checks it. | Confirm Traefik sets HSTS for `keymesh.cloud`. Record that as a deploy prerequisite and add a post-deploy header check. | S |
| L-3 | low | delivery | `deploy/web.Dockerfile:5`, `deploy/compose.yaml:22` | The runtime image is full `node:26-alpine`, with npm, npx, corepack and a shell, none of which serve.mjs needs. The container also uses host networking and has no memory or pids limit. It is already read-only, non-root, `cap_drop: ALL` and `no-new-privileges`. | Remove npm, npx and corepack from the image (or use a minimal Node runtime), and set `mem_limit` and `pids_limit`. Host networking is a documented choice; keep it only while it is needed. | S |
| L-4 | low | CI | `.github/workflows/ci.yml:48`, `:75` | The `rust` and `web` job checkouts keep the default `persist-credentials: true`. The job token (contents: read) therefore stays in `.git/config` while `npm ci`, build scripts and tests run third-party code. Every other checkout sets `false`. | Add `persist-credentials: false` to both. | S |
| L-5 | low | supply chain | `apps/web/package.json:30` (lock: `@angular/build` 22.2.3 → `vite` 8.3.0) | `npm audit` reports 1 high and 1 low, both dev-only:<br>• vite 8.3.0 under `@angular/build` (GHSA-9jrq-w75r-8gcw, GHSA-rq7h-c2jc-7f22, GHSA-vfpm-58rq-9qcg, plus launch-editor advisories);<br>• the dev server only, not used in production (serve.mjs).<br>`npm audit --omit=dev`: 0 vulnerabilities. | Bump `@angular/build` to a fixed release (≥ 22.2.5, per audit) and refresh the lock. | S |
| L-6 | low | supply chain | `Cargo.lock:636` | `rustix` 1.1.5 is affected by RUSTSEC-2026-0486 (xattr functions mark unwritten bytes as initialized). It is transitive (tempfile), and Keymesh doesn't call the xattr API. | `cargo update -p rustix` (≥ 1.1.6). Add `cargo audit` (or `cargo deny`) to CI. | S |
| L-7 | low | web | `core/quick-unlock.ts:77` | `prfFirst` copies the PRF output and callers zero the copy, but the original buffer in `getClientExtensionResults()` stays alive with the credential object until GC. | Zero the original buffer too, after copying. | S |
| L-8 | low | core / web | `src/vault.rs:26`; `docs/ARCHITECTURE.md:69` | Whole-file rollback is undetected (documented). Someone who can write the browser's storage, or who kept an old copy, can bring back an envelope from before a password change or passkey removal and open it with the old credential. Removing a passkey or changing the password protects only revisions written afterwards. | Document this in the UI near "remove passkey" and "change password": also rotate, and treat old backups as still valid. A monotonic revision kept outside the vault (e.g. in a separate store) would detect rollback within one profile. | S (docs) / M |
| L-9 | low | core | `src/kdf.rs:99` | The new-password blocklist has 16 entries. NIST SP 800-63B-4 asks for a check against commonly used or compromised passwords; the 15-character minimum carries most of the weight. | Bundle a modest common-password list (or a k-anonymous offline set) of passwords ≥ 15 characters. | S–M |
| L-10 | low | tests / safety | `tests/cli.rs:28`, `tests/cli_protected.rs:21` | The CLI tests inherit `PATH`. Every current `import-op` test passes `--op-path` to the fake `op`, and library tests inject `FakeRunner` or `ProcessOpRunner::with_program`, so nothing reaches a real `op` today. A future test that forgets `--op-path` would run the developer's real `op` (default `op` on `PATH`, `src/bin/keymesh.rs:975`). | Give the CLI test helpers a `PATH` that contains no `op` (or a decoy that fails loudly). | S |
| I-1 | info | threat model | ADR 0002 §3 | A compromised server or web host (or a compromised release pipeline) can serve modified JS or WASM that reads the password at unlock. HTTPS and attested images narrow who can do that but don't remove the trust. The service worker installs new versions automatically (`ngsw` prefetch), and there is no code signing, pinning or SRI. | Write this down for users before any real data is stored. Later options: an installed or native shell, reproducible builds with published bundle hashes (the asset ledger exists), and user-visible version/hash pinning. | — |
| I-2 | info | threat model | ADR 0003 §3 | **Browser-profile copy:** a copied profile includes the IndexedDB ciphertext and its slots, so it becomes an offline password-guessing target (Argon2id 64 MiB, t=3). A PRF slot is safe only if the authenticator secret is not in the profile (it depends on the authenticator, and a synced passkey depends on the provider account). | Keep it in the user-facing limits. | — |
| I-3 | info | threat model | `docs/ARCHITECTURE.md:258` | **No sync:** each browser holds an independent store. Backups are manual files, and an old backup stays openable with its old password or recovery code. | State it plainly at backup time (it already does for password changes). | — |
| I-4 | info | threat model | ADR 0001 §3 | **Lost device:** it keeps its ciphertext and old slots, unlocked by its password, recovery code or passkey. While unlocked, the auto-lock deadline decides exposure, and "never" is an option (`core/auto-lock.ts:24`). Rotation protects only later revisions. There is no remote wipe and no account. | Consider removing "never" (or warning) for password vaults before real data; document the lost-device steps (rotate, new recovery code, remove the passkey). | S |
| I-5 | info | core | `src/vault.rs:896`, `src/keyslot.rs:404`, `src/kdf.rs:203` | Short-lived stack copies of 32-byte keys (`[u8; 32]` before `Key256::from_bytes`, `*okm`) are not wiped. Low value next to M-4. | Build `Key256` in place, e.g. `Zeroizing::new([0; 32])` filled via `copy_from_slice`. | S |
| I-6 | info | core | `src/recovery.rs:79` | `RecoveryCode::parse` reserves 56 bytes in a `Zeroizing<String>`. Input longer than that (always invalid) makes it reallocate, which frees the earlier buffer without wiping it. | Reject based on the count of non-separator characters before pushing, or reserve the 256-byte input bound. | S |
| I-7 | info | core | ADR 0002 §3 | XChaCha20-Poly1305 is not key-committing (documented). The writer wraps one DEK, and the manifest check catches a wrong DEK. | None now; note it for any future multi-recipient format. | — |
| I-8 | info | web | `src/vault.rs:953` | The WebAuthn assertion signature is not verified, since there is no server (documented). The rpIdHash and UP/UV flags are checked, and the PRF output is the secret. Anyone who controls the JS can fake authenticator data, but such an attacker already has everything (I-1). | None. | — |
| I-9 | info | web | `apps/web/scripts/favicon.mjs:1`, `deploy/compose.yaml` | The optional favicon route is off: it needs `KEYMESH_FAVICON=1`, which compose doesn't set, plus an opt-in in each browser. When on, it reveals login hostnames to the server operator. Its design comment points to an uncommitted `.supervision/` note. | Keep it off. Move the design rationale into `docs/` if it stays. | S |
| I-10 | info | docs | `docs/ARCHITECTURE.md:255` vs `docs/DELIVERY.md:104` | ARCHITECTURE says there is no service worker, but the production build registers one (`app.config.ts:13`). | Fix the doc. | S |
| I-11 | info | tests | `apps/web/scripts/favicon.test.mjs:397` | Test F2 (a result just before the 3 s deadline) failed once in the full local run under load ("late success returned after 2999 ms"), then passed 3 of 3 reruns. It's a wall-clock boundary test. | Use an injected clock, or widen the margin. | S |
| I-12 | info | tests | `scripts/check-vectors.mjs`, `tests/fixtures/v2/` | Vector coverage:<br>• The independent Node/OpenSSL check covers Argon2id, HKDF, recovery-code text, both v2 envelopes (normal and rotated), PRF and a few negative cases. Rust tests cover tampering broadly.<br>• No v1 vector.<br>• No fuzzing of the untrusted parsers (`parse_any`, `RecoveryCode::parse`, `parse_otpauth_uri`, the favicon PNG decoder). | Add `cargo fuzz` targets for the envelope, recovery and otpauth parsers, and a tampered-slot or AAD-mismatch negative case to the independent checker. | M |

## Checked and found sound

* **KDF:**
  * Argon2id v0x13, 64 MiB / t=3 / p=1 by default.
  * File-read bounds are 19–128 MiB, t 2–8, p 1–4 and m×t ≤ 4× the default, checked before any allocation, on both read and write.
  * Salts are 16 bytes from the CSPRNG.
  * Passwords are NFC-normalized and length-bounded.
  * The Argon2 crate's `zeroize` feature is on.
* **AEAD:**
  * XChaCha20-Poly1305 with a fresh 192-bit random nonce on every seal, so random nonces can't realistically collide.
  * `open` checks the nonce and tag lengths first.
  * Plaintext is returned in `Zeroizing`.
* **Slots:**
  * Ids, kinds, algorithm, salt and wrapped lengths, the credential id range, and rp id/label syntax are all validated before unwrap.
  * Exactly one password and one recovery slot, at most 4 PRF slots, unique ids and credential ids.
  * HKDF info binds kind, vault id, slot id (and the credential id for PRF).
  * The slot AAD binds the canonical KDF record, so a changed BE flag, salt or parameter fails.
  * The manifest AAD binds `slots_digest`, so a slot that is added, removed or altered is detected.
* **Recovery code:**
  * 256-bit random secret, a versioned payload and a 16-bit check compared in constant time.
  * Never stored, and masked in screenshots.
* **Envelope parsing:**
  * Duplicate JSON member names are refused at any depth.
  * `deny_unknown_fields`, and the version comes from the file.
  * v1 opens only with a key provider and v2 only with a slot secret, so a v1 file in the password store fails closed (no downgrade).
  * The bridge caps envelopes at 64 MiB.
  * Item, title, value and list sizes are bounded.
* **Generators:**
  * `uniform_index` uses rejection sampling (no modulo bias) for passwords, passphrases (EFF list, pinned) and the Fisher–Yates shuffle.
  * `getrandom` is the only source, with no fallback (`js` feature on WASM).
  * There is no `Math.random` in the app.
* **Web storage:** IndexedDB holds only envelope bytes and public header fields, written with exact-byte compare-and-swap. `localStorage` holds only preferences, auto-lock settings and the favicon opt-in.
* **Lock:** `lock()` bumps the epoch, terminates the KDF worker, aborts WebAuthn, and frees the WASM sessions. Async continuations re-check the epoch, and derived keys are zeroed on stale paths.
* **Auto-lock:** deadlines are checked on resume and before protected operations, and `pagehide` locks.
* **XSS:**
  * No `innerHTML`, `bypassSecurityTrust*`, `eval` or `new Function` in app code.
  * The only dynamic `[src]` is the same-origin favicon URL behind the off-by-default route.
* **WebAuthn:**
  * RP ID is `location.hostname`, stored in the slot and compared again on unlock.
  * `userVerification: 'required'`, and UV is checked by the core.
  * The PRF salt is 32 bytes issued by the core for each slot.
  * Removing a passkey only deletes its slot. A passkey deleted on the authenticator just fails unlock, and the password and recovery code still work.
* **QR and TOTP:**
  * Image size, pixel and side limits.
  * Decoding runs in a worker, and pixel data is zeroed afterwards.
  * `otpauth://` parsing refuses HOTP, unknown or duplicate parameters and fragments, and bounds the secret length and period.
* **Service worker:** registered only in secure contexts. The degraded and unrecoverable states are surfaced (`app-update.ts`), and app repair never touches vault data.
* **1Password importer:**
  * Tests use `FakeRunner` or `ProcessOpRunner::with_program` with the fake `op` fixture.
  * `ProcessOpRunner::new()` (real `op`) is never used in tests. See L-10 for the remaining footgun.
* **CI:**
  * Top-level `contents: read`.
  * Only the manifest job has `id-token`, `attestations` and `artifact-metadata` write.
  * Every action is pinned by SHA.
  * Publishing happens only from strict `vX.Y.Z` tags, and tag builds skip caches.
  * No `pull_request_target`.
* **pull-deploy (when verification runs):**
  * Pins the image by index digest.
  * The signer regex requires `ci.yml@refs/tags/vX.Y.Z` in this repo, plus `--source-digest`, `--source-ref` and `--deny-self-hosted-runners`.
  * Checks the revision label and platform.
  * Can compare against the asset ledger.
  * Swaps only the web container, with rollback.

## Graduation blockers

What must be resolved before password vaults hold real data:

1. **M-1:** make deploy provenance verification mandatory.
2. **M-2:** clear copied secrets from the clipboard after a timeout and on lock, and warn about copying the recovery code.
3. **M-3 and ADR 0003 D1/D5:** decide on synced passkeys and the compromise-response gate. Revisit the auto-lock "never" option for password vaults (I-4).
4. **I-1 to I-4:** FlareX accepts and publishes the threat model in user-facing docs: a malicious server or JS swap, browser-profile copy, no sync, lost device and old backups.
5. **L-5 and L-6:** dependency hygiene (bump `@angular/build` and `rustix`) and add `cargo audit` to CI, so advisories are caught without a manual run.

Recommended before real data, but not blocking: M-4 (re-instantiate WASM on lock), L-1, L-2, L-4, L-7 and I-12 (fuzzing).

## Evidence

All on `dc6e9f5` (macOS, local), run 2026-11-26:

| Check | Result |
|---|---|
| `cargo fmt --all --check` | rc=0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | rc=0 |
| `cargo test --workspace --all-features` | 176 passed, 0 failed |
| `cargo clippy -p keymesh -p keymesh-wasm --lib --no-default-features --target wasm32-unknown-unknown -- -D warnings` | rc=0 |
| `node scripts/check-vectors.mjs` | all vector checks passed (25 checks) |
| `npm ci` / `npm run build:wasm` / `typecheck` / `build` | rc=0 |
| `npm test` | 196 passed (18 files) |
| `npm run e2e` | 128 passed (3.1 min) |
| `npm run tls-check` | all TLS checks passed |
| `npm run test:serve` | first run 1 failure (I-11, timing), then 3 reruns: 39 passed, 0 failed |
| `npm audit` | 2 vulnerabilities (1 low, 1 high), dev-only (L-5); `--omit=dev`: 0 |
| `cargo audit` | not installed on this machine. Equivalent: the 102 registry crates in `Cargo.lock` were queried against OSV (RustSec data), with 1 advisory: rustix 1.1.5, RUSTSEC-2026-0486 (L-6) |
