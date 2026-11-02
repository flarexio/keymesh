# ADR 0002: Envelope v2 — master password and recovery code

* **Status:** Implemented as **experimental** in M4 (native core, CLI, browser). Not independently reviewed yet; synthetic data only until Jarvis accepts it. Implements Stage 1 of ADR 0001.
* **Date:** 2026-11-02
* **Deciders:** FlareX approved M4: master password plus an independent recovery code first, with mnemonic, keycard and passkey adapters deferred.

## 1. Scope

**In scope:**
* Local decryption of one vault with a master password, or with a recovery code that is independent of the password.
* Encrypted backup and restore.
* Password reset with the recovery code.
* Replacing the password or the recovery code.

**Out of scope:**
* Accounts, sign-in, sync and remote identity.
* Wallet-derived keys, passkeys/PRF and device slots (ADR 0001 stages 2–4).
* Key escrow and support resets.
* Compromise rotation of the data key (§8).
* Migration of demo data (§10).

## 2. Standards and libraries (checked 2026-11-02)

| Need | Choice | Primary source |
|---|---|---|
| Password KDF | Argon2id, version 0x13 | RFC 9106: §3.1 (salt 16 bytes recommended), §4 (parameter choice) |
| Key derivation from Argon2 output and from the recovery secret | HKDF-SHA256 | RFC 5869 |
| AEAD | XChaCha20-Poly1305 (unchanged from v1) | draft-irtf-cfrg-xchacha-03; `chacha20poly1305` 0.10 |
| New master passwords | Length rules plus a whole-password blocklist, NFC, paste allowed | NIST SP 800-63B-4 §3.1.1.2 |
| Where the browser allows password vaults | Secure contexts only | W3C Secure Contexts |

Pinned crates (`=` versions in `Cargo.toml`):
* `argon2 =0.5.3`, `hkdf =0.12.4`, `unicode-normalization =0.1.26`, plus the native-only `rpassword =7.5.4`.
* `argon2 0.6.0` (docs.rs, released 2026-10-19) is the newest release. It moves to the next RustCrypto digest generation and is two weeks old. Adopting it would add a second `digest`/`sha2` stack to the WASM build, so it is deferred to its own review.
* `argon2 0.5.3` is pinned against the RFC 9106 §5.3 Argon2id test vector (`kdf::tests`).
* Node's independent OpenSSL Argon2id reproduces both that vector and Keymesh's own vector (`scripts/check-vectors.mjs`).
* None of these crates states an audit.

## 3. Threat model

**Assets:** item plaintext; the data key (DEK); the master password; the recovery code.

**Protected against:**

| Adversary | Can do | Result |
|---|---|---|
| Someone with a copy of the vault file or a backup | Offline guessing against the password slot | Each guess costs one Argon2id (64 MiB, t=3). A strong password resists; a weak one does not. The recovery slot needs a 256-bit secret, so it cannot be guessed |
| A malicious or corrupted file (e.g. a "backup" from someone else) | Hostile KDF cost, malformed or duplicated slots, version tricks | Bounds are checked before any derivation or allocation. Every structural error is refused (§6); a failed open never yields an empty or new vault |
| An attacker who can edit the stored file but has no key | Swap, drop, add or alter slots, items, the revision or the vault id | Detected: the slot AAD binds each slot to the vault; the manifest binds the slot list and every item (§5) |
| Another tab, or a writer that is behind | Overwriting newer data | Exact-byte compare-and-swap (browser) and an exact-byte check before replacing (native, single writer; §9) |
| A network attacker on plain HTTP | Replace the app's code | Password vaults are refused on non-secure origins (§11). The HTTP previews stay demo-only |

**Not protected against (stated limits):**
* A compromised device, browser, extension or OS while the vault is unlocked.
* A malicious server delivering the web app. HTTPS limits who that can be; it does not remove the trust in the operator.
* Rollback of the whole file to an older valid revision.
* Someone who already holds an old backup together with its old password or code (§8).
* JavaScript strings cannot be reliably erased. The typed password lives in JS memory until it is garbage-collected.
* XChaCha20-Poly1305 is not key-committing. Unwrapping a slot to a wrong DEK is still caught, because the manifest fails to open, but a crafted file could in principle make two slots unwrap to different keys. The writer only ever wraps one DEK.

## 4. Key hierarchy

```text
DEK  = 32 random bytes (OS CSPRNG), per vault; encrypts manifest and items (as in v1)
password slot:
  ikm  = Argon2id(NFC(password), salt[16], m_kib, t, p, out = 32)
  KEK  = HKDF-SHA256(salt = ∅, ikm, info = fields("keymesh.vault","2","kek","password", vault_id, slot_id))
recovery slot:
  ikm  = recovery secret[32]
  KEK  = HKDF-SHA256(salt = slot salt[16], ikm, info = fields("keymesh.vault","2","kek","recovery", vault_id, slot_id))
wrapped = XChaCha20-Poly1305(KEK, nonce[24] random, DEK, AAD = slot_aad)
```

* The DEK and the KEKs are separate keys. Changing a password or recovery code rewraps the same DEK.
* Neither the Argon2 output nor the recovery secret is ever used as a key directly.
* `fields(a, b, …)` means each part preceded by its length as a u32 big-endian, for unambiguous context strings.

## 5. Wire format (`keymesh.vault`, version 2)

```json
{
  "format": "keymesh.vault", "version": 2, "aead": "xchacha20poly1305",
  "vault_id": "<32 lowercase hex>", "revision": 1,
  "slots": [
    { "id": "<16 lowercase hex>", "kind": "password",
      "kdf": { "alg": "argon2id", "v": 19, "m_kib": 65536, "t": 3, "p": 1, "salt": "<b64url 16 bytes>" },
      "wrapped": { "nonce": "<b64url 24>", "ct": "<b64url 48>" } },
    { "id": "<16 lowercase hex>", "kind": "recovery",
      "kdf": { "alg": "hkdf-sha256", "salt": "<b64url 16 bytes>" },
      "wrapped": { "nonce": "…", "ct": "…" } }
  ],
  "manifest": { "nonce": "…", "ct": "…" },
  "items": [ { "id": "…", "rev": 1, "sealed": { "nonce": "…", "ct": "…" } } ]
}
```

Authenticated data:

```text
canonical(argon2id) = fields("argon2id", be32 v, be32 m_kib, be32 t, be32 p, salt)
canonical(hkdf)     = fields("hkdf-sha256", salt)
slot_aad     = fields("keymesh.vault","2","slot", aead, vault_id, slot_id, kind, canonical(kdf))
slots_digest = SHA-256(be32 count ‖ for each slot in file order: fields(id, kind, canonical(kdf), nonce, ct))
manifest_aad = fields("keymesh.vault","2","manifest", aead, vault_id, be64 revision, slots_digest)
item_aad     = fields("keymesh.vault","2","item", aead, vault_id, item_id, be64 rev)
```

Which metadata is authenticated, and when:
* **Before unlock:** each slot's own AAD covers its vault id, slot id, kind and KDF parameters. A changed parameter, or a slot copied from another vault, fails to unwrap.
* **After unlock, with either slot:** the manifest covers the header (vault id, revision) and the exact bytes and order of every slot. Removing, adding, reordering or altering any slot, including the one not used, fails the open.
* **Not authenticated:** the `format`, `version` and `aead` strings, but they are checked against fixed values and every key derivation also binds version "2", and JSON whitespace.

## 6. Validation and failure handling

Everything below is checked when the file is parsed, before any key derivation. Order: bounded read (64 MiB, the same as v1), JSON, format, version, then per-version strict schema (`deny_unknown_fields`).

| Input | Handling |
|---|---|
| Unknown `version`, unknown `aead` | `Format` error |
| v2 file relabelled `version: 1` (or the reverse) | `Format` error: the v1 schema has no `slots`, and the v2 schema has no `kek_id`/`wrapped_dek` |
| v1 file opened with a password, v2 file opened with a demo key | `Format` error ("demo vault without a password" / "opens with its password or recovery code") |
| Slot count outside 1..=8, not exactly one `password` and one `recovery`, duplicate slot id | `Format` error |
| Unknown slot kind, wrong algorithm for the kind, unknown fields | `Format` error (no silent skipping) |
| Slot id not 16 lowercase hex, vault id not 32 lowercase hex | `Format` error |
| Salt ≠ 16 bytes (base64 text over 64 characters is refused before decoding), nonce ≠ 24, wrapped ≠ 48 bytes | `Format` error |
| Argon2 `v` ≠ 19; `m_kib` outside 19 456..=131 072; `t` outside 2..=8; `p` outside 1..=4; m·t over 786 432 KiB-passes | `Format` error before allocation (tests assert under 200 ms natively; a 5 s ceiling in the browser) |
| KDF parameters changed within bounds, slot from another vault, revision or vault id changed | `Decrypt` (AEAD fails) |
| Altered recovery slot, while opening with the password (and the reverse) | `Decrypt` (manifest AAD binds the slot digest) |
| Item records dropped, swapped or duplicated | `Integrity` / `Decrypt`, as in v1 |
| Wrong password or wrong recovery code | `Decrypt`. The UI says "doesn't open this vault"; it never distinguishes the cause further |
| Recovery-code typo | Refused by the 16-bit check before any decryption |

The KDF request that the browser sends to its worker is just the slot's public parameters. The worker re-validates the same bounds before it allocates (`derive_password_key`). A failed open never replaces or empties stored data: every write is a separate, explicit step after a successful open.

## 7. Parameters and measurements

Synthetic input. Five runs each; the table shows the median in ms. Single-threaded Argon2 in both builds.

| m (MiB) | t | p | Native release, Pi 4 (ms) | WASM, Chromium 156 headless, same Pi (ms) |
|---|---|---|---|---|
| 19 | 2 | 1 | 89 | 128 |
| 46 | 1 | 1 | 209 | 164 |
| 46 | 2 | 1 | 332 | 314 |
| 64 | 1 | 1 | 293 | 231 |
| 64 | 2 | 1 | 466 | 437 |
| **64** | **3** | **1** | **637** | **643** |
| 64 | 3 | 4 | 634 | 641 |

* **Hardware and toolchain:**
  * Raspberry Pi 4 Model B (Cortex-A72 at 1.8 GHz, 8 GB RAM), Ubuntu with Linux 6.8 (aarch64).
  * rustc 1.99.1, wasm-bindgen 0.2.129, Playwright Chromium 156.0.8078.4 headless.
  * Full table: `cargo run --release --example kdf_bench` and `bench/kdf-wasm`.
* **Not measured:** no phone, no laptop, no Firefox or Safari. Nothing here is a real-phone measurement.
* **Real app:** a full unlock in the app (worker start, module hand-off, Argon2id, decrypt, UI) took about 1.1 s in the E2E on the Pi.

Choice: **m = 64 MiB, t = 3, p = 1, 16-byte salt, 32-byte output.**
* This is RFC 9106's second recommended option, except for parallelism.
* RFC 9106 §4 says to pick the number of lanes from the threads available. The core runs Argon2 on one thread, and browser WASM without threads (which would need cross-origin isolation) is single-threaded too. The table shows p=4 is no faster in either build.
* p does not change the memory or total work an attacker needs, so p=1 is the honest match to the real capability.
* RFC 9106's first option (2 GiB) is not practical in a browser.
* Roughly 0.65 s on a Pi 4 meets the ADR 0001 laptop target (≤ 1 s) on slower hardware. Phones remain unmeasured.

**Read bounds:**
* The bounds allow future defaults up to 128 MiB, t up to 8, and four times the default work.
* They also accept down to an OWASP-style floor of 19 MiB and t=2, for a future low-memory profile.
* Keymesh itself only ever writes the default; the lower floor is defence in depth, not a configurable setting.
* Tests use the real default parameters. No floor is lowered for test speed: only the `argon2`/`blake2` crates are compiled with optimisation in debug builds.

## 8. Recovery code, password rules and lifecycle

**Recovery code (version 1):**
* `payload = 0x01 ‖ secret[32] ‖ SHA-256("keymesh recovery code" ‖ 0x01 ‖ secret)[0..2]`.
* Encoded in RFC 4648 Base32: 56 characters, shown as 14 groups of 4.
* Parsing ignores case, spaces and hyphens, and maps `0/1/8` to `O/I/B`. An unknown version byte is refused.
* The code *is* the key material for its slot. It is not a password, a wallet phrase or a signature, and it is not BIP-39. Keymesh never stores it.

**New master passwords** (NIST SP 800-63B-4 §3.1.1.2):
* NFC normalization; at least 15 code points; at most 1024 UTF-8 bytes.
* No composition rules.
* Refused if the whole password is one repeated character or appears on a small built-in blocklist (not a breach corpus).
* Paste and password managers are allowed. Existing passwords are only NFC-normalized and bounded.

**Lifecycle:**

| Operation | Authority required (verified by the core, never a UI flag) | Effect |
|---|---|---|
| Create | none | New random vault id and DEK, fresh password and recovery slots. **Cannot be sealed or stored until the recovery code is typed back** (checked by unwrapping its slot) |
| Unlock | password | Opens a session |
| Reset password | recovery code (the core unwraps the recovery slot) | New password slot with a fresh id and salt; same DEK |
| Change password | current password: its Argon2 key must unwrap the current slot to the in-memory DEK (constant-time compare) | Same as reset |
| New recovery code | current password | New code shown once; installed only after it is typed back; same DEK |
| Restore from backup | that backup's password (stored as is) or its recovery code plus a new password (stored as a new revision) | Allowed into empty storage, or over the unlocked vault this tab last saw (compare-and-swap) |

Changing a password or recovery code is a **rewrap, not a rotation**:
* Backups made before the change still open with the old password and the old code.
* Data that was already read stays read.
* The UI and CLI say this. A recovery-code reset leaves the recovery code unchanged.

**Compromise rotation is deferred.** That means a new DEK, every item re-encrypted, and every surviving slot re-established. `Vault::rotate_data_key` refuses v2 vaults, and nothing advertises revocation.

## 9. Persistence and concurrency

**Browser (`apps/web`):**
* Password vaults live in their own IndexedDB database, `keymesh-vault`.
* Every write is an exact-byte compare-and-swap. A write's guard is checked after the database opens and again after the current record is read, before `put`.
* Each operation captures the lock generation when it is invoked and re-checks it after every `await`. That covers the worker KDF, IndexedDB reads and writes, and file reads.
* **One credential operation at a time:** a second one is refused, not queued.
* **Locking** terminates a running worker, and a result that arrives late is zeroed and dropped.
* **Failed credential writes:** if a password or recovery-code change fails to write, the core rolls back to the stored slots.
* **Derived keys** (in `Uint8Array`) are zeroed after use. Both tests above are deterministic: `protected-vault.spec.ts` uses a hand-released KDF, and the E2E holds the worker script.

**Native (`storage.rs`, CLI):**
* The atomic replace is a temp file, fsync, rename, then a directory fsync.
* **Before replacing:** the file is re-read, and the save is refused unless its SHA-256 equals the bytes this process last read or wrote.
* **This is a check, then a rename, not a lock:** Keymesh assumes a single writer per vault file and does not implement file locking. Two processes saving in the same instant can still race.
* Every CLI command opens the vault itself, running Argon2id each time; there is no agent or key cache.
* Credentials come from the terminal without echo, or with `--password-stdin` one line each. They never come from arguments or the environment.

## 10. Demo data and migration

**Demo vaults are not converted:**
* Demo vaults (v1, the public fixture key or the ephemeral key) keep their own database (`keymesh-demo`) and CLI path (`init --demo`, `KEYMESH_DEMO_KEY`).
* They are never relabelled or converted. Their contents were already disclosed (fixture) or cannot be recovered (ephemeral).

**Password vaults start empty:**
* A password vault always starts empty, with a fresh vault id and DEK.
* There is no automatic or manual migration. Importing real 1Password data is not part of M4.

**Formats never cross:**
* v1 files stay readable for synthetic and demo use.
* A v1 backup cannot be restored as a password vault, and a v2 backup cannot be restored as a demo.

## 11. Delivery

The browser offers password vaults only in a secure context (W3C Secure Contexts): HTTPS, or loopback for development.
* **On non-secure origins:** on the plain-HTTP LAN/VPN previews, every password-vault operation is refused, and the `keymesh-vault` database is never opened. The demo stays usable.
* **Trusted remote access:** that needs a certificate the client devices trust. See `docs/DELIVERY.md` for the tested scope and the open decision.

## 12. Verification

* **Rust vault-format tests:** `vault::tests::v2_*`, `keyslot`/`kdf`/`recovery` unit tests, `storage::tests::protected_*`.
* **Rust CLI and bridge tests:** real-binary CLI flows (`tests/cli_protected.rs`), bridge tests.
* **Shared vectors:** `tests/fixtures/v2/vectors.json`. They are checked natively (`tests/v2_vectors.rs`), independently with Node and OpenSSL including a full envelope decryption (`scripts/check-vectors.mjs`), and in the browser through the compiled WASM (`apps/web/e2e/protected.spec.ts`).
* **Browser orchestration:** `protected-vault.spec.ts` (unit tests) and `e2e/protected.spec.ts` (Chromium only).

## 13. Sources (accessed 2026-11-02)

* RFC 9106 (Argon2), §3.1, §4, §5.3: https://www.rfc-editor.org/rfc/rfc9106.html
* RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869.html
* RFC 4648 (Base32): https://www.rfc-editor.org/rfc/rfc4648.html
* NIST SP 800-63B-4 §3.1.1.2: https://pages.nist.gov/800-63-4/sp800-63b.html
* W3C Secure Contexts: https://www.w3.org/TR/secure-contexts/
* XChaCha20 (draft-irtf-cfrg-xchacha-03): https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
* RustCrypto `argon2` documentation (0.6.0 listed as latest, 2026-10-19): https://docs.rs/argon2/latest/argon2/
