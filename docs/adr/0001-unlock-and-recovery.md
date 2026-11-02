# ADR 0001: Local unlock, recovery and trusted delivery

* **Status:** Proposed. **Stage 1 (password + recovery slots, secure-context gating) is implemented as experimental in M4; see ADR 0002**, which supersedes §3's sketch where they differ: exact AAD, HKDF over the Argon2 output, and parameters chosen from measurements. Stages 2–4 remain design only. This ADR does not authorize real-secret entry, Keymesh authentication, identity registration, KMS/NATS/blockchain dependencies, public deployment or automatic migration.
* **Date:** 2026-10-29
* **Deciders:** FlareX (product owner). Reviewed by Jarvis.

## 1. Context

Today's keys (see `docs/ARCHITECTURE.md`, "Key hierarchy"):

* A per-vault random 256-bit DEK encrypts the manifest and items with XChaCha20-Poly1305. The DEK is wrapped once by a KEK from a `KeyProvider`, and the AAD binds `vault_id` and `kek_id`.
* The only providers are test/demo providers: an ephemeral in-memory key (lost on reload) and the **synthetic fixture key, which is public** because it is in the repository. A vault sealed with the fixture key is effectively plaintext to anyone with a copy.
* The web previews are served over plain HTTP on a LAN/VPN address. That is not a secure context: anyone on the path can replace the app's script and read an unlocked vault.
* The product direction (`CLAUDE.md`) defers own-app authentication, mnemonic login, image keycards, wallet/identity/KMS integration, NATS and blockchain. The user's original concept is a wallet- and edge-oriented system. This ADR keeps that path open and does not choose an identity model on the user's behalf.

## 2. Terms

These are different things and must not share keys.

| Term | Question it answers | Key material | In scope now |
|---|---|---|---|
| **Local unlock** | Can this device decrypt this vault? | A KEK that wraps the DEK | Designed here |
| **Recovery** | Can the owner regain decryption after losing the usual unlock? | A separate high-entropy wrapper of the DEK | Designed here |
| **Remote identity / authentication** | Is this the same person or device to a sync or edge service? | Signing keys, passkeys (assertions), sessions | Deferred |
| **Recovery authorization** | Who may add an unlock method or enrol a device? | Proof of an existing unlock, or a policy | Partly (local only) |
| **Wallet identity** | Which on-chain or edge identity is this? | The user's wallet keys | Deferred (human decision) |
| **App mnemonic / keycard** | How does a person write down or carry a recovery secret? | An *encoding* of the recovery key | Encoding decision only |

Rules:

* Encryption keys are never identity keys. A signing key (Ed25519 vault items, a wallet, a passkey assertion) is never used directly as a KEK.
* Logging in to a future service never decrypts the vault by itself. The server holds ciphertext only.

## 3. Decision (proposed): key slots wrapping one DEK

Envelope v2 replaces the single `wrapped_dek` with a list of independent **key slots**. Each slot wraps the same DEK. The DEK and the item format stay as in v1.

```text
slot = { id, kind, params, wrapped: XChaCha20-Poly1305(KEK_slot, DEK) }
AAD  = "keymesh.vault" ‖ v2 ‖ "dek" ‖ alg ‖ vault_id ‖ slot.id ‖ slot.kind ‖ canonical(params)
```

* **`password`** (Stage 1). `KEK = Argon2id(password, salt_128, m, t, p) → 32 bytes`, with the salt and parameters stored in `params`.
  * The starting point is RFC 9106's second recommended option (Argon2id, t=3, p=4, m=64 MiB, 128-bit salt), checked against the measured budget (§7). RFC 9106's first option (2 GiB) is not practical in a browser.
  * Parameters are bounded on read, so a hostile file cannot demand excessive memory. The bound also limits work per guess.
  * Password guidance follows NIST SP 800-63B-4: a long passphrase rather than composition rules, a blocklist check, and paste and password managers allowed. The vault's own generator can produce the password.
* **`recovery`** (Stage 1, required when a vault is created).
  * A random 256-bit recovery key, shown once and never stored by Keymesh. `KEK = HKDF-SHA256(recovery_key, info="keymesh recovery v2" ‖ vault_id)`. No password stretching is needed because the key is full-entropy.
  * The user must confirm it was saved (for example by re-entering a few groups) before the vault holds data.
* **`webauthn-prf`** (Stage 2, optional).
  * A passkey's PRF output (WebAuthn Level 3 `prf` extension), using a per-slot salt. The extension is *modelled on* CTAP2 `hmac-secret`, but clients and authenticators may implement it by other means, so Keymesh relies only on the WebAuthn-level behaviour: the same credential and salt give the same output, and evaluation needs a user gesture on that authenticator. `KEK = HKDF-SHA256(prf_output, info="keymesh webauthn-prf v2" ‖ vault_id ‖ credential_id)`.
  * It is a convenience unlock, not a replacement for password and recovery, because not every authenticator or browser supports PRF.
* **`device`** (Stage 3, multi-device).
  * Each device holds an X25519 key pair in platform or OS storage where available. An already unlocked device wraps the DEK to the new device with HPKE (RFC 9180, base mode). Enrolment therefore needs an existing unlock: that is the local recovery-authorization rule.

Slot changes:

* Adding or removing a slot needs the vault to be unlocked.
* Removing a slot that is merely unused (for example a passkey the user no longer has) only deletes its entry; no rotation is needed. Older ciphertext copies (backups, other devices) still carry that slot, and the UI must say so.
* **Rotation after suspected compromise** (a lost device, an exposed password or recovery key) replaces the DEK (`Vault::rotate_data_key` exists) and re-encrypts every item. Holding the DEK does **not** give the other slots' KEKs, so each remaining slot must be re-established for the new DEK:

  | Slot | What re-establishing it needs |
  |---|---|
  | `password` | The user re-enters the password (or sets a new one). Argon2id runs again with a new salt |
  | `recovery` | The user re-enters the existing recovery key, or Keymesh generates a new one, shows it once and requires confirmation (re-entering some groups). A replaced recovery key stops working for the new DEK |
  | `webauthn-prf` | A fresh PRF evaluation, which needs a user gesture on that authenticator |
  | `device` | Only the device's public key: HPKE wraps to a public key, so other enrolled devices need no secret from them. The lost device's slot is dropped |

  **Staging.** The rotation first collects every KEK it can, before anything is written. Slots that cannot be re-established in that session (the authenticator isn't present, the user skips the password) are listed and explicitly **invalidated**, never silently kept with the old DEK. The user confirms the resulting slot list. A rotation that would leave no confirmed recovery path is refused unless the user explicitly accepts "no recovery" after a plain warning.

  **Atomicity.** The new envelope (new DEK, re-encrypted items, new slot list) is built fully in memory and written in one step: an atomic file replace on native, one IndexedDB compare-and-swap transaction in the browser. Either the old or the new envelope is stored, never a mix. Cancelling, a lock, or a failure before that write leaves the old envelope and all old slots intact.

  **Device-loss consequences.** Rotation protects only revisions written afterwards. A lost device keeps whatever ciphertext and old slots it had, protected only by those slots (an offline guessing target for a weak password). If the recovery key could have been exposed with it (for example, written down and kept with the device), replace the recovery key as part of the same rotation. Devices whose slots were dropped must enrol again from an unlocked device.

Rejected or deferred alternatives:

* **One password-derived KEK only (v1 shape).** Losing the password loses the data, and a second method cannot be added without re-wrapping.
* **Server-side escrow or KMS.** It conflicts with local-first and needs an identity model. Deferred.
* **KEK derived from a wallet signature.** Deterministic signatures exist (Ed25519 per RFC 8032 is deterministic; ECDSA only with RFC 6979, and wallets differ). However:
  * the vault's confidentiality would be tied to wallet-key compromise;
  * every unlock would ask the wallet to sign;
  * a wallet that changes its signing behaviour would lock the user out.

  This is listed as a human decision (§8), not chosen.
* **BIP-39 seed derivation for the recovery key.** BIP-39's PBKDF2 seed (2048 rounds, salt "mnemonic") is a wallet construction. Its word list may at most serve as a human *encoding* of our 256-bit recovery key, which would be decoded back to the raw entropy. Using the same format as wallet recovery words invites confusion with the user's wallet phrases, which Keymesh stores only as encrypted item data. Base32 groups are the default encoding; words, QR or an "image keycard" are encoding choices for the human (§8).

## 4. Recovery paths and device loss

| Situation | Path | Result |
|---|---|---|
| Forgot password, has recovery key | Unlock with the recovery slot and wrap the same DEK under a new password (replaces the `password` slot; no rotation needed). If the old password may be known to someone else, run a rotation (§3) instead | Full access |
| Lost one device, another device is unlocked | Rotation (§3): drop the lost device's slot, re-establish the others (password re-entry, PRF gesture, recovery key re-entry or replacement with confirmation, other devices via public keys), invalidate any that can't be re-established, then write once | Full access with the confirmed slots. The lost device keeps the ciphertext it had, protected only by its old slots (an offline guessing target for a weak password) |
| Lost every device, has the recovery key and a ciphertext copy (backup file or future sync) | Open the backup with the recovery slot | Full access to that backup's revision |
| Lost every unlock method | None | **Data is unrecoverable.** The UI and docs must say this plainly when the vault is created |
| Passkey removed or provider changed | Use the password or recovery slot, then remove the stale `webauthn-prf` slot (rotate only if the passkey may be in someone else's hands) | Full access |

Keymesh never promises recovery that needs material it does not have. There is no "contact support" path, because no one else holds a key.

## 5. Trusted delivery (HTTPS and secure contexts)

* Under W3C Secure Contexts, `http://` to a LAN or VPN IP is **not potentially trustworthy**; `https:`, `127.0.0.0/8` and `::1` are.
  * `crypto.subtle` is `[SecureContext]` in the Web Crypto API.
  * WebAuthn is available only in secure contexts.
  * `crypto.getRandomValues` is not `[SecureContext]`, which is why the HTTP preview works.
* Even over HTTPS, a web vault trusts whoever serves its code on each load. Delivery options, increasing in assurance:
  1. **HTTPS origin with a valid certificate.** Keep the current strict CSP and same-origin assets, and add Subresource Integrity on the entry chunks. The server operator is trusted on every load.
  2. **Installed app shell.** A PWA with a service worker reduces exposure to a single update path, but updates still come from the origin.
  3. **Signed native or desktop shell, or the CLI.** Code changes only with a signed release.
* **Rule:** real-secret entry is enabled only from a secure context with a non-demo key provider. The HTTP previews stay UI-only and keep the warning "Preview version. Do not store real passwords."

## 6. Migration from fixture or demo data

* Anything sealed with the public fixture key must be treated as **already disclosed**: the stored vault, IndexedDB copies and backup files. Relabelling it "production" or adding a password slot cannot make it secret.
* The ephemeral demo key is gone after reload. Those vaults cannot be migrated at all.
* **Recommended:** real vaults start empty with v2 slots. There is no automatic migration of demo vaults. If moving data out of a demo vault is wanted, it is an explicit "copy items into a new vault" action that warns the data was not protected. It rotates to a fresh random DEK and never reuses the fixture-sealed bytes.
* Reading v1 stays supported for synthetic or demo files. Writing v2 needs a reviewed format specification and migration tests (corrupt, oversized and downgrade cases) before any implementation.

## 7. Algorithms, libraries, and what to measure

| Need | Choice | Notes |
|---|---|---|
| AEAD | XChaCha20-Poly1305 (`chacha20poly1305`, already used) | Unchanged |
| Password KDF | Argon2id, RFC 9106 | RustCrypto `argon2` (docs.rs shows 0.6.0, 2026-10-19; supports `no_std`; no audit stated). Pin the version and review it before adoption |
| Key derivation from high-entropy inputs | HKDF-SHA256, RFC 5869 | RustCrypto `hkdf` |
| Device enrolment | HPKE, RFC 9180 (Informational, CFRG) | Choose a maintained Rust implementation in Stage 3. Not selected yet |
| Passkey PRF | WebAuthn Level 3 `prf` (W3C Recommendation, 2026-08-25) | Feature-detect it; never the only slot |
| RNG | OS CSPRNG (`getrandom` / `crypto.getRandomValues`), already used, no fallback | Unchanged |

No measurement spike was run for this ADR, because it would have meant adding a new crypto dependency to the repository. The first Stage 1 task is a synthetic-input benchmark:

* Measure Argon2id at m ∈ {19, 46, 64} MiB, t ∈ {1, 2, 3}, p=1 versus p=4.
* Run it natively on the Pi and in WASM in Chromium and Firefox on a mid-range phone and a laptop.
* Targets: unlock ≤ 1 s on a laptop and ≤ 3 s on a phone, no out-of-memory on a 2 GB phone, and reject any parameter set above the stored bound.
* WASM runs the lanes sequentially unless threads are enabled (threads need cross-origin isolation, which also requires a secure context). That cost is part of what is measured.

## 8. Material human decisions

1. **Identity model.** Should a future Keymesh account or sync identity be a passkey, a wallet key (which chain or standard), or an edge-node or device identity? This ADR only requires that it is separate from encryption keys.
2. **Wallet-derived unlock.** Allow a wallet signature as an *optional* extra slot (with the drawbacks in §3), or never?
3. **Recovery-key format.** Base32 groups (default), a word list, QR, or an "image keycard"? Is a printed copy expected?
4. **Delivery channel for real use.** An HTTPS web origin (whose?), an installed PWA, a signed desktop or mobile shell, or CLI only at first?
5. **Escrow.** Confirm "no server or KMS escrow; lost slots mean lost data", or ask for an escrow design later.
6. **Demo data.** Confirm that demo vaults are never migrated automatically.

## 9. Recommended staged path

1. **Stage 0 (now).** Demo only, synthetic data, warnings unchanged. The HTTP previews are for UI checks only.
2. **Stage 1.** Envelope v2 format specification and review, then the Argon2id `password` slot and the mandatory `recovery` slot.
   * Implement in the native CLI first, where web delivery trust does not apply.
   * Then the web app, served only from a secure context.
   * Fresh vaults only. Includes the KDF benchmark (§7) and tests for slot add/remove, DEK rotation and hostile parameters.
3. **Stage 2.** Optional `webauthn-prf` slot behind feature detection.
4. **Stage 3.** Device slots with HPKE enrolment, once a sync channel exists (for example the user's edge/NATS idea). It needs decision 1.
5. **Stage 4.** Remote identity and wallet integration, as decided in §8. Sync and authentication carry ciphertext and authorization, never the DEK in plaintext.

## 10. Sources (primary, accessed 2026-10-29)

* RFC 9106, Argon2 Memory-Hard Function, §4 Parameter Choice: https://www.rfc-editor.org/rfc/rfc9106.html
* RFC 5869, HKDF: https://www.rfc-editor.org/rfc/rfc5869.html
* RFC 9180, Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180.html
* RFC 8032, EdDSA (deterministic Ed25519): https://www.rfc-editor.org/rfc/rfc8032.html
* W3C Web Authentication Level 3 (Recommendation, 2026-08-25), §10.1.4 `prf`: https://www.w3.org/TR/webauthn-3/
* W3C Secure Contexts (Candidate Recommendation Draft, 2023-11-10): https://www.w3.org/TR/secure-contexts/
* W3C Web Cryptography API (`[SecureContext] subtle`): https://www.w3.org/TR/WebCryptoAPI/
* NIST SP 800-63B-4, passwords (§3.1.1), syncable authenticators, account recovery (§4.2): https://pages.nist.gov/800-63-4/sp800-63b.html
* BIP-39 (seed derivation and word lists): https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
* RustCrypto `argon2` crate: https://docs.rs/argon2/latest/argon2/
