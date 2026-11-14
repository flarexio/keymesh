# ADR 0003: Quick unlock, auto-lock and master-password custody

* **Status:** **Proposed. Nothing in this ADR is implemented.** It needs independent review and a scoped task before any code. It does not authorize real-secret entry, Keymesh login, external network calls or trust changes.
* **Date:** 2026-11-14
* **Builds on:**
  * ADR 0001 (key slots wrapping one DEK; the `webauthn-prf` sketch in §3; rotation in §3 and §4).
  * ADR 0002 (envelope v2: the `password` and `recovery` slots, rewrap versus rotation).
* **Requested by:** FlareX (2026-11-14), high priority. Retyping a strong master password on every page load is not workable: people will pick weak passwords instead. The master password should be strong, rarely used and kept offline or in a separate document. Daily unlock should be biometric where possible, with an optional user-chosen short PIN.

## 1. Context

**Today (M4, experimental):**
* A password vault keeps its DEK only in WASM memory.
* Every reload, every new tab and every Lock press needs the master password. Each unlock then runs Argon2id (64 MiB, t=3, p=1), measured at about 1.1 s in desktop Chromium on the development Raspberry Pi; phones are unmeasured.
* There is no idle or background lock. An open tab stays unlocked until the user locks it, reloads or closes it.

FlareX's requirement is right about usability. The goal is to type the strong master password **rarely**: on a new device, after a long absence, and for sensitive operations. It is not to make the master password weaker or optional.

## 2. Constraints taken as facts (primary sources, §10)

1. **WebAuthn exists only in secure contexts** [MDN-WA].
   * The current plain-HTTP LAN/VPN previews cannot offer it.
   * Quick unlock therefore depends on the trusted-HTTPS gate C in `docs/DELIVERY.md`. Loopback is enough for development.
2. **A WebAuthn assertion is a signature, not a key.** Authentication alone gives Keymesh nothing to derive a KEK from. Only the `prf` extension yields secret material [WA3 §10.1.4].
3. **PRF is optional and may not be available.**
   * Registration returns `enabled: false` when the authenticator lacks support. Some authenticators evaluate PRF only during assertions, not at creation [WA3 §10.1.4; MDN-EXT].
   * An assertion without support returns an empty `prf` output [MDN-EXT].
4. **`getClientCapabilities()` is a hint, not a guarantee.**
   * A missing key means unknown, not unsupported [MDN-GCC]. The extension key format is `extension:<id>`.
   * Even when the client supports an extension, a particular authenticator may not [MDN-GCC].
5. **PRF behaviour:**
   * Outputs are 32 bytes [WA3 §10.1.4].
   * The client hashes each input as `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`, so a web origin cannot evaluate the platform's raw `hmac-secret` [WA3 §10.1.4].
   * When built on `hmac-secret`, the exposed PRF is the one bound to user verification, and the spec overrides the requested `userVerification` if necessary [WA3 §10.1.4].
   * The PRF is associated with the credential for the credential's lifetime [WA3 §10.1.4].
6. **"User verification" is not necessarily biometric.**
   * It may be "a biometric gesture … the device PIN, or … the device password" [PK-TERMS]. The spec treats a PIN as a knowledge factor [WA3 §6.2.3].
   * Requiring UV fails with `ConstraintError` if the authenticator cannot perform it [WA3 §6.3.2].
   * User-facing copy must say "your device's unlock (fingerprint, face, or device PIN/password)", never "biometrics" alone.
7. **Passkeys may be synced.**
   * Synced passkeys are copied by a provider across the user's devices; device-bound passkeys "cannot leave the device" [PK-TERMS].
   * The BE flag (backup eligible) is fixed at creation. BS (backed up) may change over time [WA3 §6.1.3].
   * Because the PRF belongs to the credential, a synced passkey's PRF follows the passkey to every device of that provider account. That account then becomes part of the vault's unlock surface.
8. **A browser-side non-extractable CryptoKey is not a hardware guarantee.** The Web Crypto API:
   * "places no normative requirements on implementations as to how the underlying cryptographic key material is stored";
   * "does not guarantee that the underlying cryptographic key material will not be persisted to disk";
   * and says "any application or user that has access to the device storage may be able to recover the key material" [WC §6.2].
   * `extractable: false` only stops `exportKey`/`wrapKey` from script [MDN-CK].
9. **Pages cannot rely on unload.** `visibilitychange` to hidden "is the last event that's reliably observable by the page" [MDN-VIS].
   * WebAuthn calls are cancelled if the window loses focus while pending [MDN-WA].
10. **Browser support:**
    * The PRF extension shipped in Chromium (Intent to Ship, 2023) [CR-I2S] and in Safari 18.0 [SAF18].
    * A Safari cross-device (QR/hybrid) PRF gap has been reported by developers [APPLE-FORUM]. That report is not a primary statement of design, and it is why runtime detection is mandatory.
    * Firefox support was not verified from a primary source for this ADR.

## 3. Options considered

| Option | Daily cost | Protects against someone who copies the vault file or backup | Protects against someone who copies the whole browser profile | Verdict |
|---|---|---|---|---|
| A. Master password every time (status quo) | high (typing + ~1 s KDF) | yes (Argon2id) | yes (Argon2id) | Keep as a fallback; insufficient alone (usability) |
| B. Keep the DEK in `sessionStorage` / IndexedDB to "remember" | none | **no** | **no** | **Rejected.** Plaintext auto-unlock key beside ciphertext (CLAUDE.md) |
| C. `webauthn-prf` slot | one gesture | yes (needs the authenticator plus UV) | yes, for device-bound credentials. For synced credentials, protected only as well as the provider account | **Proposed primary quick unlock** |
| D. Short PIN as its own Argon2id slot | low | **no**: about 10⁶ guesses for 6 digits is feasible offline | **no** | **Rejected** |
| E. Short PIN + non-extractable WebCrypto key in IndexedDB + local attempt counter | low | yes, if only the vault file or backup is copied | **no**: the key material may be on disk [WC §6.2], and a copied profile resets the counter. Rollback cannot be detected locally | **Not in the first implementation.** Product choice in §8 |
| F. Native app: OS keystore or secure hardware (Secure Enclave, TPM, Android Keystore) with hardware attempt limits | one gesture or PIN | yes | depends on the platform's hardware binding; must be verified per platform | Future native track; out of scope for the web app |
| G. External hardware adapter (FlareX's ESP32 devices) | depends | depends on the device | depends on the device | Future adapter (§6); never a prerequisite for recovery |

Option E is the "PIN + non-extractable key + attempt limit" idea from the 2026-11-14 discussion. **It is not universally secure.** It protects against someone who copies only the vault file or a backup. It does **not** protect against someone who copies the browser profile (rollback of the counter, key material possibly on disk). It must never be presented as equivalent to a hardware-enforced PIN.

A user who wants a PIN can already get a **hardware- or OS-enforced** PIN through option C: many platform authenticators and security keys accept the device PIN as user verification (constraint 6).

## 4. Proposed decision

### 4.1 `webauthn-prf` slot (Stage 2 of ADR 0001)

**Slot**
```
kind   = "webauthn-prf"
params = { credential_id, rp_id, salt (32 random bytes), be (bool at enrolment), transports?, label }
KEK    = HKDF-SHA256(ikm = prf_output(salt), salt = none,
                     info = "keymesh webauthn-prf v1" ‖ vault_id ‖ slot_id ‖ credential_id)
```
* The slot wraps the existing DEK with XChaCha20-Poly1305.
* The AAD binds the slot exactly like ADR 0002, through `slot.id`, `kind` and canonical `params`.
* The manifest digest covers the slot list.
* The salt is per slot and random, so two vaults on one passkey get unrelated KEKs. It is not secret: the authenticator holds the secret.

**Enrolment**
1. The vault is unlocked, and the user re-enters the master password. Enrolment is a sensitive operation (§4.4).
2. Pre-check with `PublicKeyCredential.getClientCapabilities()`:
   * `extension:prf === false` → do not offer quick unlock, and say why;
   * `true` or absent → continue, because absent means unknown [MDN-GCC].
3. Call `navigator.credentials.create()`:
   * `authenticatorSelection.userVerification: "required"` and `residentKey: "preferred"`;
   * `extensions.prf.eval.first = salt`.
4. If `prf.enabled !== true` → stop, store nothing, and report "this authenticator cannot unlock vaults".
5. If no `results` came back at creation (allowed by the spec), immediately run `get()` with `allowCredentials = [that id]` and `evalByCredential`.
6. If there is still no 32-byte `results.first` → stop, store nothing, and suggest deleting the orphan passkey.
7. Derive the KEK, wrap the DEK, then verify by unwrapping the new slot in memory.
8. Write once with the existing exact-byte CAS. Lock or cancel at any step before the write leaves nothing behind.

**Unlock**
* Call `get()` with `userVerification: "required"`, `allowCredentials` listing this vault's PRF slots, and `evalByCredential` per credential.
* Use the returned `rawId` to pick the slot. Fail closed on missing results, a UV flag not set, an unknown credential or an unwrap failure.
* The user can always fall back to the master password or the recovery code. A failure never downgrades silently to "remembered" access.

**Synced versus device-bound.** Record BE at enrolment and show it:
* **Device-bound (BE = 0):** "Unlocks on this device only."
* **Synced (BE = 1):** "Unlocks on every device where this passkey syncs (your <provider> account). Anyone who controls that account and can pass its device unlock can open this vault if they also have the vault data."

Whether synced passkeys are allowed at all is a product decision (§8, D1). The proposal allows both, with this disclosure.

**What it does not do.** It does not authenticate the user to any server; Keymesh has no login. It does not prove a person is present beyond what the authenticator's UV asserts. It does not replace the recovery code.

### 4.2 Auto-lock and lifecycle

**Locking rules (browser and CLI session equivalents):**
* **Reload, close or navigation** always ends the session, because the DEK lives only in page memory. Quick unlock makes this cheap; it is not changed.
* **Idle timeout:**
  * default 5 minutes without input, configurable from 1 to 60 minutes, or "never" with a warning;
  * input events only, never network timers;
  * stored in the vault's local preferences, not inside the ciphertext.
* **On hide:**
  * `visibilitychange` → hidden starts a short grace timer, default 30 seconds, configurable, with "immediately" available;
  * expiry locks;
  * coming back before expiry cancels the timer;
  * on mobile, consider defaulting to immediately.

**What locking does:**
* Drops the DEK and all decrypted items: Rust zeroizes its buffers, and JS references are cleared.
* Clears any revealed-secret state in the UI.
* Bumps the session epoch.
* Every async continuation already checks the epoch after each await: the KDF worker, IndexedDB reads and writes, the CAS and restore. A WebAuthn call is aborted with an `AbortController`; its late result is discarded after the epoch check.
* A write that has not committed fails as "locked". One that has committed stays committed (existing M4 semantics).

**What it does not promise.** JavaScript strings, DOM text, browser caches and copies the engine made inside WASM linear memory cannot be proven erased. Locking removes the app's references and zeroizes what Rust owns. It does not guarantee that every in-memory copy is gone [WC §6.2 notes the same for key material]. The UI must not claim otherwise.

### 4.3 Master-password custody (FlareX decision)

* **Offer to generate the master password at creation.** Show it once, with a "print emergency sheet" action. A user-chosen password stays allowed, subject to the ADR 0002 rules.
* **Format of the generated password:**
  * Prefer a passphrase from a reviewed, versioned wordlist, which is easier to transcribe. That needs the wordlist work in the roadmap.
  * Until then, use a random-character password of at least 120 bits from the existing generator.
* **Emergency sheet (printable, local, never uploaded):** vault id, the generated password, instructions, and a reminder to store the recovery code **separately**. The recovery code goes on its own sheet. Two independent slots in different places means losing one does not lose the vault, and stealing one does not open it.
* **Encourage at least two quick-unlock authenticators** (for example phone and laptop), so the offline password is rarely needed.

### 4.4 Sensitive operations still need the master password

These operations need the master password even when a quick unlock is active:
* changing the password;
* a new recovery code;
* enrolling or removing a quick-unlock slot;
* exporting, or downloading a backup;
* DEK rotation.

A recovery-code path remains for each of them where ADR 0002 already allows it.

### 4.5 Device loss, revocation and rotation

* **Removing a PRF slot** needs an unlocked vault. Removal deletes the slot entry, but copies made earlier (backups, another browser profile) still carry it.
* **Lost or stolen authenticator, or a compromised sync account:** remove the slot, and also run a **DEK rotation**:
  * Rewrap is insufficient, because the old slot still opens old copies.
  * Rotation follows ADR 0001 §3 staging. Every surviving PRF slot needs a fresh PRF evaluation by its own authenticator, or it is invalidated, never silently kept.
* **Deleting the passkey at the provider** leaves a stale slot. Unlock fails closed, and the UI offers to remove it.
* **Rotation never revokes copies an attacker already holds.** It protects revisions written afterwards. Stored site credentials that may have been seen must be changed at those sites.

## 5. Capability test required before implementation

A small, separate synthetic test page (loopback, or the approved HTTPS origin once gate C is decided) records for each target the following:
* the `getClientCapabilities()` result;
* `create()` `prf.enabled` and whether results come at creation;
* whether `get()` returns 32-byte results;
* the UV flag and the BE/BS flags;
* behaviour after a reload;
* the cross-device (QR/hybrid) path.

**Targets:**
1. Chromium desktop with Google Password Manager passkeys.
2. Chromium with a USB security key that supports `hmac-secret`, if FlareX has one.
3. Safari on macOS with iCloud Keychain.
4. Android Chrome.
5. iOS Safari.

Automated coverage uses Chromium's DevTools-protocol virtual authenticator with PRF enabled, in the existing Playwright suite. This verifies Keymesh's handling, not any real authenticator.

**Exit criterion:** at least one device-bound and one synced path behave as specified on real devices, and the measured results are recorded in this ADR before the implementation task is accepted.

## 6. ESP32 and other adapters (future, not prerequisites)

FlareX's devices:
* **HID password typer:** can hold the offline master password.
  * Risks: it types into whatever window has focus, with no origin binding, and keyloggers see the keystrokes.
  * Requirements: an on-device PIN and the chip's flash encryption and secure boot.
* **Simulated HSM:** could hold Ed25519 signing keys, or become a FIDO2/CTAP2 authenticator with `hmac-secret`.
  * As a FIDO2 authenticator, it would plug into §4.1 with no Keymesh-specific protocol.
  * The chip model and firmware must be reviewed first.

Neither replaces the recovery code, and the vault must stay fully recoverable without them.

## 7. Consequences

* **Daily use:** one device-unlock gesture instead of a long password.
* **Shared envelope:** the envelope gains an optional slot kind. v2 readers that don't know it must keep refusing unknown kinds, as ADR 0002 does today. Adding the kind is a format revision, reviewed with test vectors.
* **Dependency on gate C:** quick unlock depends on trusted HTTPS for any non-loopback use.
* **Synced passkeys** extend trust to the passkey provider's account recovery. The user must be told.

## 8. Decisions still needed (human / product)

| # | Decision | Proposal |
|---|---|---|
| D1 | Allow synced passkeys for PRF slots? | Allow, with the §4.1 disclosure; a setting may restrict to device-bound |
| D2 | Offer option E (browser PIN) at all? | **Not in the first implementation**: the device PIN via WebAuthn covers most cases with OS/hardware limits. Revisit for the native app |
| D3 | Default idle and hide timeouts | 5 min idle, 30 s hidden (desktop); immediate on hide for mobile |
| D4 | Trusted HTTPS approach (gate C) | See `docs/DELIVERY.md` §4; needed before any non-loopback quick unlock |

## 9. Proposed next implementation contract (after this ADR is reviewed)

1. Capability test page and recorded results (§5). No vault changes.
2. Envelope: `webauthn-prf` slot kind, with test vectors, native and WASM parsing, and bounds.
3. Browser: enrolment, unlock, removal, auto-lock (idle and hide), lifecycle cancellation tests, and a Playwright virtual authenticator.
4. Generated master password, emergency sheet and copy.
5. Then DEK rotation (roadmap item) reusing the same slot re-establishment logic.

## 10. Sources (primary unless stated, accessed 2026-11-14)

* [WA3] W3C, *Web Authentication Level 3*, Recommendation 2026-08-25: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
  * §10.1.4 `prf`: `#prf-extension`
  * §6.1.3 backup flags: `#sctn-credential-backup`
  * §6.2.3 authentication factor capability: `#sctn-authentication-factor-capability`
  * §6.3.2 user verification: `#sctn-op-make-cred`
* [MDN-EXT] MDN, *WebAuthn extensions* (`prf`): https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions#prf
* [MDN-GCC] MDN, `PublicKeyCredential.getClientCapabilities()`: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/getClientCapabilities_static
* [MDN-WA] MDN, *Web Authentication API*: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
* [PK-TERMS] passkeys.dev (FIDO Alliance and W3C community reference), *Terms*: https://passkeys.dev/docs/reference/terms/
* [WC] W3C, *Web Cryptography API* (Editor's Draft), §6.2 Security considerations for authors: https://w3c.github.io/webcrypto/#security-developers ; §5.2 Key storage: `#concepts-key-storage`
* [MDN-CK] MDN, `CryptoKey.extractable`: https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable
* [MDN-VIS] MDN, `visibilitychange`: https://developer.mozilla.org/en-US/docs/Web/API/Document/visibilitychange_event
* [CR-I2S] Chromium blink-dev, *Intent to Ship: WebAuthn PRF extension*: https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI ; status entry https://chromestatus.com/feature/5138422207348736
* [SAF18] Apple, *Safari 18 Release Notes* (Authentication: WebAuthn PRF extension): https://developer.apple.com/documentation/safari-release-notes/safari-18-release-notes
* [APPLE-FORUM] (developer report, not primary) *PRF Extension Not Supported in Safari's Cross-Device WebAuthn Flow*: https://developer.apple.com/forums/thread/774112
* web.dev, *Simpler WebAuthn feature detection* (browser versions for `getClientCapabilities`): https://web.dev/articles/webauthn-client-capabilities
