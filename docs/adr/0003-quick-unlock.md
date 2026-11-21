# ADR 0003: Quick unlock, auto-lock and master-password custody

* **Status:** **Proposed. Nothing in this ADR is implemented.** It needs independent review and a scoped task before any code. It does not authorize real-secret entry, Keymesh login, external network calls or trust changes.
  * Any capability study or prototype built from it stays **synthetic-data only and experimental** until a compromise-response (DEK rotation) policy is approved (§4.5, D5).
  * The product decisions in §8 (synced passkeys, browser PIN, lifecycle defaults, HTTPS trust, interim rotation gate) are open. This document proposes; it records no approval.
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
   * The method itself may be absent in older browsers; MDN's own example feature-detects it before calling [MDN-GCC]. Keymesh treats an absent method, a rejected call and an absent key all as **unknown**.
   * Even when the client supports an extension, a particular authenticator may not [MDN-GCC]. Only the actual `create()`/`get()` results decide (§4.1).
5. **PRF behaviour:**
   * Outputs are 32 bytes [WA3 §10.1.4].
   * The client hashes each input as `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`, so a web origin cannot evaluate the platform's raw `hmac-secret` [WA3 §10.1.4].
   * When built on `hmac-secret`, the exposed PRF is the one bound to user verification, and the spec overrides the requested `userVerification` if necessary [WA3 §10.1.4].
   * The PRF is associated with the credential for the credential's lifetime [WA3 §10.1.4].
6. **"User verification" is not necessarily biometric.**
   * It may be "a biometric gesture … the device PIN, or … the device password" [PK-TERMS]. The spec treats a PIN as a knowledge factor [WA3 §6.2.3].
   * Requiring UV fails with `ConstraintError` if the authenticator cannot perform it [WA3 §6.3.2].
   * User-facing copy must say "your device's unlock (fingerprint, face, or device PIN/password)", never "biometrics" alone.
7. **Passkeys may be synced; the flags say less than they seem.**
   * Synced passkeys are copied by a provider across the user's devices. A device-bound passkey is bound to **one authenticator** [PK-TERMS], and that authenticator may be a roaming security key that works from any client it is plugged into [WA3 §1.2.2].
   * BE (backup eligible) is fixed at creation and means the credential is **allowed** to be backed up. BS (backed up) says whether it is backed up **now**, and may change [WA3 §6.1.3].
   * Neither flag names the provider, proves where or how the key is stored, or attests attempt limiting or hardware isolation. Those need attestation or measurement, which this design does not rely on.
   * The PRF belongs to the credential for its lifetime [WA3 §10.1.4]. A backed-up credential may therefore be usable to unlock wherever its provider makes it available, and that account's recovery becomes part of the unlock surface. Whether PRF actually works on each such device or cross-device (hybrid) path is not implied by the flags; it is measured (§5).
8. **A browser-side non-extractable CryptoKey is not a hardware guarantee.** The Web Crypto API:
   * "places no normative requirements on implementations as to how the underlying cryptographic key material is stored";
   * "does not guarantee that the underlying cryptographic key material will not be persisted to disk";
   * and says "any application or user that has access to the device storage may be able to recover the key material" [WC §6.2].
   * `extractable: false` only stops `exportKey`/`wrapKey` from script [MDN-CK].
9. **Pages cannot rely on unload, and hidden pages may stop running.**
   * `visibilitychange` to hidden "is the last event that's reliably observable by the page" [MDN-VIS].
   * A hidden page may be **frozen**: the browser "suspends execution of freezable tasks … This means things like JavaScript timers and fetch callbacks don't run", and a frozen page may be discarded without further events [CR-LC].
   * Pages in the back/forward cache likewise have pending timers and promises paused, resumed only if the page is restored [WD-BFC]. A restore fires `pageshow` with `persisted = true` [MDN-PS].
   * So a timer started on hide is **not** guaranteed to fire at its deadline. It may fire late, on resume, or never.
   * WebAuthn calls are cancelled if the window loses focus while pending [MDN-WA].
10. **Browser support:**
    * Chromium published an *Intent to Ship* for the PRF extension in April 2023 [CR-I2S]. That is evidence of intent, not of a shipping version; the shipping version was **not** verified from an inspectable official source for this ADR.
    * Safari 18 release notes list "Added support for the WebAuthn PRF extension" [SAF18]. That does not prove every credential type or the hybrid path works.
    * A Safari cross-device (QR/hybrid) PRF gap has been reported by developers [APPLE-FORUM]. That report is not a primary statement of design, and it is why runtime detection is mandatory.
    * Firefox support was not verified from a primary source for this ADR.

## 3. Options considered

| Option | Daily cost | Protects against someone who copies the vault file or backup | Protects against someone who copies the whole browser profile | Verdict |
|---|---|---|---|---|
| A. Master password every time (status quo) | high (typing + ~1 s KDF) | yes (Argon2id) | yes (Argon2id) | Keep as a fallback; insufficient alone (usability) |
| B. Keep the DEK in `sessionStorage` / IndexedDB to "remember" | none | **no** | **no** | **Rejected.** Plaintext auto-unlock key beside ciphertext (CLAUDE.md) |
| C. `webauthn-prf` slot | one gesture | yes (needs the authenticator plus UV) | **depends on the authenticator, not the flags.** A profile copy alone should not carry a security key's or OS authenticator's secret, but this is per authenticator and unverified here. A backed-up credential is protected only as well as the provider account | **Proposed primary quick unlock** (experimental until D5) |
| D. Short PIN as its own Argon2id slot | low | **no**: about 10⁶ guesses for 6 digits is feasible offline | **no** | **Rejected** |
| E. Short PIN + non-extractable WebCrypto key in IndexedDB + local attempt counter | low | yes, if only the vault file or backup is copied | **no**: the key material may be on disk [WC §6.2], and a copied profile resets the counter. Rollback cannot be detected locally | **Not in the first implementation.** Product choice in §8 |
| F. Native app: OS keystore or secure hardware (Secure Enclave, TPM, Android Keystore) with hardware attempt limits | one gesture or PIN | yes | depends on the platform's hardware binding; must be verified per platform | Future native track; out of scope for the web app |
| G. External hardware adapter (FlareX's ESP32 devices) | depends | depends on the device | depends on the device | Future adapter (§6); never a prerequisite for recovery |

Option E is the "PIN + non-extractable key + attempt limit" idea from the 2026-11-14 discussion. **It is not universally secure.** It protects against someone who copies only the vault file or a backup. It does **not** protect against someone who copies the browser profile (rollback of the counter, key material possibly on disk). It must never be presented as equivalent to a hardware-enforced PIN.

A user who wants a PIN can often use one through option C: many platform authenticators and security keys accept a device PIN as user verification (constraint 6). The PIN is then checked by the authenticator or OS, not by Keymesh. **How well it resists guessing (attempt limits, hardware isolation) depends on that authenticator** and is not proven by the UV or BE flags; Keymesh does not claim it.

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
2. Pre-check, as a hint only:
   * `PublicKeyCredential.getClientCapabilities` absent, the call rejected, or the `extension:prf` key absent → **unknown**: continue to step 3 and let the real results decide [MDN-GCC];
   * `extension:prf === false` → do not offer quick unlock, and say why;
   * `true` → continue.
3. Call `navigator.credentials.create()`:
   * `authenticatorSelection.userVerification: "required"` and `residentKey: "preferred"`;
   * `extensions.prf.eval.first = salt`.
4. If `prf.enabled !== true` → stop before any write, and report "this authenticator cannot unlock vaults".
5. If no `results` came back at creation (allowed by the spec), immediately run `get()` with `allowCredentials = [that id]` and `evalByCredential`.
6. If there is still no 32-byte `results.first` → stop before any write.
7. Derive the KEK, wrap the DEK, then verify by unwrapping the new slot in memory.
8. Write once with the existing exact-byte CAS. Its **last cancellable point is the guard just before IndexedDB `put`** (`vault-store.ts`); once `put` is issued the write can complete even if the vault is locked meanwhile (§4.2).

**Failure after `create()` succeeded.** Any failure from step 4 on happens **after the authenticator has already made a credential**, which Keymesh cannot delete from an authenticator or provider. In every case the in-memory KEK and PRF output are zeroed, and a lock drops all decrypted state. What happened to the **vault** depends on where the failure happened, so the outcomes are not all called "orphans":
* **Confirmed before the write** (steps 4–7, a CAS conflict, or a lock or cancel caught by the guard before `put`): this operation wrote no slot. A conflict means another writer changed storage, not that the vault stayed globally unchanged; this operation's slot is simply absent. The credential is an **orphan**:
  * the UI names it (user name, display name and creation time chosen by Keymesh, so it is recognisable) and tells the user how to delete it in their authenticator or provider settings;
  * where the client implements it, Keymesh may also call `PublicKeyCredential.signalUnknownCredential()` for that id [WA3 §5.1.10.2]. This is a best-effort hint; the client and authenticator decide what to do, so the manual instruction stays.
* **Committed or uncertain** (the write was submitted: `put` issued, then a lock, expiry or stale epoch, or an error whose outcome is unknown): the slot **may be stored**. Keymesh never reinstalls an unlocked session from that late result. At the next unlock (by any method) it first **reconciles**: it reads the stored slot list and checks whether a slot for that credential id exists.
  * **Slot present:** enrolment did take effect. The UI says so, and offers to keep it or to remove it as a normal slot removal (unlocked vault, master password). No `signalUnknownCredential()` is sent while a slot still refers to the credential.
  * **Slot absent:** it is treated as an orphan, as above.
* **Tests:** each failure point, including lock during the follow-up `get()`, a lock before `put` (no slot, orphan message), and a lock after `put` (slot reconciled on the next unlock, never reported as an orphan, no secret shown before that unlock).

**Unlock**
* Call `get()` with `userVerification: "required"`, `allowCredentials` listing this vault's PRF slots, and `evalByCredential` per credential.
* Use the returned `rawId` to pick the slot. Fail closed on missing results, a UV flag not set, an unknown credential or an unwrap failure.
* The user can always fall back to the master password or the recovery code. A failure never downgrades silently to "remembered" access.

**Backup-eligible versus not.** Record BE (and BS as observed) at enrolment and show what the flags actually mean (constraint 7):
* **BE = 0:** "This passkey is bound to the authenticator that made it. If that is a security key, it can unlock this vault from any computer it is plugged into."
* **BE = 1:** "This passkey may be backed up and made available on other devices by its provider. Anyone who controls that provider account and can pass its device unlock may be able to open this vault if they also have the vault data."
* The provider is named only when it is reliably known (for example the user picked it); flags never identify it. The copy never promises that the passkey **will** work on another device; that depends on the client, provider and transport (§5).

Whether backup-eligible passkeys are allowed at all is a product decision (§8, D1). The proposal allows both, with this disclosure.

**What it does not do.** It does not authenticate the user to any server; Keymesh has no login. It does not prove a person is present beyond what the authenticator's UV asserts. It does not replace the recovery code.

### 4.2 Auto-lock and lifecycle

**What ends a session.**
* **Document destruction** (reload, closing the tab, navigating the tab to another document, or the browser discarding a frozen page) ends it, because the DEK lives only in that document's memory.
* **Same-document navigation does not.** Moving between Keymesh's own routes (the Angular router, `history.pushState`) keeps the same document and the same unlocked session. Only the lock rules below end it.
* **Back/forward cache.** A document left by navigation may be kept alive in the bfcache and restored later with its memory intact [WD-BFC]. So leaving the page is **not** enough on its own: `pagehide` always locks (proposal), and a `pageshow` with `persisted = true` re-runs the freshness check before anything renders.

**Deadlines, not timers.** Timers may not run while a page is hidden, frozen or in the bfcache (constraint 9). The rules are therefore stated as **deadlines that are checked**, with timers only as a best-effort trigger:
* **Idle deadline:** `lastInput + idleLimit`. Default 5 minutes without input, configurable from 1 to 60 minutes, or "never" with a warning. Input events only, never network activity. Stored in the vault's local preferences, not inside the ciphertext.
  * **Input cannot revive an expired session.** Each input event runs the freshness check **before** it updates `lastInput`. If the idle (or hidden) deadline has already passed, that input locks instead of extending the session.
* **Hidden deadline:** `hiddenAt + hideGrace`, set on `visibilitychange` → hidden. Default 30 seconds, configurable, with "immediately" available (proposed default on mobile).
  * **Cleared only after a passing check.** On return (`visibilitychange` → visible, `resume`, `pageshow`), the freshness check runs **first**. If the deadline has passed, the vault locks. Only if it has not passed is the hidden deadline cleared. The next hide sets a new one from its own `hiddenAt`, so a short hide never causes a lock later while the user is active.
* **"Immediately" is enforced synchronously** in the `visibilitychange` handler, which runs before the page can be frozen. This is the only setting that does not depend on later execution.
* **Freshness check before secret access.** One synchronous check, `sessionFresh()`, compares now with both deadlines and locks first if either has passed. It runs:
  * on `visibilitychange` → visible, `resume`, `pageshow` (including `persisted = true`) and `focus`;
  * when a timer fires;
  * **before every protected operation**: rendering decrypted items or fields, reveal, copy, edit, save, export or backup, and before using the result of any async step that started before the check.
* **What is honestly promised:** when the page comes back after a deadline, it is locked **before any secret is shown or used**. It is not promised that the lock ran at the exact deadline while the page was hidden or frozen: during that time decrypted data may still be in the suspended page's memory.
* **Clock policy:** deadlines use both a monotonic clock (`performance.now()`) and wall-clock time (`Date.now()`); the session is expired if **either** says the limit has passed. A wall clock that moved backwards by more than a small tolerance also counts as expired (fail closed). Whether the monotonic clock advances during system sleep differs between platforms, so neither clock alone is trusted.

**What locking does:**
* Drops the DEK and all decrypted items: Rust zeroizes its buffers, and JS references are cleared.
* Clears any revealed-secret state in the UI.
* Bumps the session epoch.
* Every async continuation already checks the epoch after each await: the KDF worker, IndexedDB reads and writes, the CAS and restore. A WebAuthn call is aborted with an `AbortController`; its late result is discarded after the epoch check.
* **Decrypted state is always dropped**, whatever stage any operation was in. Locking never keeps an unlocked session to let an operation finish.
* **Writes, by stage (existing M4 boundary):**
  * **Stopped before the last cancellable point** (the guard just before IndexedDB `put`; natively, before the rename): the write is abandoned and storage keeps its previous contents.
  * **Already submitted** (`put` issued; natively, the rename done): the ciphertext write may still complete, and is not rolled back. The operation reports stale or locked, but storage may hold the new envelope. Keymesh **reconciles** against what is stored at the next unlock or read, and never re-unlocks or renders secrets from the late result.

**What it does not promise.** JavaScript strings, DOM text, browser caches and copies the engine made inside WASM linear memory cannot be proven erased. Locking removes the app's references and zeroizes what Rust owns. It does not guarantee that every in-memory copy is gone [WC §6.2 notes the same for key material]. The UI must not claim otherwise.

**Future acceptance cases for the lifecycle** (proposed; nothing here is implemented now). The tests drive an injected clock and dispatch lifecycle events directly, so they do not depend on real timers firing:
1. **Elapsed deadline, timer never fired:** hide, advance both clocks past the grace period without running timers, return to visible. The vault is locked before any item renders, and no decrypted value reaches the DOM.
2. **Suspended resume:** the same through `freeze`/`resume` (Chromium's DevTools `Page.setWebLifecycleState` can freeze a real page) and through `pageshow` with `persisted = true`.
3. **Protected operation after expiry:** reveal, copy, edit, save and export each lock and refuse when called past a deadline, even if no lifecycle event arrived.
4. **Clock changes:** wall clock moved forward past the limit → locked; wall clock moved backwards beyond tolerance → locked; monotonic clock past the limit with an unchanged wall clock → locked.
5. **Stale async work:** a KDF, IndexedDB read or WebAuthn result that completes after an expiry lock is dropped by the epoch check: never rendered, and never the start of a new write. A write stopped before `put` leaves storage as it was. A write already submitted may commit: the test asserts that the vault stays locked, that no secret is shown, and that the next unlock reconciles to whichever envelope is stored.
6. **"Immediately" on hide:** locked synchronously inside the `visibilitychange` handler.
7. **Same-document navigation:** route changes inside the app keep the session; `pagehide` locks.
8. **Early return and re-hide:** hide, return after 5 s (before the 30 s grace), stay active. No lock at the original 30 s mark. Hide again: a new deadline counts from the second hide.
9. **First input after expiry:** advance past the idle deadline without timers firing, then send one input event. The vault locks and the input does not extend the session.

### 4.3 Master-password custody (FlareX decision)

* **Offer to generate the master password at creation.** Show it once, with a "print emergency sheet" action. A user-chosen password stays allowed, subject to the ADR 0002 rules.
* **Format of the generated password:**
  * Prefer a passphrase from a reviewed, versioned wordlist, which is easier to transcribe. That needs the wordlist work in the roadmap.
  * Until then, use a random-character password of at least 120 bits from the existing generator.
* **Emergency sheet (generated locally, never uploaded):** vault id, the generated password, instructions, and a reminder to store the recovery code **separately**. The recovery code goes on its own sheet.
* **What separate custody does and does not do.** The master password and the recovery code each unwrap the same DEK on their own (ADR 0002 §4). So:
  * **Either sheet plus a copy of the vault data opens the vault.** Stealing one sheet is enough for someone who also has, or later gets, the ciphertext (a backup file, a copied profile). This is **not** two-factor or threshold custody. Each sheet must be protected as if it were the whole vault.
  * Keeping them apart reduces the chance of **losing both at once** (fire, one lost bag) and means one theft does not expose both. That is its whole benefit.
  * **The recovery code is useless without the ciphertext.** Recovery needs an encrypted backup (ADR 0001 §4): the sheet must tell the user to keep an up-to-date encrypted backup somewhere other than the browser.
* **Printing leaves copies Keymesh cannot erase.** Print spoolers, "print to PDF" files, printer memory and the browser's print preview are outside the app. The UI says so and suggests writing the sheet by hand or printing to a local printer the user controls; it never claims the sheet exists only on paper.
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
* **Lost or stolen authenticator, or a compromised sync account:** removing the slot is not enough, because any copy made earlier still has it. The complete response is a **DEK rotation**, but **rotation does not exist today**: `Vault::rotate_data_key` refuses v2 vaults (ADR 0002 §8). Until it does:
  * the UI must **not** offer or mention rotation as an available action;
  * it says plainly that removing the slot protects only future copies of this vault, and that copies already taken stay openable with that authenticator;
  * it advises changing the site credentials stored in the vault.
  * This gap is why quick unlock stays **experimental and synthetic-data only** until a compromise-response policy is approved (D5): either rotation lands first, or a bounded interim release is approved that states it has no revocation.
* **When rotation exists** (roadmap item 2): it follows ADR 0001 §3 staging. Every surviving PRF slot needs a fresh PRF evaluation by its own authenticator, or it is invalidated, never silently kept. Rewrap alone is insufficient, because the old slot still opens old copies.
* **Deleting the passkey at the provider** leaves a stale slot. Unlock fails closed, and the UI offers to remove it.
* **Rotation never revokes copies an attacker already holds.** It protects revisions written afterwards. Stored site credentials that may have been seen must be changed at those sites.

## 5. Capability test required before implementation

A small, separate **synthetic, experimental** test page (loopback, or the approved HTTPS origin once gate C is decided) records for each target the following. It never touches a vault or real data.
* the actual authenticator (make and kind: platform, security key, phone over hybrid) and the transport used;
* whether `getClientCapabilities` exists, and its result;
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

**Exit criterion:** at least one BE = 0 and one backup-eligible path behave as specified on real devices, and the measured results (authenticator, transport, client version, flags, PRF results) are recorded in this ADR before the implementation task is accepted. These recorded results, not the flags or browser announcements, are the preconditions for offering quick unlock on a given platform.

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
* **Backup-eligible passkeys** extend trust to the passkey provider's account recovery. The user must be told.
* **No revocation until rotation exists** (§4.5): a lost authenticator's slot keeps opening copies made earlier.

## 8. Decisions still needed (human / product)

| # | Decision | Proposal |
|---|---|---|
| D1 | Allow backup-eligible (BE = 1) passkeys for PRF slots? | Allow, with the §4.1 disclosure; a setting may restrict to BE = 0 |
| D2 | Offer option E (browser PIN) at all? | **Not in the first implementation.** A device PIN used as WebAuthn user verification covers the wish for a short code; its guessing limits depend on the authenticator (§3). Revisit for the native app |
| D3 | Lifecycle defaults and semantics | 5 min idle, 30 s hidden (desktop), immediate on hide for mobile; `pagehide` locks; deadline checks on resume, `pageshow` and before protected operations (§4.2) |
| D4 | Trusted HTTPS approach (gate C) | See `docs/DELIVERY.md` §4; needed before any non-loopback quick unlock |
| D5 | Interim compromise-response gate | Keep quick unlock experimental and synthetic-only until DEK rotation lands, **or** approve a bounded interim release that states it has no revocation. No proposal is assumed approved |

## 9. Proposed next implementation contract (after this ADR is reviewed)

Nothing below is authorized by this ADR. Each step needs its own task contract, and everything stays synthetic-data only and experimental until D5 is decided.

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
  * §1.2.2 single-device credentials on a roaming security key: `#sctn-usecase-workforce-sdc`
  * §5.1.10.2 `signalUnknownCredential()`: `#sctn-signalUnknownCredential`
* [MDN-EXT] MDN, *WebAuthn extensions* (`prf`): https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions#prf
* [MDN-GCC] MDN, `PublicKeyCredential.getClientCapabilities()`: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/getClientCapabilities_static
* [MDN-WA] MDN, *Web Authentication API*: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API
* [PK-TERMS] passkeys.dev (FIDO Alliance and W3C community reference), *Terms*: https://passkeys.dev/docs/reference/terms/
* [WC] W3C, *Web Cryptography API* (Editor's Draft), §6.2 Security considerations for authors: https://w3c.github.io/webcrypto/#security-developers ; §5.2 Key storage: `#concepts-key-storage`
* [MDN-CK] MDN, `CryptoKey.extractable`: https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable
* [MDN-VIS] MDN, `visibilitychange`: https://developer.mozilla.org/en-US/docs/Web/API/Document/visibilitychange_event
* [CR-LC] Chrome for Developers, *Page Lifecycle API* (frozen state suspends freezable tasks, including JavaScript timers): https://developer.chrome.com/docs/web-platform/page-lifecycle-api
* [WD-BFC] web.dev, *Back/forward cache* (pending timers and promises paused while cached): https://web.dev/articles/bfcache
* [MDN-PS] MDN, `pageshow` event (`persisted`): https://developer.mozilla.org/en-US/docs/Web/API/Window/pageshow_event
* [CR-I2S] Chromium blink-dev, *Intent to Ship: WebAuthn PRF extension* (April 2023; intent, not a shipping record): https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI ; status entry https://chromestatus.com/feature/5138422207348736 (renders only with JavaScript; shipping version not verified)
* [SAF18] Apple, *Safari 18 Release Notes* (Authentication: WebAuthn PRF extension): https://developer.apple.com/documentation/safari-release-notes/safari-18-release-notes
* [APPLE-FORUM] (developer report, not primary) *PRF Extension Not Supported in Safari's Cross-Device WebAuthn Flow*: https://developer.apple.com/forums/thread/774112
* web.dev, *Simpler WebAuthn feature detection* (browser versions for `getClientCapabilities`): https://web.dev/articles/webauthn-client-capabilities
