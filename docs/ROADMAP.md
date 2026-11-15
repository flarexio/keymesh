# Keymesh roadmap

**Status as of 2026-11-16.**
* **Authorized rollout (M5):** FlareX authorized implementing the backlog below plus an installable app (PWA), in phases A, B and C (task `keymesh-product-rollout`). Each phase gets an independent review before it is deployed to the private endpoint.
* **Boundaries:** everything stays experimental and synthetic-data only until independent acceptance. Outside this rollout, each item still needs its own task contract.
* **Priorities** follow FlareX's requests from 2026-11-14 and 2026-11-15 unless noted.

## Where things stand

| Milestone | State |
|---|---|
| M1 vault core, CLI, `op` importer (fake-runner tested) | Accepted |
| M2 browser vault (WASM) | Accepted |
| M3 UI polish, locale and theme | Accepted |
| Generator finish | Accepted |
| **M4 local unlock** (password and recovery slots, backup/restore, HTTPS mechanics) | **Partial, not accepted.** A private HTTPS endpoint (`keymesh.cloud`, Docker, internal CA) now runs; **gate C** (a real client device trusting it) is still unverified by the human |
| **M5 product rollout** (PWA + backlog) | **Phase A accepted** (`7079932`) and **Phase B accepted** (`4e65efb`). Both are experimental, synthetic only, and privately deployed to `keymesh.cloud`, A and then B on 2026-11-16. **Phase C is implemented and tested in Chromium, but not reviewed and not deployed.** The C1 format and the C3 architecture passed their design gates; outbound icon fetching is still not approved. See the checklist below |

## M5 checklist (versioned)

**v4.1, 2026-11-16** (A and B deployed; C implemented with independent-review fixes), on branch `feature/m5-pwa-product-features`. The exact commits are listed in the draft PR. "Deployed" for A means the accepted `7079932` web image; B is not deployed and stays off the private endpoint until its independent review.
* **States:** *implemented* · *tested* (automated, Chromium on the Pi) · *deployed* (private `keymesh.cloud` image) · *blocked*.
* **Not covered by "tested":** real phones, Safari and Firefox; iOS install; and real camera hardware. Those need human device checks.

| Phase | Feature | Implemented | Tested | Deployed | Notes |
|---|---|---|---|---|---|
| A | PWA: manifest, icons (incl. maskable), install button/hint | yes | yes | yes | Chromium only. The `beforeinstallprompt` flow and the iOS hint were not verified on real devices |
| A | Offline reopen and unlock after one online visit | yes | yes | yes | Tested with the server stopped. A cold first visit offline is not supported |
| A | Updates offered, never forced; lock before reload | yes | yes | yes | Covers v1→v2, the ephemeral-vault warning and the unrecoverable chunk state. A genuinely failed install degrades offline reopening until a bounded retry succeeds (tested). Damaged cached files: online repair (tested) |
| A | TOTP from QR: image upload and paste | yes | yes | yes | zxing-wasm in a worker, self-hosted. Header bounds checked before decoding |
| A | TOTP from QR: live camera | yes | Chromium fake camera | yes | Real camera hardware is untested |
| A | Circular TOTP countdown (last 5 s warning) | yes | yes | yes | Fixed-clock unit and E2E tests; reduced motion |
| A | Local login icons (brand, private host, category, letter) | yes | yes | yes | 81 reviewed Simple Icons: no per-icon licence (Rust, CC-BY-SA-4.0, removed); explicit domain aliases. No network. Not a security indicator |
| B | Ed25519 Base58 public key, sign and verify | yes | yes | yes | Raw 32-byte Base58 (no prefix/checksum); pure Ed25519 over the exact shown bytes; `verify_strict`. RFC 8032 + Base58 + negative vectors natively, through WASM, and Node/OpenSSL in E2E |
| B | DEK rotation (password + recovery slots) | yes | yes | yes | No wire-format change. Native, CLI, bridge, browser; rotation vector checked by Node/OpenSSL. Browser outcome reconciliation tested with a fake store and, in the production build, with held IndexedDB completion. If the outcome is only known after a lock, a non-secret notice stays on the locked screen (review fix). IndexedDB post-commit durability can't be observed. Design gate approved; code review fixes pending re-review |
| B | Passphrase wordlist and emergency kit | yes | yes | yes | EFF Long Wordlist pinned by SHA-256; core CSPRNG with rejection sampling. Kit never prints the password; code only on request. Real printers/PDF untested |
| C | WebAuthn PRF quick unlock | yes | virtual authenticator only | no | ADR 0003 §4.1.1. Idle deadlines are checked on every async continuation (capability query, KDF, ceremony, before the write). Real-device capability (§5) is not recorded: no TouchID, FaceID, Windows Hello, Android or iOS proof |
| C | Auto-lock (idle, hidden, pagehide, clock) | yes | yes | no | Deadline checks; visibility simulated in tests (no real OS app switch or freeze) |
| C | Custom short PIN | no | n/a | no | **Blocked**: no protected mechanism in the web app (ADR 0003 D2). The device PIN as WebAuthn UV is the supported route; it is not a Keymesh PIN |
| C | Optional favicon route | yes (off) | mock network plus a local TLS production-connector test | no | `KEYMESH_FAVICON` unset in Docker; outbound use is not approved.<br>• **Fixed:** address allowlist; one deadline (monotonic, including DNS); no shared cache, `no-store`; connector works with Node family autoselection.<br>• **Not hard limits:** native DNS jobs can't be cancelled; the PNG decode is synchronous and not preempted |

### Gates shared by several items
* **G-HTTPS (gate C).** A client-trusted HTTPS origin for LAN/VPN use, because the plain-HTTP previews are not secure contexts. It is required for non-loopback password vaults, WebAuthn, the camera and the Clipboard API. The decision is the human's; no CA or certificate is created without approval.
* **G-REVIEW.** Each format or crypto change gets test vectors and an independent review.

## Backlog (ordered)

### 1. Quick unlock and auto-lock — high priority
* **Scope:** design in [ADR 0003](adr/0003-quick-unlock.md); proposed now, not implemented. Any capability study or prototype is **synthetic-data only and experimental** until the interim compromise-response gate (ADR 0003 D5) is decided, because revoking a lost authenticator needs item 2.
  * A `webauthn-prf` slot with fail-closed capability detection.
  * Deadline-based idle and hide auto-lock, checked on resume and before protected operations, with the existing epoch cancellation.
  * A generated master password and printable emergency sheet.
  * Separate custody of the recovery code.
* **Not in scope:** a browser-only PIN slot (ADR 0003 option E, decision D2), plaintext remembered keys, and Keymesh login.
* **Depends on:**
  * review of ADR 0003;
  * the real-device capability test (ADR 0003 §5);
  * G-HTTPS for any non-loopback use;
  * the product decisions D1–D3 and D5 (none is approved by the ADR).
* **Acceptance:**
  * **Format:** test vectors for the new slot kind; unknown kinds are still refused by older readers.
  * **Browser:** the Playwright virtual authenticator covers enrolment, unlock, removal, PRF-unsupported and no-results refusal, UV-missing refusal, abort on lock or hide, and enrolment failures after `create()` split by commit stage: a leftover-credential message when no slot was written, and reconciliation of a possibly committed slot otherwise (ADR 0003 §4.1).
  * **Lock:** deadline-based (ADR 0003 §4.2): elapsed deadline with timers never fired, freeze/resume and bfcache `pageshow`, protected operations after expiry, clock changes, early return and re-hide, first input after expiry, stale async work dropped, and submitted writes reconciled without re-unlocking.
  * **Real devices:** at least one BE = 0 and one backup-eligible path recorded on real devices, with authenticator and transport.
  * **Copy:** never says "biometric" alone; describes BE = 0 as bound to an authenticator (not to this computer) and BE = 1 as backup-eligible (not as synced everywhere); never offers rotation before it exists.

### 2. DEK rotation (re-encrypt the vault) — implemented (M5 phase B), accepted and deployed
* **Implemented:**
  * **Core:** `Vault::begin_rotation` / `finish_rotation` (`src/vault.rs`). A pending rotation is bound to the exact slots its authority was checked against.
  * **Other layers:** `storage::save_protected` (native), `keymesh rotate-key` (CLI), `Session::begin_rotation` / `finish_rotation` (bridge), and `VaultService.beginRotation` / `finishRotation` (browser, with read-back reconciliation and strict durability).
  * **Tests:** `vault::tests::v2_rotation_*`, `storage::tests::*rotation*`, `tests/cli_protected.rs`, `tests/rotation_vectors.rs` and `scripts/check-vectors.mjs`; `core/protected-vault.spec.ts` (data-key rotation) and `e2e/m5b.spec.ts`.
  * **Still open:** the "no recovery path" acknowledgement does not arise yet, because rotation always installs both a new password and a new recovery code.
* **Scope:**
  * A new random DEK, every item re-encrypted, and new password and recovery slots, with the new recovery code typed back.
  * Every other slot (PRF, later device) re-established with a fresh evaluation, or explicitly invalidated and listed for confirmation (ADR 0001 §3).
  * One write of the new vault:
    * **Browser:** one IndexedDB exact-byte compare-and-swap transaction.
    * **Native:** the existing re-read, SHA-256 check, then temp-file rename and directory fsync (ADR 0002 §9). This is a **check-then-rename under a single-writer assumption, not a lock**: two processes writing at once can still race. Rotation keeps that documented limit unless file locking is separately authorized.
* **Must tell the user:**
  * Copies an attacker already holds (old backups, a copied profile, plaintext already seen) **cannot be revoked**.
  * Delete your own old backups.
  * Change the credentials stored at sites that may have been exposed.
* **Depends on:** ADR 0001 §3 staging. Rotation is implemented first for the slots that exist today (password and recovery). It leaves an extension point so a later PRF or device slot is re-enrolled with authentication or explicitly revoked; PRF does **not** have to exist first.
* **Acceptance:**
  * After rotation, old-credential failures are shown against the new revision.
  * **Stopped before the last cancellable point**, meaning the browser guard just before IndexedDB `put` or, natively, before the rename:
    * an interruption, a CAS conflict or another ordinary failure leaves the old stored vault, and an unlocked session stays as it was;
    * a **lock** leaves the old stored vault but always drops decrypted memory (ADR 0003 §4.2).
  * **Submitted but not confirmed** (browser: `put` issued and then a lock, expiry or stale epoch): the new envelope may commit even though the operation reports locked or stale. Decrypted memory is still dropped. The next unlock reconciles against what is stored and never reinstalls a session from the late result. Rotation must therefore show both credential sets as possibly current until reconciliation.
  * **After commit**, nothing is rolled back. If the native directory fsync then fails (`DurabilityUncertain`), the new vault and its new credentials are reported as **possibly in effect**: the UI reconciles to the new revision, tells the user to keep the old credentials until the new ones open the vault, and to make a fresh backup. Tests distinguish the precommit and postcommit outcomes and never assert rollback after commit.
  * A rotation that would leave no recovery path is refused without an explicit acknowledgement.
  * Native and browser tests run on synthetic data.

### 3. TOTP QR import — implemented (M5 phase A)
* **Implemented:** `apps/web/src/app/core/qr/`, `features/qr-import.ts`. Tests: `core/qr/*.spec.ts` and `e2e/totp-qr.spec.ts` (upload, paste, fake camera, denied camera, plain-HTTP, hostile files).
* **Scope, step 1:** decode a QR **image** the user uploads or pastes, locally, with a maintained decoder and no network.
  * The decoded `otpauth://` URI goes through the existing parser.
  * The image and secret are never logged or persisted.
* **Scope, step 2:** live camera (`getUserMedia`), only in a real secure context, gated like password vaults.
* **Depends on:** a dependency review of the decoder; G-HTTPS for the camera step.
* **Acceptance:**
  * Valid, invalid and oversized images.
  * Hostile URIs are rejected by the existing parser.
  * The camera is unavailable on plain HTTP, with a clear message.
  * No secret appears in logs or screenshots.

### 4. TOTP countdown display — implemented (M5 phase A)
* **Implemented:** `shared/totp-countdown.ts`. The next code is not shown. Tests: fixed-clock unit and E2E, reduced motion. Contrast is measured in the phase A screenshots.
* **Scope:**
  * Replace the progress bar with a small circular countdown beside the code.
  * In the last ~5 s, the code and ring change to a warning colour **and** a non-colour cue (icon or text), with the remaining seconds available to assistive technology.
  * Respect `prefers-reduced-motion`.
  * Optionally show the next code during the warning window.
  * Follow the interaction pattern of common authenticator apps without copying any product's branding or artwork.
* **Depends on:** nothing beyond the current UI.
* **Acceptance:**
  * A fixed-clock unit test for the threshold.
  * Measured contrast of the warning state in light and dark.
  * Reduced-motion snapshot.
  * Accessible label check.

### 5. Ed25519 Base58 public key, signing and verification — implemented (M5 phase B), accepted and deployed
* **Implemented:**
  * **Core:** `src/ed25519.rs` (`base58`, `parse_public_key`, `parse_signature`, `message_bytes`, `Ed25519KeyPair::sign`).
  * **Bridge and UI:** `sign_ed25519` / `verify_ed25519` in the bridge; `features/ed25519-tools.ts` in the UI.
  * **Inputs:** keys and signatures are accepted as hex or raw Base58. Base64 is not offered.
  * **Chain formats:** none; no chain-specific prefix or checksum was requested.
* **Scope (local utilities only):**
  * Show the raw 32-byte public key in Base58 (Bitcoin alphabet, no prefix or checksum) beside the existing format, with a copy action.
  * Sign an explicit message (text, or hex bytes shown before signing) with an unlocked item's key.
  * Strict verification (`verify_strict`) of a message, signature and public key in Base58, hex or Base64, with no unlock needed.
* **Not in scope:** chain RPC, transactions, wallet derivation, and Keymesh login (CLAUDE.md deferrals).
* **Honest boundary:** the browser signs inside WASM, but the key still passes through WASM memory and the JS bridge on reveal or export. Language choice does not prove a key never crosses JS.
* **Decision needed:** confirm whether any chain-specific prefix or checksum is wanted.
* **Acceptance:**
  * RFC 8032 vectors.
  * Base58 vectors.
  * Malleability and small-order rejection through strict verification.
  * The signed bytes are shown before signing.

### 6. Login item icons — step 1 implemented (M5 phase A); step 2 is phase C
* **Implemented:** `core/login-icon.ts`, `core/brand-icons.ts` and `shared/item-icon.ts`.
  * **Icon set:** 81 reviewed Simple Icons in a lazy chunk. The package is CC0, and the generator refuses any icon with its own licence (Rust, CC-BY-SA-4.0, was removed). Each icon's source and guidelines are recorded.
  * **Matching:** explicit domain aliases only, never name guessing.
  * **Icons are not a security or origin indicator.** Tests: `core/login-icon.spec.ts`, `e2e/login-icons.spec.ts` (no request leaves the origin).
**Latest direction (2026-11-14). It supersedes the earlier GPT-API idea and the idea of a separate service.**
1. **Deterministic local matching:**
   * a bundled brand-icon set (e.g. a CC0 Simple Icons subset) keyed by registrable domain;
   * a small subdomain table;
   * keyword categories (bank, mail, exchange, …);
   * private and loopback IP or `.local` detection ("internal system").
2. **Optional favicon route in the same serving program** (not a separate service), on a cache miss:
   * It sends only the host, never the path, query, fragment or userinfo.
   * The result is cached per host and stored encrypted with the item.
3. **Letter avatar fallback.**

**Design boundaries for the later route (nothing is implemented now: no external calls, no CSP change):**
* **SSRF:**
  * Resolve the host first, then refuse loopback, private, link-local, CGNAT, multicast and reserved ranges, for IPv4 and IPv6, including IPv4-mapped addresses.
  * Connect to the **resolved** IP with the original Host and SNI, so DNS rebinding cannot swap the address.
  * Allow at most 3 redirects, re-validating each hop.
  * Only `http`/`https` on default ports.
* **Limits:**
  * Short timeouts.
  * Response size caps (e.g. 256 KiB HTML scan, 64 KiB image).
  * No cookies or credentials. A fixed generic User-Agent.
* **Decode:**
  * Decode the raster image with a maintained decoder and re-encode to a fixed-size PNG.
  * **Never pass SVG or HTML through.**
  * Reject decompression bombs by dimension cap.
* **Privacy:**
  * The serving program and the target site learn which hosts are looked up.
  * Caching reduces repeats but is not unlinkability.
  * The route must be disclosed in the UI and docs.
* **Before any route is implemented** (prerequisites, not decisions):
  * opt-in only, with **no automatic lookup** of hosts already in the vault;
  * no logging of looked-up hosts;
  * defined cache ownership and retention (a shared plaintext host cache would leak browsing history);
  * handling of hosts that resolve differently on public and private DNS;
  * parsing tests for numeric, IDNA and IPv6 hosts.
* **Review:** a same-program route is not intrinsically a new listener. The outbound fetch and the metadata exposure still need their own scoped review, and so would any CSP change.
* **Acceptance (for step 1 now, step 2 later):**
  * Table-driven matching tests.
  * No network access in step 1.
  * Step 2: SSRF test matrix, including a rebinding fixture.

### 7. Passphrase generator and wordlist
* **Scope:** a reviewed, versioned wordlist (e.g. EFF large list, 7,776 words), with exact entropy shown. It is used by item 1's generated master password.
* **Acceptance:**
  * Wordlist hash pinned.
  * Uniform selection (rejection sampling).
  * Entropy figures tested.

### 8. Hardware adapters (future, not prerequisites)
* **FlareX's ESP32 HID password typer:** optional custody of the offline master password.
  * Risks: no origin binding and keyloggers.
  * Needs: an on-device PIN, flash encryption and secure boot.
* **FlareX's ESP32 "HSM":** an Ed25519 signer, or preferably a FIDO2/CTAP2 authenticator with `hmac-secret` so it plugs into item 1 unchanged.
* **Never replaces the independent recovery code.**
* **Depends on:** the chip model and firmware review; hardware/KMS integration is deferred in CLAUDE.md.

## Still deferred (CLAUDE.md)
* Own-app authentication and mnemonic login.
* Image keycards.
* Wallet, identity and KMS integration.
* NATS and sync.
* Blockchain integration.
* Real `op` imports, until a separately authorized user action.
