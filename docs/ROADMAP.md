# Keymesh roadmap

**Status as of 2026-11-14.** This is a plan, not a commitment or an authorization.
* Each item needs its own task contract and independent review before implementation.
* Everything stays experimental and synthetic-data only until independent acceptance.
* Priorities follow FlareX's requests from 2026-11-14 unless noted.

## Where things stand

| Milestone | State |
|---|---|
| M1 vault core, CLI, `op` importer (fake-runner tested) | Accepted |
| M2 browser vault (WASM) | Accepted |
| M3 UI polish, locale and theme | Accepted |
| Generator finish | Accepted |
| **M4 local unlock** (password and recovery slots, backup/restore, HTTPS mechanics) | **Partial.** Exact-head native, web and static-containment evidence exists. Open: visual follow-ups (reconcile task) and **gate C, trusted remote HTTPS**, which needs a human decision (`docs/DELIVERY.md` §4) |

### Gates shared by several items
* **G-HTTPS (gate C).** A client-trusted HTTPS origin for LAN/VPN use, because the plain-HTTP previews are not secure contexts. It is required for non-loopback password vaults, WebAuthn, the camera and the Clipboard API. The decision is the human's; no CA or certificate is created without approval.
* **G-REVIEW.** Each format or crypto change gets test vectors and an independent review.

## Backlog (ordered)

### 1. Quick unlock and auto-lock — high priority
* **Scope:** design in [ADR 0003](adr/0003-quick-unlock.md); proposed now, not implemented.
  * A `webauthn-prf` slot with fail-closed capability detection.
  * Idle and hide auto-lock with the existing epoch cancellation.
  * A generated master password and printable emergency sheet.
  * Separate custody of the recovery code.
* **Not in scope:** a browser-only PIN slot (ADR 0003 option E, decision D2), plaintext remembered keys, and Keymesh login.
* **Depends on:**
  * review of ADR 0003;
  * the real-device capability test (ADR 0003 §5);
  * G-HTTPS for any non-loopback use;
  * the product decisions D1–D3.
* **Acceptance:**
  * **Format:** test vectors for the new slot kind; unknown kinds are still refused by older readers.
  * **Browser:** the Playwright virtual authenticator covers enrolment, unlock, removal, PRF-unsupported and no-results refusal, UV-missing refusal, and abort on lock or hide.
  * **Lock:** idle and hide timers lock and cancel in-flight work.
  * **Real devices:** at least one device-bound and one synced path recorded on real devices.
  * **Copy:** never says "biometric" alone, and discloses synced-passkey scope.

### 2. DEK rotation (re-encrypt the vault) — after item 1
* **Scope:**
  * A new random DEK, every item re-encrypted, and new password and recovery slots, with the new recovery code typed back.
  * Every other slot (PRF, later device) re-established with a fresh evaluation, or explicitly invalidated and listed for confirmation (ADR 0001 §3).
  * One atomic write: the native exact-byte CAS and durable replace, or one IndexedDB CAS transaction.
* **Must tell the user:**
  * Copies an attacker already holds (old backups, a copied profile, plaintext already seen) **cannot be revoked**.
  * Delete your own old backups.
  * Change the credentials stored at sites that may have been exposed.
* **Depends on:** ADR 0001 §3 staging; item 1's slot model, so rotation knows every slot kind.
* **Acceptance:**
  * After rotation, old-credential failures are shown against the new revision.
  * Interruption or a lock at each stage leaves the old vault intact.
  * A rotation that would leave no recovery path is refused without an explicit acknowledgement.
  * Native and browser tests run on synthetic data.

### 3. TOTP QR import
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

### 4. TOTP countdown display
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

### 5. Ed25519 Base58 public key, signing and verification
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

### 6. Login item icons
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
