# Keymesh architecture and format decisions

Status: **M1–M4; not production ready.** Password vaults (M4) are experimental and synthetic-data only until independent acceptance.

## Crate layout

Single crate `keymesh` (library + `keymesh` CLI binary).

| Module | Purpose | Native only |
|---|---|---|
| `rng` | `RandomSource` port; `OsRandom` (getrandom); unbiased `uniform_index` | |
| `secret` | `SecretString` / `SecretBytes`: zeroize on drop, redacted `Debug` | |
| `crypto` | XChaCha20-Poly1305 seal/open, `Key256`, `KeyProvider` port, synthetic providers | |
| `kdf` | Argon2id (bounded parameters), NFC password normalization and new-password rules, HKDF slot KEKs | |
| `keyslot` | v2 password/recovery key slots: validation, wrap/unwrap, slot-list digest, `Authority` | |
| `recovery` | Recovery code: 256-bit secret, versioned Base32 text with check digits | |
| `model` | Typed items + validation | |
| `generate` | Passwords, random secrets (passphrase: pending) | |
| `ed25519` | RFC 8032 keypair storage format, OpenSSH public-key line | |
| `totp` | RFC 6238, Base32, `otpauth://totp` URIs, injectable clock | |
| `vault` | In-memory vault + `keymesh.vault` v1 (demo) and v2 (password) envelopes | |
| `storage` | Atomic file write, load/save, backup/restore | yes |
| `import::op` | 1Password mapping, preview/apply, `OpRunner` port | |
| `import::process` | Subprocess `OpRunner` | yes |
| `bin/keymesh` | CLI (password vaults; `--demo` for v1) | yes |

Native-only parts are behind the default `native` feature. `cargo check --lib --no-default-features --target wasm32-unknown-unknown` builds (the browser build reaches the CSPRNG through getrandom's `js` backend). The core has not been exercised in a browser yet.

## Key hierarchy

```
v1 (demo):  KeyProvider (KEK, 256-bit)  ──wraps──▶  per-vault DEK (256-bit, random)  ──encrypts──▶  items + manifest
v2:         password ─Argon2id─HKDF─▶ KEK_pw  ─┐
            recovery code ──HKDF────▶ KEK_rc  ─┴─wraps (each)──▶  DEK  ──encrypts──▶  items + manifest
```

* **v1 (demo vaults):** the KEK comes from a `KeyProvider`: `EphemeralKeyProvider` (tests, browser "This session only") or `SyntheticDemoKeyProvider` (CLI, `KEYMESH_DEMO_KEY`) and the browser's public fixture key. Neither stores a key next to the vault.
* **v2 (password vaults, M4, experimental):** exactly one password slot and one recovery slot, each wrapping the same random DEK. The full specification is in `docs/adr/0002-envelope-v2.md`: wire format, AAD, bounds, threat model, measurements and lifecycle. The design background is in `docs/adr/0001-unlock-and-recovery.md`.
* The DEK is random. For v1, `Vault::rotate_data_key` replaces it, and the next save re-encrypts everything. For v2 it is refused: compromise rotation, which would also re-establish every slot, is deferred. Password and recovery-code changes are rewraps.
* Ed25519 keys stored in the vault are item data. They are never used as or derived from the KEK/DEK.

## `keymesh.vault` v1 file

A JSON envelope. Binary fields are base64url without padding.

```json
{
  "format": "keymesh.vault", "version": 1, "aead": "xchacha20poly1305",
  "vault_id": "<128-bit hex>", "kek_id": "<provider id>", "revision": 3,
  "wrapped_dek": {"nonce": "...", "ct": "..."},
  "manifest":    {"nonce": "...", "ct": "..."},
  "items": [ {"id": "<128-bit hex>", "rev": 2, "sealed": {"nonce": "...", "ct": "..."}} ]
}
```

Associated data (NUL-separated):

| Ciphertext | Key | AAD |
|---|---|---|
| `wrapped_dek` | KEK | `keymesh.vault, v1, dek, alg, vault_id, kek_id` |
| `manifest` | DEK | `keymesh.vault, v1, manifest, alg, vault_id, kek_id, revision` |
| item | DEK | `keymesh.vault, v1, item, alg, vault_id, item_id, item_rev` |

The manifest lists `(id, rev, sha256(nonce‖ct))` for every item record in order. On load, every check must pass: format/version/alg, the key-id match, every AEAD tag, manifest-vs-records equality, payload-id equality and item validation. If any check fails, loading errors and no vault is returned. Nonces are 192-bit random values, fresh for every seal. Unknown JSON keys are rejected (`deny_unknown_fields`). A future `version` gives a `Format` error.

Public metadata is limited to the header plus item ids and revisions. The item count is visible. Titles, URLs, notes and item kinds are encrypted.

**Known limitation:** without external state, nothing detects a rollback of the whole file to an older valid revision.

## `keymesh.vault` v2 file (password vaults)

Same item and manifest structure, but `kek_id`/`wrapped_dek` are replaced by `slots` (exactly one `password` and one `recovery` slot), and every AAD uses length-prefixed fields that bind version 2. The manifest AAD also binds a digest of the whole slot list. The file's version decides how it opens: v1 only with a key provider, v2 only with its password or recovery code. The full specification is in `docs/adr/0002-envelope-v2.md`, and the shared vectors are in `tests/fixtures/v2/vectors.json`.

## Persistence safety

* Writes go to a temp file in the same directory (mode 0600), then `fsync`, atomic rename and directory `fsync`.
* `create` uses no-clobber. `save` re-reads the file and refuses unless it is byte for byte (SHA-256) what this vault last read or wrote, including vault id and revision (lost-update guard).
  * This catches a same-revision replacement with different content.
  * The guard is not a lock: two writers racing inside the check→rename window are not excluded, and Keymesh assumes a single writer per file.
* A failed decrypt never produces an empty vault, and there is no path that saves a fresh vault over an existing file.
* `backup` and `restore` verify that the source decrypts before writing. Without `--force`, `restore` won't replace an existing file.
* Reads and writes share one size bound, `MAX_VAULT_BYTES` (64 MiB). An oversize vault is refused when `create` or `save` is called, before any temp file is written: the old file stays byte-identical and loadable, and the in-memory revision does not advance. The caller must shrink the vault and save again.

## Generators

* `uniform_index` uses rejection sampling over u32 draws, so there is no modulo bias.
* Passwords: profiles `default` (24 characters) and `strong` (32 characters) over lower/upper/digits/symbols with every class required. When classes are required, one character is drawn per class, the rest come from the union, and then an unbiased Fisher–Yates shuffle runs. No retry loop is used. A custom allowlist is deduplicated, and control or whitespace characters are rejected.
* Policies are rejected when they have empty classes, a length outside 8..=1024, a length shorter than the number of required classes, or a **min-entropy** below 64 bits.
* **The 64-bit floor uses the exact min-entropy of the generator's output** (−log2 of the probability of the most likely password), not the uniform estimate. With k forced classes of sizes s_i, alphabet N and length L, a password w with n_i(w) characters of class i arises from exactly ∏n_i(w)·(L−k)! of the L! shuffle orders, so P(w) = ∏n_i(w) · (L−k)!/L! · ∏(1/s_i) · N^−(L−k). This is largest for the most even counts (∏n_i ≤ (q+1)^r·q^(k−r), L = qk + r), giving H∞ = log2(L!/(L−k)!) − log2 max∏n_i + Σlog2 s_i + (L−k)·log2 N. Without forced classes the output is uniform and H∞ = L·log2 N. `min_entropy_bits` implements this; a test compares it with the exhaustively enumerated output distribution of small policies, and min-entropy is a lower bound on Shannon entropy. Example: 11 characters of all four types with the symbol set `!` has a 65.75-bit upper bound but 61.8 bits min-entropy, so it is refused; all four default types need 11 characters (70.2 bits), not 10 (63.6).
* **User settings (`PasswordOptions`).** `{length, lowercase, uppercase, digits, symbols, symbolSet, excludeAmbiguous, requireEachClass}` becomes a policy through `PasswordPolicy::from_options`. Each selected type stays its own class, so "use each selected type at least once" keeps its meaning (no concatenated allowlist). Everything is validated before any random number is drawn:
  * length 8..=128 (the UI range, which also bounds the work per request);
  * at least one type selected;
  * when symbols are on, the symbol set holds 1–64 characters and only printable ASCII punctuation. Letters, digits, spaces, control characters and other scripts are refused, so the symbol field cannot re-enable a type the user turned off. Duplicates are removed and never add weight. When symbols are off the field is ignored;
  * "avoid look-alike characters" removes `Il1O0o`; a type left empty is an error;
  * the 64-bit floor above still applies. Nothing is added or lengthened to make a policy pass: digits-only needs at least 20 characters, lowercase-only at least 14.
* `PasswordPolicy::summary()` reports length, alphabet size, `upperBoundBits` (`length × log2(alphabet)`, a theoretical upper bound only, never used for validation) and `minEntropyBits` (the value the floor is checked against). Neither number is shown in the UI.
* WASM: `generatePasswordWithOptions(json)` (stateless, used by the item forms), `passwordPolicySummary(json)` (validates, no RNG) and `VaultSession.generatePasswordItemWithOptions(title, json, service)` (generated and stored in one step; kept for API compatibility, not used by the UI). The JSON is strict: unknown, missing or wrongly typed fields and input over 2 KiB are refused.
* **Previews (exact save).** `VaultSession.previewPassword(json)` and `previewSecret(bytes, encoding)` generate a value, keep it in the session as the current preview of that generator (one slot each, replaced by the next preview) and return a copy to show. `savePreview(kind, shown, title, service)` stores the preview as a Secret item with origin *generated* only if `shown` equals the held value (constant-time comparison); otherwise it fails with "generated value is no longer available". A successful insert consumes the preview, so a double click or a second tab cannot save it twice; a validation failure keeps it. `discardPreviews()` and `lock()` drop all previews. The web page therefore saves exactly what the user saw: there is no path that substitutes a freshly generated value.
* Random secrets default to 32 bytes (256 bits), with an explicit encoding (hex, base64url or base32). They are local random values, not provider-issued credentials.
* RNG failure returns `Error::Rng`. There is no fallback.
* Passphrases are **pending**: no reviewed, versioned wordlist is bundled.

## TOTP

RFC 6238 with SHA1/SHA256/SHA512, 6 or 8 digits, period 15..=300 s (default 30), and secrets of 10..=128 bytes. The 80-bit minimum matches widely deployed providers. RFC 4226 recommends ≥128 bits.

The `otpauth://totp` parser accepts `secret, issuer, algorithm, digits, period, image`. It rejects `hotp`, unknown parameters (`counter`, `encoder=steam`, …), duplicates, and an issuer that differs between the label and the parameter. QR decoding is **not implemented** (a future UI adapter).

## Ed25519

Implemented with `ed25519-dalek` 2. The stored format is the 32-byte RFC 8032 seed plus the 32-byte public key (hex), and validation checks that the public key matches the seed. Export is limited to the OpenSSH public-key line. OpenSSH/PKCS#8 private-key formats are **not** implemented, and the raw seed JSON is not either format. There is no general signing API. Signing appears only in tests (RFC 8032 §7.1 vectors 1–3).

## 1Password import

* Targets are explicit only:
  * an item: `op item get <item> --vault=<v> --format=json --reveal [--account=<a>]`
  * a single field reference: `op read --no-newline --account=<a> op://v/i/[s/]f`. The account is **required** here, as explained below.
* No list, whoami or enumeration commands run. `--otp` and `?attribute=otp` are never used or accepted.
* No shell is involved: arguments go out as an argv vector, stdin is closed, and output is bounded to 16 MiB. `OP_DEBUG` is removed from the child environment.
* The timeout is end to end: it covers the child running *and* the collection of its stdout and stderr. The child is spawned as the leader of a new process group. On timeout, or on a reader error, the whole group gets SIGKILL, so descendants holding the pipes open cannot hang an import. A descendant that deliberately escapes into its own session or process group is not covered.
* Positional values that start with `-`, control characters and values over 512 bytes are rejected before anything executes.
* Authentication comes from the user's existing `op` session. Keymesh never asks for credentials.
* `plan()` fetches and maps targets into in-memory drafts. `preview()` reports without writing. `apply()` mutates the vault in memory, all-or-nothing per entry, and the caller then saves it encrypted.
* **Account scoping:**
  * Item ids. An item's source id is derived from the vault id and item id in `op`'s JSON output. Those identify the item independently of the account selector. Both ids must have the shape shown in `op item get --help` (26 lowercase alphanumerics, e.g. `kiramv6tpjijkuci7fig4lndta`); anything else fails closed as `malformed_output`. That shape is inferred from the CLI help and **not verified against real output**. The synthetic fixtures use ids of that shape on purpose.
  * Reference ids. A secret reference is a *path* of names, and a path is only unique within one account. When `--account` is omitted, `op` falls back to `OP_ACCOUNT` or its default account, and that can change between runs. Keymesh therefore rejects reference targets that have no explicit account (`invalid_target`, with no `op` call made).
  * Reference id format. See *Provenance ids* below. Neither the account nor the path appears in reports.
  * Aliases. The same account named by different selectors (shorthand, sign-in address, ID) produces different ids. That can create a duplicate record; it never overwrites another account's record.
  * Migration. Source ids changed twice during M1 review: at `fc838fb` they were `1password:item:<vault>/<item>`, `…#otp:<field>` and `1password:ref:<hash>`; at `5465bcc` references became `1password:acct-ref:<hash>`; now every id uses the v3 provenance hash. Records imported by earlier M1 commits are not matched, so re-importing them creates new records. Only synthetic development vaults exist, so no migration code was added.
* **Provenance ids** (all derived from untrusted provider data, never shown in clear):
  * `provenance_id(kind, parts)` = `1password:<kind>:<hex of the first 16 bytes of SHA-256>`, computed over the tag `keymesh.op-provenance.v3`, the kind and every part, each length-prefixed (u64 big-endian). Separators, NULs or empty parts cannot make two tuples collide.
  * item: `(vault id, item id)`; OTP field: `(vault id, item id, field id)`; an OTP field with a missing or duplicate id falls back to `otp-index` `(vault id, item id, position)`, which is not stable under reordering; reference: `acct-ref` `(account, reference)`.
* **Report metadata:** a category is published only if it is on the allowlist of the 20 categories listed by `op item list --help`, in the upper-snake form; anything else is reported as `UNKNOWN`, and the original value is preserved as an encrypted custom field (`section = "1password"`, label `category`). Each imported item also keeps the original vault id and item id as encrypted custom fields in the same section, for traceability.
* Dedup: each item records `ImportSource {provider, source_id, fingerprint}` inside its encrypted payload. Re-importing gives one of these results:
  * unchanged content → `unchanged_duplicate`
  * changed content → `conflict` (the default), or `updated` with `ConflictPolicy::Update`
  * the same target twice in one run → `duplicate_in_run`
* Mapping:
  * LOGIN maps to Login, plus one TOTP item per OTP field, holding the provisioning URI/secret. The Login links to the TOTP item of its *first* OTP field. The ephemeral `totp` code key is ignored.
  * **Link reconciliation:** the Login's fingerprint includes the source id of its link target, and a Login only counts as unchanged if its local `totp_item` also resolves to that target's local item. Adding, replacing, removing or reordering OTP fields therefore shows as `conflict` under the default policy, which leaves the Login and its link untouched (a TOTP record for a newly added OTP field is still created, as a new record), and as `updated` under `ConflictPolicy::Update`, which points the Login at the current target or clears the link. TOTP records that are no longer referenced are kept, never deleted.
  * PASSWORD and API_CREDENTIAL map to Secret.
  * SSH_KEY maps to a Secret with format `opaque_private_key`. It is never presented as an Ed25519 key.
  * SECURE_NOTE maps to SecureNote, IDENTITY to Contact, and CRYPTO_WALLET to CryptoWalletRecord.
  * DOCUMENT is reported as `unsupported`. Other categories become a SecureNote that preserves every field.
  * Fields that aren't consumed become encrypted custom fields carrying their source type. Unknown types get `kind = unsupported`.
  * Every item URL that isn't mapped into `Login.urls` is kept verbatim as an encrypted custom field. This covers URLs on every non-login category, and login URLs that fail URL validation. The field has `section = "urls"`, `kind = url` and `source_type = "URL"`, with the label taken from the source URL's label or defaulting to `url`. Warnings count invalid and empty URLs.
  * Warnings give counts for empty fields and attachments.
* Reports contain only hashed provenance ids (or `target:<n>` when a fetch failed before identification), allowlisted category codes, statuses, error codes, counts and constant warning codes. They never contain values, titles, raw ids, field ids, stderr or arguments.
* The JSON field shape (`id/type/purpose/label/value/section`, `urls[].href`, `vault.id`) comes from the `op` item JSON format as understood at M1. The official reference pages do not specify it. **It has not been verified against real `op` output**, because accessing real data was not authorized.

## Browser app (M2 demo, UI refined in M3, password vaults in M4)

Status: **demo vaults use development-only keys; password vaults are experimental and synthetic-data only until independent acceptance. Not production.**

### Layers

```
Angular (apps/web)  ── JSON views / masked slots ──▶  keymesh-wasm (wasm-bindgen)  ──▶  keymesh core (no "native" feature)
        │                                                     │
        └── IndexedDB: encrypted envelope bytes only ◀── seal() ┘
```

* `crates/keymesh-wasm/src/bridge.rs` contains all of the bridge logic and is unit-tested natively. `lib.rs` is a thin `wasm-bindgen` adapter.
* The core's filesystem, `op` process runner and CLI stay behind the `native` feature and are not part of the browser build. The 1Password importer stays native-only, and no HTTP endpoint runs `op`.
* On `wasm32-unknown-unknown`, randomness comes from `crypto.getRandomValues` (via `getrandom`'s `js` backend), and wall-clock time from `Date.now()` (via `js-sys`), because `std::time::SystemTime` panics there.

### Data crossing into JavaScript

* `list` returns summaries: id, kind, title, a non-secret subtitle (username, service, issuer, etc.) and tags.
* `get` returns an item view with non-secret fields plus *slots* for secret fields: password, recovery codes, secret, wallet secrets, note body, notes, concealed custom fields, and the TOTP setup secret.
* A slot's plaintext crosses only through `reveal(id, slot)`, used by the Reveal and Copy buttons. Revealed text is rendered as text content, never as an attribute, and is hidden again after 30 seconds or on lock.
* Ed25519 seeds are never revealable. Only the public key, in hex and as an OpenSSH line, is exposed, and there is no signing API.
* Generated passwords, random secrets and Ed25519 keys can be created and stored entirely inside WASM. A password generated on the Generators page, or inside the Login/Secret form, is returned to the UI on purpose. It is shown masked with explicit Reveal/Copy, and it reaches a form field only when the user chooses "Use this password". Cancel discards it and leaves the field unchanged.
* The core's error messages contain no secret values, and item-input parse errors are reported generically, because serde messages can quote input. The UI never shows raw error text anyway: `apps/web/src/app/core/errors.ts` maps known conditions to localized messages and everything else to a generic "something went wrong" (see *Language and appearance*).

### Key providers (DEVELOPMENT ONLY)

| Mode | Key | Reload | Notes |
|---|---|---|---|
| `ephemeral` | random, generated in WASM | lost; the stored ciphertext becomes inaccessible, and the UI says so | no recovery exists |
| `synthetic-fixture` | SHA-256 of a **public** label | reopens | anyone can decrypt; only for demos and tests |

The key is never exported to JavaScript and never appears in the URL, storage, console or error messages. A demo vault is never converted into a password vault.

### Password vault (M4, experimental)

* **Separate storage:** IndexedDB database `keymesh-vault` (same record shape; `kekId` is a fixed placeholder). It is opened only in a secure context, and reads never create it.
* **Secure contexts only:** `SECURE_CONTEXT` is `isSecureContext`. On a plain-HTTP LAN/VPN origin every password-vault operation throws `insecureContext`, and the start screen explains why; the demo keeps working.
* **Argon2id in a worker:** `core/kdf.ts` compiles the WASM module once and hands it to a short-lived module worker (`kdf.worker.ts`). The worker runs `deriveArgon2id` for a request the core issued: `passwordRequest(bytes)`, `ProtectedCreation.request()` or `beginPasswordChange()`. The core keeps every pending setup, so JavaScript only passes derived keys back, never parameters of its own choosing. Results are transferred and zeroed after use.
* **One credential operation at a time:** a second one is refused (`busy`), not queued.
* **Lock cancels:** `lock()` terminates the worker and frees an unconfirmed new vault. Every step re-checks the lock generation after the KDF, after IndexedDB and after file reads.
* **Create:** a password → `VaultSession.createProtected` (in memory) → the recovery code is shown → the user types it back → the core verifies it by unwrapping the recovery slot → seal → compare-and-swap into empty storage → open.
* **Other flows:** unlock; reset with the recovery code; restore a v2 backup with its password (stored unchanged) or its recovery code plus a new password; change password; new recovery code; delete from this browser. All writes use the same exact-byte compare-and-swap. Failed credential writes roll the core back (`rollback`).
* **Product copy mapping:** "Password vault" is envelope v2; "Demo vault" is v1 with the ephemeral or fixture key; "Securing your vault…" is the Argon2id step; "Password vaults need a secure connection" means a non-secure context.

### Persistence and concurrency

* IndexedDB database `keymesh-demo`, store `vault`, key `primary` holds `{bytes, vaultId, kekId, revision}`. `bytes` is the same `keymesh.vault` v1 envelope as on native.
* No vault data, key material or item index is kept in Web Storage. The only `localStorage` entry is the non-secret display preference (see *Language and appearance*). No sessionStorage or cookies are used.
* **Every write is an exact-snapshot compare-and-swap** inside one readwrite transaction. It succeeds only if the stored envelope is byte-for-byte the snapshot this tab last read or wrote; `null` means storage must still be empty.
  * Exact bytes are compared, not revision numbers. Restoring an older backup can bring back a revision number that a stale tab already holds with different content, and a revision check would let that tab overwrite newer data.
  * This applies to mutations, restore, the initial vault and discard. There is no unconditional write path.
* A mutation runs in WASM, then `seal()` produces the envelope, then the compare-and-swap writes it. The session revision advances only after the write succeeded (`commit`).
* `seal()` enforces the same 64 MiB bound that `open()` accepts. If a change would exceed it, or sealing fails for any other reason, nothing is published, the session rolls back to its last committed state, and the stored envelope is untouched and still readable.
* After a failed persist the tab is marked *stale*. Editing, and restoring from that tab, are blocked until it reloads from storage, which drops any unsaved in-memory change.
* Other tabs receive a `BroadcastChannel` ping and compare the stored bytes against their snapshot. Bytes are used rather than revisions for the same reuse reason. The compare-and-swap protects data even when the ping is missed, and E2E covers both paths.
* Async work within a tab is serialized through a promise queue.

### Lock

* `lock()` drops the decrypted `Vault`, its checkpoint and the data key inside WASM, and frees the session handle. It also clears list, search and selection state, and bumps the lock generation (`epoch`).
* **Lock wins.** Every asynchronous operation (unlock, start, mutation, backup, restore, discard) captures the generation when it is *invoked*, not when the queue reaches it. It re-checks the generation before starting and after every `await`. Work invoked before a lock never installs a session, never repopulates the UI and never commits.
* **The guard reaches the storage boundary.** `VaultStore.compareAndSwap` / `compareAndClear` take the operation's guard and check it after the database opens and again after reading the current record, immediately before `put`/`delete`. A write still waiting there (for the database, for another transaction, or in the queue) is cancelled: its transaction is aborted and the stored ciphertext is unchanged (`StaleWorkError`, "cancelled"). Only a write whose `put` was already issued can land; it is never committed to the freed session and is reported as `StaleWorkError(committed = true)` ("locked right after your change was saved; unlock to see it"), never as success. A failing `put` (for example a clone error) aborts the transaction and leaves the record unchanged.
* Where cancellation is still possible, nothing is persisted: a restore checks the generation before its compare-and-swap.
* If a lock lands while an already-verified write is in flight, the ciphertext write completes but nothing is installed. Unlocking later reads whatever is stored.
* Every vault operation then fails with "vault is locked", in both the core session and the service.
* The development key provider stays in WASM memory so the demo can unlock again. That is a test-provider transition, not app identity.

### Backup and restore

* Backup downloads the stored envelope bytes exactly as stored, after checking they match this tab's snapshot. They are ciphertext only, and E2E checks them for planted markers.
* Restore is allowed only from an unlocked, non-stale tab, which replaces exactly the envelope it last saw, or into empty storage using the synthetic fixture key (labelled as a test harness).
* Restore first checks the file size (64 MiB maximum), then decrypts the file with the demo key. Only then, if no lock happened, does it compare-and-swap.
* Truncated, garbage, unknown-version and wrong-key files are rejected, and the stored vault stays byte-identical. The same happens if another tab wrote meanwhile.

### Browser hardening

* A CSP meta tag and server header allow `default-src 'self'` and `script-src 'self' 'wasm-unsafe-eval'`. Styles allow `'unsafe-inline'` for Angular component styles. Critical-CSS inlining is disabled, so no inline event handler is needed.
* There are no third-party origins, analytics or remote fonts (system font stack only). E2E asserts that only same-origin requests are made.
* The saved theme and language are applied before first paint by `public/preferences-boot.js`, a same-origin classic script loaded from `<head>`. No inline script and no new CSP allowance is needed; E2E asserts the page has no inline scripts and logs no CSP violations.
* `scripts/serve.mjs` (production build) binds to 127.0.0.1 and sends `nosniff`, `no-referrer`, COOP and `frame-ancestors 'none'`.
  * An explicit `HOST=<one literal IP>` enables a LAN preview. Wildcards and hostnames are refused, and the headers are unchanged.
  * That origin is plain HTTP and not a secure context: there is no Clipboard API, COOP is ignored, traffic is unencrypted and password vaults are off (see `apps/web/README.md`).
  * `TLS_CERT`/`TLS_KEY` serve HTTPS (TLS 1.2+) with HSTS. See `docs/DELIVERY.md` for what is and isn't proven.
* The CSP also allows `worker-src 'self'` for the KDF worker. The worker script is a same-origin build chunk, and the WASM module is compiled by the page and handed to it.

### Language and appearance (M3)

* **Locales:** exactly `zh-TW` (繁體中文) and `en`. `src/app/core/i18n/en.ts` is the source catalog and defines `MessageKey`; `zh-tw.ts` is typed `Record<MessageKey, string>`, and Angular strict template checking makes an unknown key in a template a build error. `I18n.t()` reads the locale signal, so switching re-renders text without touching component state: form inputs, selection, generator previews, TOTP codes and keys are unchanged, and nothing is written to the vault. Dates and numbers use `Intl` for the active locale. User data, technical identifiers, key formats and wallet addresses are not translated.
* **Labels from the core:** secret slot labels from `bridge.rs` (`password`, `recovery_code:n`, …) are mapped by slot key to catalog entries. Custom-field labels are the user's own text.
* **Errors:** `errorKey()` maps app error classes (`VaultError` codes, `LockedError`, `StaleWorkError`, `ConflictError`) and a fixed allowlist of core message prefixes to catalog keys. Anything else becomes `errors.unexpected`; the raw text is neither shown nor logged.
* **Appearance:** `system` (default), `light` or `dark`. `system` follows `prefers-color-scheme`, including live OS changes; an explicit choice overrides the OS until `system` is chosen again. Colours are `light-dark()` tokens driven by `color-scheme`, so native controls, scrollbars, dialogs and toasts follow the same theme. Without JavaScript the OS preference applies.
* **Default language:** the first `navigator.languages` entry that is Chinese (any `zh*` → `zh-TW`) or English; otherwise English.
* **Persistence:** only an explicit choice is saved, as `{"locale","theme"}` JSON under `localStorage["keymesh.settings.v1"]`. Missing, corrupt or partially invalid values fall back per field; blocked or full storage keeps the choice for the current page and shows a note. `<html lang>`, `data-theme` and the document title are kept in sync.
* **Password settings** are shared by the Generators page and the Login/Secret forms (`PasswordSettings`). Choosing Default or Strong fills every setting; any later change switches the preset to Custom without re-applying preset rules. Changing settings never generates, regenerates or saves anything. The last settings **the core accepts** are stored as JSON `{preset, options}` under their own Web Storage key `keymesh.password-settings.v1`, separate from `keymesh.settings.v1` and from the vault. Acceptance is the core's own policy check (`passwordPolicySummary`, no RNG; the same validation generation uses, including the min-entropy floor), so TypeScript has no second copy of the policy. Nothing is written until the user changes a setting; edits the core rejects (a weak policy, an enabled but empty symbol set) stay on screen with their message but are not stored, so the last accepted settings remain. Reading is strict: unknown or missing fields, wrong types or values out of shape discard the whole entry, and an entry the core rejects is ignored too; the defaults apply and the rejected entry is not rewritten by loading. Like the core, symbol text is not judged while Symbols is off: invalid or overlong text in the hidden field never blocks saving otherwise valid settings, and it is kept unchanged (stored text is bounded at 256 characters, which the input also enforces). A preset whose values no longer match it reads as Custom. Nothing is restored or saved before the core is loaded; stored settings are then applied once, unless the user already changed something. Blocked or full storage leaves the settings in memory for the page. Generated values, item data and keys are never stored there.
* **Generated previews** (`core/generated-draft.ts`) remember a copy of the settings they were generated with. While the current settings differ, the value is not shown and cannot be saved or used ("Settings changed. Generate again…"). Generator previews are cleared, and the core's copies discarded, when the page is left, on lock and on destroy. Save is disabled while nothing current is generated, while a save runs, and while the tab is stale or locked; success is shown only after the encrypted write was committed. A save invoked before a lock is cancelled by the epoch guard, down to the storage write (see "The guard reaches the storage boundary").
* **Product copy.** Normal screens describe what the user can do and what happens, in plain language: they do not mention Rust, WASM, IndexedDB, compare-and-swap, envelopes or key-provider names. The technical facts behind that copy are documented here: the "This session only" vault type is the `ephemeral` provider, "Reopen after reload (test key)" is `synthetic-fixture`, and "Load latest version" is the stale-tab reload. Tests target the stable `data-key-mode`, `data-revision` and `data-rev` attributes instead.
* See `docs/DESIGN.md` for tokens and UI conventions.

### Limitations

* JavaScript and WASM cannot guarantee zeroization. Strings passed to the UI (revealed values, form inputs, previews) and the clipboard are outside the core's control. WASM linear memory is not reliably cleared on lock.
* Offline startup is deferred: there is no service worker, so loading the app needs its origin.
* QR or camera TOTP import is not implemented.
* No passphrase generator yet.
* The browser and CLI vault files are separate stores; a v2 backup from one can be restored in the other (same format), but there is no sync.
* The typed master password is a JavaScript string and cannot be reliably erased. Derived keys are zeroed, but only as `Uint8Array` copies.
* Native limitations still apply: a single writer per file with no file lock (natively), and whole-file rollback cannot be detected.
