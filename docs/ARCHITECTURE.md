# Keymesh M1 architecture and format decisions

Status: **M1 foundation, not production ready.**

## Crate layout

Single crate `keymesh` (library + `keymesh` CLI binary).

| Module | Purpose | Native only |
|---|---|---|
| `rng` | `RandomSource` port; `OsRandom` (getrandom); unbiased `uniform_index` | |
| `secret` | `SecretString` / `SecretBytes`: zeroize on drop, redacted `Debug` | |
| `crypto` | XChaCha20-Poly1305 seal/open, `Key256`, `KeyProvider` port, synthetic providers | |
| `model` | Typed items + validation | |
| `generate` | Passwords, random secrets (passphrase: pending) | |
| `ed25519` | RFC 8032 keypair storage format, OpenSSH public-key line | |
| `totp` | RFC 6238, Base32, `otpauth://totp` URIs, injectable clock | |
| `vault` | In-memory vault + `keymesh.vault` v1 envelope | |
| `storage` | Atomic file write, load/save, backup/restore | yes |
| `import::op` | 1Password mapping, preview/apply, `OpRunner` port | |
| `import::process` | Subprocess `OpRunner` | yes |
| `bin/keymesh` | CLI harness | yes |

Native-only parts are behind the default `native` feature. `cargo check --lib --no-default-features --target wasm32-unknown-unknown` builds (the browser build reaches the CSPRNG through getrandom's `js` backend). The core has not been exercised in a browser yet.

## Key hierarchy

```
KeyProvider (KEK, 256-bit)  ──wraps──▶  per-vault DEK (256-bit, random)  ──encrypts──▶  items + manifest
```

* The KEK comes from a `KeyProvider`. M1 ships only `EphemeralKeyProvider` (tests) and `SyntheticDemoKeyProvider` (CLI, key from `KEYMESH_DEMO_KEY`). Neither stores a key next to the vault. **Production unlock (passphrase KDF, OS keystore, hardware) and recovery are not designed yet.**
* The DEK is random. `Vault::rotate_data_key` replaces it, and the next save re-encrypts everything.
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

## Persistence safety

* Writes go to a temp file in the same directory (mode 0600), then `fsync`, atomic rename and directory `fsync`.
* `create` uses no-clobber. `save` re-reads the on-disk header and refuses if the vault id or revision differs from the loaded one (lost-update guard). This guard is not a lock: two writers racing inside the check→rename window are not excluded.
* A failed decrypt never produces an empty vault, and there is no path that saves a fresh vault over an existing file.
* `backup` and `restore` verify that the source decrypts before writing. Without `--force`, `restore` won't replace an existing file.

## Generators

* `uniform_index` uses rejection sampling over u32 draws, so there is no modulo bias.
* Passwords: profiles `default` (24 characters) and `strong` (32 characters) over lower/upper/digits/symbols with every class required. When classes are required, one character is drawn per class, the rest come from the union, and then an unbiased Fisher–Yates shuffle runs. No retry loop is used. A custom allowlist is deduplicated, and control or whitespace characters are rejected.
* Policies are rejected when they have empty classes, a length outside 8..=1024, a length shorter than the number of required classes, or an estimated entropy below 64 bits.
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
  * a single field reference: `op read --no-newline [--account=<a>] op://v/i/[s/]f`
* No list, whoami or enumeration commands run. `--otp` and `?attribute=otp` are never used or accepted.
* No shell is involved: arguments go out as an argv vector, stdin is closed, and output is bounded to 16 MiB with a timeout. `OP_DEBUG` is removed from the child environment.
* Positional values that start with `-`, control characters and values over 512 bytes are rejected before anything executes.
* Authentication comes from the user's existing `op` session. Keymesh never asks for credentials.
* `plan()` fetches and maps targets into in-memory drafts. `preview()` reports without writing. `apply()` mutates the vault in memory, all-or-nothing per entry, and the caller then saves it encrypted.
* Dedup: each item records `ImportSource {provider, source_id, fingerprint}` inside its encrypted payload. Re-importing gives one of these results:
  * unchanged content → `unchanged_duplicate`
  * changed content → `conflict` (the default), or `updated` with `ConflictPolicy::Update`
  * the same target twice in one run → `duplicate_in_run`
* Mapping:
  * LOGIN maps to Login, plus one TOTP item per OTP field, holding the provisioning URI/secret. The first TOTP item is linked from the Login. The ephemeral `totp` code key is ignored.
  * PASSWORD and API_CREDENTIAL map to Secret.
  * SSH_KEY maps to a Secret with format `opaque_private_key`. It is never presented as an Ed25519 key.
  * SECURE_NOTE maps to SecureNote, IDENTITY to Contact, and CRYPTO_WALLET to CryptoWalletRecord.
  * DOCUMENT is reported as `unsupported`. Other categories become a SecureNote that preserves every field.
  * Fields that aren't consumed become encrypted custom fields carrying their source type. Unknown types get `kind = unsupported`.
  * Warnings give counts for empty fields and attachments.
* Reports contain source ids (`1password:item:<vault-id>/<item-id>`, `1password:ref:<sha256 prefix>`, or `target:<n>`), statuses, error codes, counts and warning codes. They never contain values, titles, stderr or arguments.
* The JSON field shape (`id/type/purpose/label/value/section`, `urls[].href`, `vault.id`) comes from the `op` item JSON format as understood at M1. The official reference pages do not specify it. **It has not been verified against real `op` output**, because accessing real data was not authorized.
