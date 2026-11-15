//! `wasm-bindgen` adapter for the Keymesh core — **EXPERIMENTAL, NOT
//! INDEPENDENTLY REVIEWED; synthetic data only.**
//!
//! Exposes a demo key-provider handle (development-only, memory-only), a
//! vault session (demo v1 or password + recovery v2), the Argon2id step the
//! browser runs in a worker, generators and envelope inspection. Errors carry the core's
//! messages, which never include secret values. All logic lives in
//! [`bridge`]; this file only converts types.

pub mod bridge;

use bridge::{DemoKey, ItemInput, ProtectedCreation as Creation, Session};
use wasm_bindgen::prelude::*;

fn err(e: keymesh::Error) -> JsError {
    JsError::new(&e.to_string())
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, JsError> {
    serde_json::to_string(v).map_err(|_| JsError::new("serialization failed"))
}

fn parse_input(s: &str) -> Result<ItemInput, JsError> {
    // Input errors are reported generically: serde messages may quote input.
    serde_json::from_str(s).map_err(|_| JsError::new("invalid item input"))
}

/// DEVELOPMENT-ONLY key provider. The key never leaves WASM memory.
#[wasm_bindgen]
pub struct DemoKeyProvider {
    inner: DemoKey,
}

#[wasm_bindgen]
impl DemoKeyProvider {
    /// Random key for this page session only.
    pub fn ephemeral() -> Result<DemoKeyProvider, JsError> {
        Ok(Self {
            inner: DemoKey::ephemeral().map_err(err)?,
        })
    }

    /// Publicly known synthetic fixture key (anyone can decrypt).
    #[wasm_bindgen(js_name = syntheticFixture)]
    pub fn synthetic_fixture() -> DemoKeyProvider {
        Self {
            inner: DemoKey::fixture(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> String {
        self.inner.mode().into()
    }

    #[wasm_bindgen(getter, js_name = keyId)]
    pub fn key_id(&self) -> String {
        self.inner.provider().key_id().into()
    }
}

/// A password vault about to be created. `request` holds the public Argon2id
/// parameters (JSON) for the KDF worker; the core keeps the setup so only a
/// key derived for exactly these parameters is accepted.
#[wasm_bindgen]
pub struct ProtectedCreation {
    inner: Creation,
}

#[wasm_bindgen]
impl ProtectedCreation {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<ProtectedCreation, JsError> {
        Ok(Self {
            inner: Creation::new().map_err(err)?,
        })
    }

    pub fn request(&self) -> Result<String, JsError> {
        json(&self.inner.request())
    }
}

#[wasm_bindgen]
pub struct SealedVault {
    bytes: Vec<u8>,
    revision: u64,
}

#[wasm_bindgen]
impl SealedVault {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn revision(&self) -> f64 {
        self.revision as f64
    }
}

#[wasm_bindgen]
pub struct TotpNow {
    code: String,
    remaining: u32,
}

#[wasm_bindgen]
impl TotpNow {
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.code.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn remaining(&self) -> u32 {
        self.remaining
    }
}

#[wasm_bindgen]
pub struct VaultSession {
    inner: Session,
}

#[wasm_bindgen]
impl VaultSession {
    pub fn create(key: &DemoKeyProvider) -> Result<VaultSession, JsError> {
        Ok(Self {
            inner: Session::create(&key.inner).map_err(err)?,
        })
    }

    /// Decrypt an envelope (fails closed).
    pub fn open(bytes: &[u8], key: &DemoKeyProvider) -> Result<VaultSession, JsError> {
        Ok(Self {
            inner: Session::open(bytes, &key.inner).map_err(err)?,
        })
    }

    /// New empty password vault from the key derived for `creation`. Shows
    /// its recovery code until `confirmRecovery`; saving is refused before.
    #[wasm_bindgen(js_name = createProtected)]
    pub fn create_protected(
        creation: &ProtectedCreation,
        password_key: &[u8],
    ) -> Result<VaultSession, JsError> {
        Ok(Self {
            inner: Session::create_protected(&creation.inner, password_key).map_err(err)?,
        })
    }

    /// Open a v2 envelope with the Argon2id output for its password slot.
    #[wasm_bindgen(js_name = openWithPasswordKey)]
    pub fn open_with_password_key(
        bytes: &[u8],
        password_key: &[u8],
    ) -> Result<VaultSession, JsError> {
        Ok(Self {
            inner: Session::open_with_password_key(bytes, password_key).map_err(err)?,
        })
    }

    #[wasm_bindgen(js_name = openWithRecovery)]
    pub fn open_with_recovery(bytes: &[u8], code: &str) -> Result<VaultSession, JsError> {
        Ok(Self {
            inner: Session::open_with_recovery(bytes, code).map_err(err)?,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn protected(&self) -> Result<bool, JsError> {
        self.inner.is_protected().map_err(err)
    }

    #[wasm_bindgen(js_name = recoveryConfirmed)]
    pub fn recovery_confirmed(&self) -> Result<bool, JsError> {
        self.inner.recovery_confirmed().map_err(err)
    }

    /// The recovery code waiting for confirmation (shown to the user).
    #[wasm_bindgen(js_name = shownRecoveryCode)]
    pub fn shown_recovery_code(&self) -> Result<String, JsError> {
        Ok(self
            .inner
            .shown_recovery_code()
            .map_err(err)?
            .as_str()
            .to_owned())
    }

    #[wasm_bindgen(js_name = confirmRecovery)]
    pub fn confirm_recovery(&mut self, code: &str) -> Result<(), JsError> {
        self.inner.confirm_recovery(code).map_err(err)
    }

    #[wasm_bindgen(js_name = currentPasswordRequest)]
    pub fn current_password_request(&self) -> Result<String, JsError> {
        json(&self.inner.current_password_request().map_err(err)?)
    }

    #[wasm_bindgen(js_name = beginPasswordChange)]
    pub fn begin_password_change(&mut self) -> Result<String, JsError> {
        json(&self.inner.begin_password_change().map_err(err)?)
    }

    #[wasm_bindgen(js_name = changePasswordWithKey)]
    pub fn change_password_with_key(
        &mut self,
        current_key: &[u8],
        new_key: &[u8],
    ) -> Result<(), JsError> {
        self.inner
            .change_password_with_key(current_key, new_key)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = changePasswordWithRecovery)]
    pub fn change_password_with_recovery(
        &mut self,
        code: &str,
        new_key: &[u8],
    ) -> Result<(), JsError> {
        self.inner
            .change_password_with_recovery(code, new_key)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = beginRecoveryChange)]
    pub fn begin_recovery_change(&mut self, current_key: &[u8]) -> Result<(), JsError> {
        self.inner.begin_recovery_change(current_key).map_err(err)
    }

    #[wasm_bindgen(js_name = finishRecoveryChange)]
    pub fn finish_recovery_change(&mut self, code: &str) -> Result<(), JsError> {
        self.inner.finish_recovery_change(code).map_err(err)
    }

    /// Data-key rotation: authority is the current password's key; `new_key`
    /// is derived for `beginPasswordChange`'s request. The new recovery code
    /// is then shown by `shownRecoveryCode`.
    #[wasm_bindgen(js_name = beginRotation)]
    pub fn begin_rotation(&mut self, current_key: &[u8], new_key: &[u8]) -> Result<(), JsError> {
        self.inner.begin_rotation(current_key, new_key).map_err(err)
    }

    /// The new code typed back: switch to the rotated vault (then seal,
    /// store with CAS and commit, or `rollback`).
    #[wasm_bindgen(js_name = finishRotation)]
    pub fn finish_rotation(&mut self, code: &str) -> Result<(), JsError> {
        self.inner.finish_rotation(code).map_err(err)
    }

    #[wasm_bindgen(js_name = cancelRotation)]
    pub fn cancel_rotation(&mut self) {
        self.inner.cancel_rotation();
    }

    #[wasm_bindgen(js_name = rotationPending)]
    pub fn rotation_pending(&self) -> bool {
        self.inner.rotation_pending()
    }

    #[wasm_bindgen(js_name = cancelRecoveryChange)]
    pub fn cancel_recovery_change(&mut self) {
        self.inner.cancel_recovery_change();
    }

    /// Back to the last committed state after a failed or cancelled write.
    pub fn rollback(&mut self) -> Result<(), JsError> {
        self.inner.rollback().map_err(err)
    }

    /// v2: encrypt the next revision; persist `bytes`, then call `commit`.
    #[wasm_bindgen(js_name = sealProtected)]
    pub fn seal_protected(&mut self) -> Result<SealedVault, JsError> {
        let (bytes, revision) = self.inner.seal_protected().map_err(err)?;
        Ok(SealedVault { bytes, revision })
    }

    /// Drop all decrypted state; every later call fails.
    pub fn lock(&mut self) {
        self.inner.lock();
    }

    #[wasm_bindgen(getter)]
    pub fn locked(&self) -> bool {
        self.inner.is_locked()
    }

    pub fn revision(&self) -> Result<f64, JsError> {
        self.inner.revision().map(|r| r as f64).map_err(err)
    }

    #[wasm_bindgen(js_name = vaultId)]
    pub fn vault_id(&self) -> Result<String, JsError> {
        self.inner.vault_id().map_err(err)
    }

    /// JSON array of item summaries.
    pub fn list(&self, query: &str, kind: &str) -> Result<String, JsError> {
        json(&self.inner.list(query, kind).map_err(err)?)
    }

    /// JSON item view with secrets masked.
    pub fn get(&self, id: &str) -> Result<String, JsError> {
        json(&self.inner.get(id).map_err(err)?)
    }

    /// Plaintext of one secret slot (explicit reveal/copy only).
    pub fn reveal(&self, id: &str, key: &str) -> Result<String, JsError> {
        Ok(self.inner.reveal(id, key).map_err(err)?.as_str().to_owned())
    }

    #[wasm_bindgen(js_name = createItem)]
    pub fn create_item(&mut self, input_json: &str) -> Result<String, JsError> {
        self.inner
            .create_item(parse_input(input_json)?)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = updateItem)]
    pub fn update_item(&mut self, id: &str, input_json: &str) -> Result<(), JsError> {
        self.inner
            .update_item(id, parse_input(input_json)?)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = deleteItem)]
    pub fn delete_item(&mut self, id: &str) -> Result<(), JsError> {
        self.inner.delete_item(id).map_err(err)
    }

    #[wasm_bindgen(js_name = createTotp)]
    pub fn create_totp(
        &mut self,
        title: &str,
        input: &str,
        issuer: &str,
        account: &str,
    ) -> Result<String, JsError> {
        self.inner
            .create_totp(title, input, issuer, account)
            .map_err(err)
    }

    /// TOTP code at `unix_seconds` (caller-supplied clock).
    #[wasm_bindgen(js_name = totpCode)]
    pub fn totp_code(&self, id: &str, unix_seconds: f64) -> Result<TotpNow, JsError> {
        if !(unix_seconds.is_finite() && unix_seconds >= 0.0) {
            return Err(JsError::new("invalid time"));
        }
        let (code, remaining) = self
            .inner
            .totp_code(id, unix_seconds.floor() as u64)
            .map_err(err)?;
        Ok(TotpNow { code, remaining })
    }

    #[wasm_bindgen(js_name = generateEd25519)]
    pub fn generate_ed25519(&mut self, title: &str, comment: &str) -> Result<String, JsError> {
        self.inner.generate_ed25519(title, comment).map_err(err)
    }

    /// Sign the exact bytes of `message` (`encoding`: "utf8" | "hex") with
    /// Ed25519 item `id`; JSON `{hex, base58, message_bytes}`.
    #[wasm_bindgen(js_name = signEd25519)]
    pub fn sign_ed25519(&self, id: &str, message: &str, encoding: &str) -> Result<String, JsError> {
        json(
            &self
                .inner
                .sign_ed25519(id, message, encoding)
                .map_err(err)?,
        )
    }

    #[wasm_bindgen(js_name = generateSecretItem)]
    pub fn generate_secret_item(
        &mut self,
        title: &str,
        n_bytes: u32,
        encoding: &str,
        service: &str,
    ) -> Result<String, JsError> {
        self.inner
            .generate_secret_item(title, n_bytes as usize, encoding, service)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = generatePasswordItem)]
    pub fn generate_password_item(
        &mut self,
        title: &str,
        profile: &str,
        service: &str,
    ) -> Result<String, JsError> {
        self.inner
            .generate_password_item(title, profile, service)
            .map_err(err)
    }

    /// `options` is JSON `PasswordOptions` (see `passwordPolicySummary`).
    #[wasm_bindgen(js_name = generatePasswordItemWithOptions)]
    pub fn generate_password_item_with_options(
        &mut self,
        title: &str,
        options: &str,
        service: &str,
    ) -> Result<String, JsError> {
        self.inner
            .generate_password_item_with(title, options, service)
            .map_err(err)
    }

    /// Generate a password with `options` (JSON `PasswordOptions`) and keep
    /// it as the current preview; returns the value to show.
    #[wasm_bindgen(js_name = previewPassword)]
    pub fn preview_password(&mut self, options: &str) -> Result<String, JsError> {
        Ok(self
            .inner
            .preview_password(options)
            .map_err(err)?
            .as_str()
            .to_owned())
    }

    /// Generate a passphrase (JSON `{words, separator}`) and keep it as the
    /// current preview; save with `savePreview("passphrase", …)`.
    #[wasm_bindgen(js_name = previewPassphrase)]
    pub fn preview_passphrase(&mut self, options: &str) -> Result<String, JsError> {
        Ok(self
            .inner
            .preview_passphrase(options)
            .map_err(err)?
            .as_str()
            .to_owned())
    }

    /// Generate an encoded random secret and keep it as the current preview.
    #[wasm_bindgen(js_name = previewSecret)]
    pub fn preview_secret(&mut self, n_bytes: u32, encoding: &str) -> Result<String, JsError> {
        Ok(self
            .inner
            .preview_secret(n_bytes as usize, encoding)
            .map_err(err)?
            .as_str()
            .to_owned())
    }

    /// Store exactly the shown preview (`kind`: "password" | "secret") as a
    /// generated Secret item; refused if it was replaced or already saved.
    #[wasm_bindgen(js_name = savePreview)]
    pub fn save_preview(
        &mut self,
        kind: &str,
        shown: &str,
        title: &str,
        service: &str,
    ) -> Result<String, JsError> {
        self.inner
            .save_preview(kind, shown, title, service)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = discardPreviews)]
    pub fn discard_previews(&mut self) {
        self.inner.discard_previews();
    }

    /// Encrypt the next revision; persist `bytes`, then call `commit`.
    pub fn seal(&mut self, key: &DemoKeyProvider) -> Result<SealedVault, JsError> {
        let (bytes, revision) = self.inner.seal(&key.inner).map_err(err)?;
        Ok(SealedVault { bytes, revision })
    }

    pub fn commit(&mut self, revision: f64) -> Result<(), JsError> {
        if !(revision.is_finite() && revision >= 1.0 && revision.fract() == 0.0) {
            return Err(JsError::new("invalid revision"));
        }
        self.inner.commit(revision as u64).map_err(err)
    }
}

/// Argon2id parameters (JSON `{salt, mKib, t, p}`) of a stored v2 envelope's
/// password slot; bounds are checked first. No secret.
#[wasm_bindgen(js_name = passwordRequest)]
pub fn password_request(bytes: &[u8]) -> Result<String, JsError> {
    json(&bridge::password_request(bytes).map_err(err)?)
}

/// Argon2id of `password` for a request from `passwordRequest`,
/// `ProtectedCreation.request` or `beginPasswordChange`. Runs in the KDF
/// worker; re-validates the bounds before allocating.
#[wasm_bindgen(js_name = deriveArgon2id)]
pub fn derive_argon2id(password: &str, request: &str) -> Result<Vec<u8>, JsError> {
    Ok(bridge::derive_password_key(password, request)
        .map_err(err)?
        .to_vec())
}

/// Throws when `password` is not acceptable as a new master password.
#[wasm_bindgen(js_name = checkNewPassword)]
pub fn check_new_password(password: &str) -> Result<(), JsError> {
    bridge::check_new_password(password).map_err(err)
}

/// Header of an envelope (no decryption): JSON `{version, vault_id, kek_id, revision}`.
#[wasm_bindgen(js_name = inspectEnvelope)]
pub fn inspect_envelope(bytes: &[u8]) -> Result<String, JsError> {
    json(&bridge::inspect_envelope(bytes).map_err(err)?)
}

/// Password for filling a form field (shown to the user by design).
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(profile: &str, length: u32, alphabet: &str) -> Result<String, JsError> {
    Ok(bridge::gen_password(profile, length as usize, alphabet)
        .map_err(err)?
        .expose()
        .to_owned())
}

/// Password from JSON `PasswordOptions` `{length, lowercase, uppercase,
/// digits, symbols, symbolSet, excludeAmbiguous, requireEachClass}`.
#[wasm_bindgen(js_name = generatePasswordWithOptions)]
pub fn generate_password_with_options(options: &str) -> Result<String, JsError> {
    Ok(bridge::gen_password_with(options)
        .map_err(err)?
        .expose()
        .to_owned())
}

/// Validate `PasswordOptions` without generating; JSON `{length,
/// alphabetSize, classes, upperBoundBits, minEntropyBits}`. The floor is
/// checked against `minEntropyBits` (exact min-entropy of the output);
/// `upperBoundBits` is only a theoretical upper bound.
#[wasm_bindgen(js_name = passwordPolicySummary)]
pub fn password_policy_summary(options: &str) -> Result<String, JsError> {
    json(&bridge::password_policy_summary(options).map_err(err)?)
}

#[wasm_bindgen(js_name = generateRandomSecret)]
pub fn generate_random_secret(n_bytes: u32, encoding: &str) -> Result<String, JsError> {
    Ok(bridge::gen_secret(n_bytes as usize, encoding)
        .map_err(err)?
        .expose()
        .to_owned())
}

/// Strict Ed25519 verification; returns "valid" | "invalid" |
/// "bad_public_key" | "bad_signature" | "bad_message". Needs no vault.
#[wasm_bindgen(js_name = verifyEd25519)]
pub fn verify_ed25519(public_key: &str, message: &str, encoding: &str, signature: &str) -> String {
    match bridge::verify_ed25519(public_key, message, encoding, signature) {
        bridge::Verdict::Valid => "valid",
        bridge::Verdict::Invalid => "invalid",
        bridge::Verdict::BadPublicKey => "bad_public_key",
        bridge::Verdict::BadSignature => "bad_signature",
        bridge::Verdict::BadMessage => "bad_message",
    }
    .into()
}

/// The exact bytes of a message: JSON `{bytes, hex, truncated}`.
#[wasm_bindgen(js_name = messagePreview)]
pub fn message_preview(message: &str, encoding: &str) -> Result<String, JsError> {
    json(&bridge::message_preview(message, encoding).map_err(err)?)
}

/// Passphrase from JSON `{words, separator: "space" | "period"}` (EFF Long Wordlist).
#[wasm_bindgen(js_name = generatePassphrase)]
pub fn generate_passphrase(options: &str) -> Result<String, JsError> {
    Ok(bridge::gen_passphrase(options)
        .map_err(err)?
        .expose()
        .to_owned())
}

/// JSON `{words, list_size, entropy_bits, master_ok}`; draws nothing.
#[wasm_bindgen(js_name = passphraseSummary)]
pub fn passphrase_summary(options: &str) -> Result<String, JsError> {
    json(&bridge::passphrase_summary(options).map_err(err)?)
}

#[wasm_bindgen(js_name = maxEnvelopeBytes)]
pub fn max_envelope_bytes() -> u32 {
    bridge::MAX_ENVELOPE_BYTES as u32
}

#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}
