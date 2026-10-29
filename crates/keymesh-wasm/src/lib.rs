//! `wasm-bindgen` adapter for the Keymesh core — **SYNTHETIC DEMO ONLY, NOT
//! PRODUCTION READY.**
//!
//! Exposes a key-provider handle (development-only, memory-only), a vault
//! session, generators and envelope inspection. Errors carry the core's
//! messages, which never include secret values. All logic lives in
//! [`bridge`]; this file only converts types.

pub mod bridge;

use bridge::{DemoKey, ItemInput, Session};
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

/// Header of an envelope (no decryption): JSON `{vault_id, kek_id, revision}`.
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

#[wasm_bindgen(js_name = maxEnvelopeBytes)]
pub fn max_envelope_bytes() -> u32 {
    bridge::MAX_ENVELOPE_BYTES as u32
}

#[wasm_bindgen(js_name = coreVersion)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}
