//! Platform-neutral bridge logic. Everything here is plain Rust so it is
//! unit-tested natively; `lib.rs` only adapts it to `wasm-bindgen`.
//!
//! Secrets stay inside this module's memory. Item *views* sent to the UI
//! contain non-secret fields plus a list of masked secret slots; plaintext of
//! a slot crosses the boundary only through an explicit [`Session::reveal`].
//! Ed25519 private seeds are never revealed. Signing happens here, on an
//! explicit request for one stored key and exact message bytes; only the
//! signature leaves.

use keymesh::crypto::{EphemeralKeyProvider, Key256, KeyProvider};
use keymesh::ed25519::{self, Ed25519KeyPair, MessageEncoding};
use keymesh::generate::{
    generate_password, generate_secret, PasswordOptions, PasswordPolicy, PasswordProfile,
    PolicySummary, SecretEncoding,
};
use keymesh::kdf::{self, KdfParams};
use keymesh::keyslot::{Authority, PasswordSetup, PRF_LEN};
use keymesh::model::{
    Contact, CryptoWalletRecord, CustomField, Ed25519KeyRecord, FieldKind, Item, ItemData, ItemId,
    ItemKind, LabeledValue, Login, SecretCredential, SecretFormat, SecretOrigin, SecureNote,
    TotpRecord,
};
use keymesh::passphrase::{self, PassphraseOptions, PassphraseSummary};
use keymesh::recovery::RecoveryCode;
use keymesh::rng::OsRandom;
use keymesh::secret::SecretString;
use keymesh::totp::{code_now, parse_base32_secret, parse_otpauth_uri, FixedClock, TotpConfig};
use keymesh::vault::{
    password_request as envelope_password_request, prf_request as envelope_prf_request,
    read_header, PendingPrf, PendingRecovery, PendingRotation, PrfRequest, ProtectedSetup, Vault,
};
use keymesh::{Error, Result};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Same bound as native storage: the browser refuses larger envelopes.
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Development-only key providers
// ---------------------------------------------------------------------------

/// **DEVELOPMENT ONLY.** Key providers for the browser demo. The key lives in
/// WASM memory only and is never exported to JavaScript.
pub enum DemoKey {
    /// Random per page session; lost on reload (the stored vault then cannot
    /// be decrypted again).
    Ephemeral(EphemeralKeyProvider),
    /// Publicly known synthetic fixture key, so a demo vault can be reopened
    /// after a reload and in tests. Anyone can decrypt data under this key.
    Fixture(FixtureKeyProvider),
}

impl DemoKey {
    pub const EPHEMERAL_ID: &'static str = "browser-ephemeral-demo-v1";

    pub fn ephemeral() -> Result<Self> {
        Ok(Self::Ephemeral(EphemeralKeyProvider::generate(
            Self::EPHEMERAL_ID,
            &mut OsRandom,
        )?))
    }
    pub fn fixture() -> Self {
        Self::Fixture(FixtureKeyProvider::new())
    }
    pub fn provider(&self) -> &dyn KeyProvider {
        match self {
            Self::Ephemeral(p) => p,
            Self::Fixture(p) => p,
        }
    }
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Ephemeral(_) => "ephemeral",
            Self::Fixture(_) => "synthetic-fixture",
        }
    }
}

/// PUBLIC synthetic fixture key: SHA-256 of a published label. Not a secret.
pub struct FixtureKeyProvider {
    key: Key256,
}

impl FixtureKeyProvider {
    pub const KEY_ID: &'static str = "synthetic-fixture-v1";
    pub const LABEL: &'static [u8] = b"keymesh synthetic fixture key v1 - PUBLIC, NOT SECRET";

    fn new() -> Self {
        use sha2::{Digest, Sha256};
        Self {
            key: Key256::from_bytes(Sha256::digest(Self::LABEL).into()),
        }
    }
}

impl KeyProvider for FixtureKeyProvider {
    fn key_id(&self) -> &str {
        Self::KEY_ID
    }
    fn key_encryption_key(&self) -> Result<Key256> {
        Ok(self.key.clone())
    }
}

// ---------------------------------------------------------------------------
// Inputs from the UI
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabeledInput {
    pub label: Option<String>,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomFieldInput {
    pub label: String,
    #[serde(default)]
    pub concealed: bool,
    /// New value. On update, `None` with `existing` keeps that field's value.
    pub value: Option<String>,
    /// Index of the existing custom field this row edits (update only).
    pub existing: Option<usize>,
}

/// Secret-ish optional fields use "keep / clear / set" semantics on update:
/// `None` = keep (create: absent), `Some("")` = clear, `Some(v)` = set.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DataInput {
    Login {
        username: Option<String>,
        password: Option<String>,
        #[serde(default)]
        urls: Vec<String>,
        totp_item: Option<String>,
        recovery_codes: Option<Vec<String>>,
    },
    Secret {
        secret: Option<String>,
        username: Option<String>,
        service: Option<String>,
    },
    Contact {
        full_name: Option<String>,
        organization: Option<String>,
        #[serde(default)]
        emails: Vec<LabeledInput>,
        #[serde(default)]
        phones: Vec<LabeledInput>,
        #[serde(default)]
        addresses: Vec<LabeledInput>,
        #[serde(default)]
        websites: Vec<LabeledInput>,
    },
    CryptoWallet {
        wallet_software: Option<String>,
        network: Option<String>,
        #[serde(default)]
        addresses: Vec<LabeledInput>,
        recovery_phrase: Option<String>,
        wallet_password: Option<String>,
        private_key: Option<String>,
        derivation_path: Option<String>,
    },
    SecureNote {
        body: Option<String>,
    },
    /// Update only: TOTP secrets are set via [`Session::create_totp`].
    Totp {
        issuer: Option<String>,
        account_name: Option<String>,
    },
    /// Update only: keys are generated via [`Session::generate_ed25519`].
    Ed25519Key {
        comment: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemInput {
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
    pub data: DataInput,
}

fn text(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// keep / clear / set for secrets.
fn secret_update(new: Option<String>, old: Option<&SecretString>) -> Option<SecretString> {
    match new {
        None => old.cloned(),
        Some(v) if v.is_empty() => None,
        Some(v) => Some(SecretString::new(v)),
    }
}

fn labeled(v: Vec<LabeledInput>) -> Vec<LabeledValue> {
    v.into_iter()
        .filter(|l| !l.value.is_empty())
        .map(|l| LabeledValue {
            label: text(l.label),
            value: l.value,
        })
        .collect()
}

fn parse_id(s: &str) -> Result<ItemId> {
    s.parse()
}

// ---------------------------------------------------------------------------
// Views to the UI (no secret values)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct Summary {
    pub id: String,
    pub kind: &'static str,
    pub title: String,
    pub subtitle: Option<String>,
    /// Login items only: the first URL, so the list can pick a local icon.
    /// Non-secret (URLs are shown in the item view and searched already).
    pub url: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretSlot {
    /// Opaque key for [`Session::reveal`].
    pub key: String,
    pub label: String,
}

#[derive(Debug, Serialize)]
pub struct CustomView {
    pub index: usize,
    pub label: String,
    pub section: Option<String>,
    pub concealed: bool,
    /// Present only for non-concealed fields.
    pub value: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ItemView {
    pub id: String,
    pub kind: &'static str,
    pub rev: u64,
    pub title: String,
    pub tags: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub imported: bool,
    /// Non-secret, kind-specific data.
    pub data: serde_json::Value,
    pub secrets: Vec<SecretSlot>,
    pub custom_fields: Vec<CustomView>,
}

fn is_concealed(k: FieldKind) -> bool {
    matches!(
        k,
        FieldKind::Concealed | FieldKind::Otp | FieldKind::Unsupported
    )
}

fn slot(key: &str, label: &str) -> SecretSlot {
    SecretSlot {
        key: key.into(),
        label: label.into(),
    }
}

fn subtitle(i: &Item) -> Option<String> {
    match &i.data {
        ItemData::Login(l) => l.username.clone().or_else(|| l.urls.first().cloned()),
        ItemData::Secret(s) => s.service.clone().or_else(|| s.username.clone()),
        ItemData::Contact(c) => c
            .organization
            .clone()
            .or_else(|| c.emails.first().map(|e| e.value.clone())),
        ItemData::CryptoWallet(w) => w.network.clone(),
        ItemData::Totp(t) => t.issuer.clone().or_else(|| t.account_name.clone()),
        ItemData::Ed25519Key(k) => k.comment.clone(),
        ItemData::SecureNote(_) => None,
    }
}

fn matches(i: &Item, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    let hit = |s: &str| s.to_lowercase().contains(q);
    let lv = |v: &[LabeledValue]| v.iter().any(|x| hit(&x.value));
    hit(&i.title)
        || i.tags.iter().any(|t| hit(t))
        || match &i.data {
            ItemData::Login(l) => {
                l.username.as_deref().is_some_and(hit) || l.urls.iter().any(|u| hit(u))
            }
            ItemData::Secret(s) => {
                s.service.as_deref().is_some_and(hit) || s.username.as_deref().is_some_and(hit)
            }
            ItemData::Contact(c) => {
                c.full_name.as_deref().is_some_and(hit)
                    || c.organization.as_deref().is_some_and(hit)
                    || lv(&c.emails)
                    || lv(&c.phones)
                    || lv(&c.websites)
            }
            ItemData::CryptoWallet(w) => {
                w.network.as_deref().is_some_and(hit)
                    || w.wallet_software.as_deref().is_some_and(hit)
                    || lv(&w.addresses)
            }
            ItemData::Totp(t) => {
                t.issuer.as_deref().is_some_and(hit) || t.account_name.as_deref().is_some_and(hit)
            }
            ItemData::Ed25519Key(k) => k.comment.as_deref().is_some_and(hit),
            ItemData::SecureNote(_) => false,
        }
}

fn kind_from(s: &str) -> Option<ItemKind> {
    Some(match s {
        "login" => ItemKind::Login,
        "secret" => ItemKind::Secret,
        "contact" => ItemKind::Contact,
        "crypto_wallet" => ItemKind::CryptoWallet,
        "ed25519_key" => ItemKind::Ed25519Key,
        "totp" => ItemKind::Totp,
        "secure_note" => ItemKind::SecureNote,
        _ => return None,
    })
}

fn view(i: &Item) -> Result<ItemView> {
    use serde_json::json;
    let lvj = |v: &[LabeledValue]| {
        v.iter()
            .map(|x| json!({"label": x.label, "value": x.value}))
            .collect::<Vec<_>>()
    };
    let mut secrets = Vec::new();
    if i.notes.is_some() {
        secrets.push(slot("notes", "Notes"));
    }
    let data = match &i.data {
        ItemData::Login(l) => {
            if l.password.is_some() {
                secrets.push(slot("password", "Password"));
            }
            for n in 0..l.recovery_codes.len() {
                secrets.push(slot(
                    &format!("recovery_code:{n}"),
                    &format!("Recovery code {}", n + 1),
                ));
            }
            json!({"username": l.username, "urls": l.urls,
                   "totp_item": l.totp_item.as_ref().map(|t| t.to_string()),
                   "recovery_code_count": l.recovery_codes.len()})
        }
        ItemData::Secret(s) => {
            secrets.push(slot("secret", "Secret"));
            let format = match s.format {
                SecretFormat::Text => "text",
                SecretFormat::Encoded(SecretEncoding::Hex) => "hex",
                SecretFormat::Encoded(SecretEncoding::Base64Url) => "base64url",
                SecretFormat::Encoded(SecretEncoding::Base32) => "base32",
                SecretFormat::OpaquePrivateKey => "opaque_private_key",
            };
            let origin = match s.origin {
                SecretOrigin::Generated => "generated",
                SecretOrigin::Manual => "manual",
                SecretOrigin::Imported => "imported",
            };
            json!({"username": s.username, "service": s.service,
                   "format": format, "origin": origin})
        }
        ItemData::Contact(c) => json!({
            "full_name": c.full_name, "organization": c.organization,
            "emails": lvj(&c.emails), "phones": lvj(&c.phones),
            "addresses": lvj(&c.addresses), "websites": lvj(&c.websites)}),
        ItemData::CryptoWallet(w) => {
            if w.recovery_phrase.is_some() {
                secrets.push(slot("recovery_phrase", "Recovery phrase"));
            }
            if w.wallet_password.is_some() {
                secrets.push(slot("wallet_password", "Wallet password"));
            }
            if w.private_key.is_some() {
                secrets.push(slot("private_key", "Private key"));
            }
            json!({"wallet_software": w.wallet_software, "network": w.network,
                   "addresses": lvj(&w.addresses), "derivation_path": w.derivation_path})
        }
        ItemData::Totp(t) => {
            secrets.push(slot("totp_secret", "Setup secret (Base32)"));
            json!({"issuer": t.issuer, "account_name": t.account_name,
                   "algorithm": t.config.algorithm.as_str(), "digits": t.config.digits,
                   "period": t.config.period})
        }
        ItemData::Ed25519Key(k) => json!({
            "comment": k.comment,
            "public_key_hex": k.key.public_key_hex,
            "public_key_base58": k.key.public_key_base58()?,
            "openssh": k.key.openssh_public_key(k.comment.as_deref())?}),
        ItemData::SecureNote(_) => {
            secrets.push(slot("body", "Note"));
            json!({})
        }
    };
    let custom_fields = i
        .custom_fields
        .iter()
        .enumerate()
        .map(|(n, f)| {
            let concealed = is_concealed(f.kind);
            if concealed {
                secrets.push(slot(&format!("custom:{n}"), &f.label));
            }
            CustomView {
                index: n,
                label: f.label.clone(),
                section: f.section.clone(),
                concealed,
                value: (!concealed).then(|| f.value.expose().to_owned()),
            }
        })
        .collect();
    Ok(ItemView {
        id: i.id.to_string(),
        kind: i.kind().as_str(),
        rev: i.rev,
        title: i.title.clone(),
        tags: i.tags.clone(),
        created_at: i.created_at,
        updated_at: i.updated_at,
        imported: i.source.is_some(),
        data,
        secrets,
        custom_fields,
    })
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct EnvelopeInfo {
    /// 1: demo key provider; 2: password + recovery key slots.
    pub version: u32,
    pub vault_id: String,
    /// v1 only.
    pub kek_id: Option<String>,
    pub revision: u64,
}

pub fn inspect_envelope(bytes: &[u8]) -> Result<EnvelopeInfo> {
    check_size(bytes)?;
    let h = read_header(bytes)?;
    Ok(EnvelopeInfo {
        version: h.version,
        vault_id: h.vault_id,
        kek_id: h.kek_id,
        revision: h.revision,
    })
}

// ---------------------------------------------------------------------------
// Password key derivation (run by the browser in a worker)
// ---------------------------------------------------------------------------

/// Public Argon2id parameters for one password slot. Sent to the KDF worker;
/// contains no secret.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KdfRequest {
    pub salt: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfRequest {
    fn of(setup: &PasswordSetup) -> Self {
        Self {
            salt: data_encoding::BASE64URL_NOPAD.encode(&setup.salt),
            m_kib: setup.params.m_kib,
            t: setup.params.t,
            p: setup.params.p,
        }
    }
}

/// Parameters for unlocking a stored v2 envelope (bounds already checked).
pub fn password_request(bytes: &[u8]) -> Result<KdfRequest> {
    check_size(bytes)?;
    Ok(KdfRequest::of(&envelope_password_request(bytes)?.setup))
}

/// Argon2id for a [`KdfRequest`]. The request is re-validated here (the
/// worker trusts nothing it is sent) before any memory is allocated.
pub fn derive_password_key(password: &str, request_json: &str) -> Result<Zeroizing<[u8; 32]>> {
    if request_json.len() > 512 {
        return Err(Error::Format("invalid key derivation request".into()));
    }
    let r: KdfRequest = serde_json::from_str(request_json)
        .map_err(|_| Error::Format("invalid key derivation request".into()))?;
    let salt = data_encoding::BASE64URL_NOPAD
        .decode(r.salt.as_bytes())
        .map_err(|_| Error::Format("invalid key derivation request".into()))?;
    kdf::argon2id(
        password,
        &salt,
        KdfParams {
            m_kib: r.m_kib,
            t: r.t,
            p: r.p,
        },
    )
}

/// NIST SP 800-63B-4 checks for a new master password.
pub fn check_new_password(password: &str) -> Result<()> {
    kdf::check_new_password(password)
}

fn key32(b: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let arr: [u8; 32] = b
        .try_into()
        .map_err(|_| Error::Validation("derived key must be 32 bytes".into()))?;
    Ok(Zeroizing::new(arr))
}

/// A vault about to be created: fixed id and password slot parameters, so
/// the derived key the browser returns is for exactly this setup.
pub struct ProtectedCreation {
    setup: ProtectedSetup,
}

impl ProtectedCreation {
    pub fn new() -> Result<Self> {
        Ok(Self {
            setup: ProtectedSetup::generate(&mut OsRandom)?,
        })
    }
    pub fn request(&self) -> KdfRequest {
        KdfRequest::of(&self.setup.password)
    }
}

fn check_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::Format("vault exceeds the maximum size".into()));
    }
    Ok(())
}

fn locked() -> Error {
    Error::Validation("vault is locked".into())
}

/// An unlocked vault plus the key provider used to seal it. `lock` drops the
/// decrypted vault (items and data key); every later call fails.
pub struct Session {
    vault: Option<Vault>,
    /// State as of the last persisted (or opened) envelope. A change that
    /// cannot be sealed is rolled back to it, so memory never diverges from
    /// what can be stored.
    committed: Option<Vault>,
    /// Revision produced by the last [`Session::seal`], awaiting commit.
    pending: Option<u64>,
    /// Same bound as [`Session::open`]; smaller only in tests.
    max_bytes: usize,
    /// Values shown to the user before saving; see [`Session::save_preview`].
    previews: Previews,
    /// v2: the code of a NEW vault, shown until it is confirmed.
    new_code: Option<RecoveryCode>,
    /// v2: password slot parameters for a pending password change.
    pending_password: Option<PasswordSetup>,
    /// v2: a replacement recovery code waiting for confirmation.
    pending_recovery: Option<PendingRecovery>,
    /// v2: a data-key rotation waiting for its new recovery code.
    pending_rotation: Option<PendingRotation>,
    /// v2: a quick-unlock enrolment in progress (bound to this vault state).
    pending_prf: Option<PendingPrf>,
}

/// The latest generated-but-unsaved value per generator. Zeroized on drop,
/// replaced by every new preview and dropped on lock.
#[derive(Default)]
struct Previews {
    password: Option<SecretString>,
    passphrase: Option<SecretString>,
    secret: Option<(SecretString, SecretEncoding)>,
}

impl Session {
    fn with_vault(vault: Vault) -> Self {
        Self {
            committed: Some(vault.clone()),
            vault: Some(vault),
            pending: None,
            max_bytes: MAX_ENVELOPE_BYTES,
            previews: Previews::default(),
            new_code: None,
            pending_password: None,
            pending_recovery: None,
            pending_rotation: None,
            pending_prf: None,
        }
    }

    pub fn create(key: &DemoKey) -> Result<Self> {
        Ok(Self::with_vault(Vault::create(
            key.provider(),
            &mut OsRandom,
        )?))
    }

    /// Decrypt an envelope. Fails closed on wrong key, corruption, unknown
    /// format or oversize input.
    pub fn open(bytes: &[u8], key: &DemoKey) -> Result<Self> {
        check_size(bytes)?;
        Ok(Self::with_vault(Vault::decrypt(bytes, key.provider())?))
    }

    #[cfg(test)]
    fn set_max_bytes_for_tests(&mut self, n: usize) {
        self.max_bytes = n;
    }

    pub fn lock(&mut self) {
        self.vault = None;
        self.committed = None;
        self.pending = None;
        self.previews = Previews::default();
        self.new_code = None;
        self.pending_password = None;
        self.pending_recovery = None;
        self.pending_rotation = None;
        self.pending_prf = None;
    }

    // --- v2: password + recovery --------------------------------------------

    /// New empty password vault for `creation` and the browser-derived key.
    /// The recovery code is available from [`Session::shown_recovery_code`]
    /// until [`Session::confirm_recovery`]; sealing is refused before that.
    pub fn create_protected(creation: &ProtectedCreation, password_key: &[u8]) -> Result<Self> {
        let key = key32(password_key)?;
        let (vault, code) = Vault::create_protected(&creation.setup, &key, &mut OsRandom)?;
        let mut s = Self::with_vault(vault);
        s.new_code = Some(code);
        Ok(s)
    }

    pub fn open_with_password_key(bytes: &[u8], password_key: &[u8]) -> Result<Self> {
        check_size(bytes)?;
        let key = key32(password_key)?;
        Ok(Self::with_vault(Vault::open_with_password_key(
            bytes, &key,
        )?))
    }

    pub fn open_with_recovery(bytes: &[u8], code: &str) -> Result<Self> {
        check_size(bytes)?;
        let code = RecoveryCode::parse(code)?;
        Ok(Self::with_vault(Vault::open_with_recovery(bytes, &code)?))
    }

    pub fn is_protected(&self) -> Result<bool> {
        Ok(self.v()?.is_protected())
    }

    pub fn recovery_confirmed(&self) -> Result<bool> {
        Ok(self.v()?.recovery_confirmed())
    }

    /// The recovery code waiting to be confirmed (new vault or a pending
    /// replacement), formatted for display.
    pub fn shown_recovery_code(&self) -> Result<Zeroizing<String>> {
        self.v()?;
        match (
            &self.new_code,
            &self.pending_recovery,
            &self.pending_rotation,
        ) {
            (Some(c), _, _) => Ok(c.to_text()),
            (None, _, Some(r)) => Ok(r.code().to_text()),
            (None, Some(p), None) => Ok(p.code().to_text()),
            _ => Err(Error::Validation("no recovery code to show".into())),
        }
    }

    /// Confirm a new vault's recovery code (verified by unwrapping its slot).
    pub fn confirm_recovery(&mut self, code: &str) -> Result<()> {
        let code = RecoveryCode::parse(code)?;
        self.vm()?.confirm_recovery(&code)?;
        self.committed = self.vault.clone();
        self.new_code = None;
        Ok(())
    }

    /// Parameters of the current password slot (to prove the current
    /// password with [`Session::change_password_with_key`]).
    pub fn current_password_request(&self) -> Result<KdfRequest> {
        Ok(KdfRequest::of(&self.v()?.password_setup()?))
    }

    /// Fresh parameters for a new password; the core keeps them so only a
    /// key derived for them is accepted.
    pub fn begin_password_change(&mut self) -> Result<KdfRequest> {
        self.v()?.password_setup()?;
        let setup = PasswordSetup::generate(&mut OsRandom)?;
        let r = KdfRequest::of(&setup);
        self.pending_password = Some(setup);
        Ok(r)
    }

    fn take_password_setup(&mut self) -> Result<PasswordSetup> {
        self.pending_password
            .take()
            .ok_or_else(|| Error::Validation("start the password change first".into()))
    }

    /// Replace the password slot; authority is the CURRENT password's key.
    /// Persist with [`Session::seal_protected`] + commit, or
    /// [`Session::rollback`] if that fails.
    pub fn change_password_with_key(&mut self, current_key: &[u8], new_key: &[u8]) -> Result<()> {
        let setup = self.take_password_setup()?;
        let (cur, new) = (key32(current_key)?, key32(new_key)?);
        self.vm()?
            .change_password(Authority::PasswordKey(&cur), &setup, &new, &mut OsRandom)
    }

    /// Replace the password slot; authority is the recovery code.
    pub fn change_password_with_recovery(&mut self, code: &str, new_key: &[u8]) -> Result<()> {
        let setup = self.take_password_setup()?;
        let code = RecoveryCode::parse(code)?;
        let new = key32(new_key)?;
        self.vm()?
            .change_password(Authority::Recovery(&code), &setup, &new, &mut OsRandom)
    }

    /// Start replacing the recovery code; authority is the current
    /// password's key. The new code is shown via [`Session::shown_recovery_code`].
    pub fn begin_recovery_change(&mut self, current_key: &[u8]) -> Result<()> {
        let cur = key32(current_key)?;
        let p = self
            .v()?
            .begin_recovery_change(Authority::PasswordKey(&cur), &mut OsRandom)?;
        self.pending_recovery = Some(p);
        Ok(())
    }

    pub fn finish_recovery_change(&mut self, code: &str) -> Result<()> {
        let code = RecoveryCode::parse(code)?;
        let matches = self
            .pending_recovery
            .as_ref()
            .ok_or_else(|| Error::Validation("no recovery code change in progress".into()))?
            .code()
            .ct_eq(&code);
        // A mistyped confirmation keeps the pending code so it can be retried.
        if !matches {
            return Err(Error::Validation("recovery code does not match".into()));
        }
        let p = self.pending_recovery.take().expect("checked above");
        self.vm()?.finish_recovery_change(p, &code)
    }

    pub fn cancel_recovery_change(&mut self) {
        self.pending_recovery = None;
    }

    /// Start a data-key rotation (ADR 0002 §8). Authority is the CURRENT
    /// password's key; `new_key` is derived for the parameters from
    /// [`Session::begin_password_change`]. A new recovery code is shown via
    /// [`Session::shown_recovery_code`]. Nothing changes until
    /// [`Session::finish_rotation`]; any pending recovery-code change is
    /// dropped (it would wrap the old data key).
    pub fn begin_rotation(&mut self, current_key: &[u8], new_key: &[u8]) -> Result<()> {
        let setup = self.take_password_setup()?;
        let (cur, new) = (key32(current_key)?, key32(new_key)?);
        let p =
            self.v()?
                .begin_rotation(Authority::PasswordKey(&cur), &setup, &new, &mut OsRandom)?;
        self.pending_recovery = None;
        self.pending_prf = None;
        self.pending_rotation = Some(p);
        Ok(())
    }

    /// The new recovery code was typed back: switch the session to the
    /// rotated vault (new data key and slots). Persist with
    /// [`Session::seal_protected`] + commit; [`Session::rollback`] returns to
    /// the stored (old) state. A mistyped code keeps the rotation pending.
    pub fn finish_rotation(&mut self, code: &str) -> Result<()> {
        let code = RecoveryCode::parse(code)?;
        let p = self
            .pending_rotation
            .as_ref()
            .ok_or_else(|| Error::Validation("no key rotation in progress".into()))?;
        let rotated = self.v()?.finish_rotation(p, &code)?;
        self.pending_rotation = None;
        self.vault = Some(rotated);
        Ok(())
    }

    /// Like [`Session::begin_rotation`], revoking quick-unlock passkeys
    /// (the user confirmed); without it rotation is refused while any exist.
    pub fn begin_rotation_revoking_quick_unlock(
        &mut self,
        current_key: &[u8],
        new_key: &[u8],
    ) -> Result<()> {
        let setup = self.take_password_setup()?;
        let (cur, new) = (key32(current_key)?, key32(new_key)?);
        let p = self.v()?.begin_rotation_revoking_quick_unlock(
            Authority::PasswordKey(&cur),
            &setup,
            &new,
            &mut OsRandom,
        )?;
        self.pending_recovery = None;
        self.pending_rotation = Some(p);
        Ok(())
    }

    // --- v2: quick unlock (webauthn-prf) ----------------------------------

    /// Start enrolling a passkey: the CURRENT password's key is verified
    /// first (no passkey is created for a wrong password), then the core
    /// issues the slot id and PRF input salt (32 random bytes).
    pub fn begin_prf_enrolment(&mut self, current_key: &[u8]) -> Result<PrfEnrolment> {
        let cur = key32(current_key)?;
        let p = self
            .v()?
            .begin_prf(Authority::PasswordKey(&cur), &mut OsRandom)?;
        let e = PrfEnrolment {
            slot_id: p.setup().slot_id.clone(),
            salt: data_encoding::BASE64URL_NOPAD.encode(&p.setup().salt),
            vault_id: self.v()?.vault_id().to_owned(),
        };
        self.pending_prf = Some(p);
        Ok(e)
    }

    /// Finish enrolling: authority is the CURRENT password's key. The new
    /// slot is verified in memory; persist with seal + commit (or rollback).
    pub fn finish_prf_enrolment(
        &mut self,
        current_key: &[u8],
        credential_id: &[u8],
        rp_id: &str,
        be: bool,
        label: &str,
        prf_output: &[u8],
    ) -> Result<()> {
        let pending = self
            .pending_prf
            .take()
            .ok_or_else(|| Error::Validation("start the quick-unlock enrolment first".into()))?;
        let cur = key32(current_key)?;
        let prf = prf32(prf_output)?;
        self.vm()?.add_prf_slot(
            Authority::PasswordKey(&cur),
            &pending,
            credential_id,
            rp_id,
            be,
            label,
            &prf,
            &mut OsRandom,
        )
    }

    pub fn cancel_prf_enrolment(&mut self) {
        self.pending_prf = None;
    }

    pub fn prf_slots(&self) -> Result<Vec<PrfRequest>> {
        self.v()?.prf_slots()
    }

    /// Remove a quick-unlock slot; authority is the CURRENT password's key.
    pub fn remove_prf_slot(&mut self, current_key: &[u8], slot_id: &str) -> Result<()> {
        let cur = key32(current_key)?;
        self.vm()?
            .remove_prf_slot(Authority::PasswordKey(&cur), slot_id)
    }

    /// Open with a quick-unlock assertion (see `Vault::open_with_prf`).
    pub fn open_with_prf(
        bytes: &[u8],
        credential_id: &[u8],
        authenticator_data: &[u8],
        prf_output: &[u8],
        rp_id: &str,
    ) -> Result<Self> {
        check_size(bytes)?;
        let prf = prf32(prf_output)?;
        Ok(Self::with_vault(Vault::open_with_prf(
            bytes,
            credential_id,
            authenticator_data,
            &prf,
            rp_id,
        )?))
    }

    pub fn cancel_rotation(&mut self) {
        self.pending_rotation = None;
    }

    pub fn rotation_pending(&self) -> bool {
        self.pending_rotation.is_some()
    }

    /// Return to the last committed state (a credential change whose write
    /// failed or was cancelled).
    pub fn rollback(&mut self) -> Result<()> {
        self.v()?;
        self.vault = self.committed.clone();
        self.pending = None;
        self.pending_password = None;
        Ok(())
    }

    pub fn is_locked(&self) -> bool {
        self.vault.is_none()
    }

    fn v(&self) -> Result<&Vault> {
        self.vault.as_ref().ok_or_else(locked)
    }

    fn vm(&mut self) -> Result<&mut Vault> {
        self.vault.as_mut().ok_or_else(locked)
    }

    pub fn vault_id(&self) -> Result<String> {
        Ok(self.v()?.vault_id().to_owned())
    }

    pub fn revision(&self) -> Result<u64> {
        Ok(self.v()?.revision())
    }

    pub fn list(&self, query: &str, kind: &str) -> Result<Vec<Summary>> {
        let q = query.trim().to_lowercase();
        let k = if kind.is_empty() {
            None
        } else {
            Some(kind_from(kind).ok_or_else(|| Error::Validation("unknown kind".into()))?)
        };
        let mut out: Vec<Summary> = self
            .v()?
            .items()
            .filter(|i| k.map_or(true, |k| i.kind() == k) && matches(i, &q))
            .map(|i| Summary {
                id: i.id.to_string(),
                kind: i.kind().as_str(),
                title: i.title.clone(),
                subtitle: subtitle(i),
                url: match &i.data {
                    ItemData::Login(l) => l.urls.first().cloned(),
                    _ => None,
                },
                tags: i.tags.clone(),
            })
            .collect();
        out.sort_by_key(|s| s.title.to_lowercase());
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Result<ItemView> {
        view(self.v()?.get(&parse_id(id)?)?)
    }

    /// Plaintext of one secret slot. Ed25519 seeds are not revealable.
    pub fn reveal(&self, id: &str, key: &str) -> Result<Zeroizing<String>> {
        let item = self.v()?.get(&parse_id(id)?)?;
        let none = || Error::Validation("no such secret field".into());
        let s =
            |o: &Option<SecretString>| o.as_ref().map(|v| v.expose().to_owned()).ok_or_else(none);
        let out = match (key, &item.data) {
            ("notes", _) => s(&item.notes)?,
            ("password", ItemData::Login(l)) => s(&l.password)?,
            ("secret", ItemData::Secret(c)) => c.secret.expose().to_owned(),
            ("recovery_phrase", ItemData::CryptoWallet(w)) => s(&w.recovery_phrase)?,
            ("wallet_password", ItemData::CryptoWallet(w)) => s(&w.wallet_password)?,
            ("private_key", ItemData::CryptoWallet(w)) => s(&w.private_key)?,
            ("body", ItemData::SecureNote(n)) => n.body.expose().to_owned(),
            ("totp_secret", ItemData::Totp(t)) => {
                data_encoding::BASE32_NOPAD.encode(t.config.secret.expose())
            }
            (k, ItemData::Login(l)) if k.starts_with("recovery_code:") => {
                let n: usize = k["recovery_code:".len()..].parse().map_err(|_| none())?;
                l.recovery_codes
                    .get(n)
                    .ok_or_else(none)?
                    .expose()
                    .to_owned()
            }
            (k, _) if k.starts_with("custom:") => {
                let n: usize = k["custom:".len()..].parse().map_err(|_| none())?;
                item.custom_fields
                    .get(n)
                    .ok_or_else(none)?
                    .value
                    .expose()
                    .to_owned()
            }
            _ => return Err(none()),
        };
        Ok(Zeroizing::new(out))
    }

    fn custom(input: Vec<CustomFieldInput>, old: &[CustomField]) -> Result<Vec<CustomField>> {
        input
            .into_iter()
            .map(|c| {
                let value = match (c.value, c.existing) {
                    (Some(v), _) => SecretString::new(v),
                    (None, Some(n)) => old
                        .get(n)
                        .ok_or_else(|| Error::Validation("unknown existing field".into()))?
                        .value
                        .clone(),
                    (None, None) => {
                        return Err(Error::Validation("custom field needs a value".into()))
                    }
                };
                Ok(CustomField {
                    section: None,
                    label: c.label,
                    kind: if c.concealed {
                        FieldKind::Concealed
                    } else {
                        FieldKind::Text
                    },
                    source_type: None,
                    value,
                })
            })
            .collect()
    }

    /// Build item data from input, merging with `old` on update.
    fn data(input: DataInput, old: Option<&ItemData>) -> Result<ItemData> {
        let wrong = || Error::Validation("item kind cannot change".into());
        Ok(match input {
            DataInput::Login {
                username,
                password,
                urls,
                totp_item,
                recovery_codes,
            } => {
                let o = match old {
                    Some(ItemData::Login(l)) => Some(l),
                    Some(_) => return Err(wrong()),
                    None => None,
                };
                ItemData::Login(Login {
                    username: text(username),
                    password: secret_update(password, o.and_then(|l| l.password.as_ref())),
                    urls: urls.into_iter().filter(|u| !u.is_empty()).collect(),
                    totp_item: text(totp_item).map(|t| parse_id(&t)).transpose()?,
                    recovery_codes: match recovery_codes {
                        Some(v) => v
                            .into_iter()
                            .filter(|c| !c.is_empty())
                            .map(SecretString::new)
                            .collect(),
                        None => o.map(|l| l.recovery_codes.clone()).unwrap_or_default(),
                    },
                })
            }
            DataInput::Secret {
                secret,
                username,
                service,
            } => {
                let o = match old {
                    Some(ItemData::Secret(s)) => Some(s),
                    Some(_) => return Err(wrong()),
                    None => None,
                };
                let (secret, format, origin) = match (secret.filter(|s| !s.is_empty()), o) {
                    (Some(v), _) => (
                        SecretString::new(v),
                        SecretFormat::Text,
                        SecretOrigin::Manual,
                    ),
                    (None, Some(o)) => (o.secret.clone(), o.format, o.origin),
                    (None, None) => return Err(Error::Validation("secret is required".into())),
                };
                ItemData::Secret(SecretCredential {
                    secret,
                    format,
                    origin,
                    username: text(username),
                    service: text(service),
                    expires_at: o.and_then(|o| o.expires_at),
                })
            }
            DataInput::Contact {
                full_name,
                organization,
                emails,
                phones,
                addresses,
                websites,
            } => {
                if matches!(old, Some(d) if !matches!(d, ItemData::Contact(_))) {
                    return Err(wrong());
                }
                ItemData::Contact(Contact {
                    full_name: text(full_name),
                    organization: text(organization),
                    emails: labeled(emails),
                    phones: labeled(phones),
                    addresses: labeled(addresses),
                    websites: labeled(websites),
                })
            }
            DataInput::CryptoWallet {
                wallet_software,
                network,
                addresses,
                recovery_phrase,
                wallet_password,
                private_key,
                derivation_path,
            } => {
                let o = match old {
                    Some(ItemData::CryptoWallet(w)) => Some(w),
                    Some(_) => return Err(wrong()),
                    None => None,
                };
                ItemData::CryptoWallet(CryptoWalletRecord {
                    wallet_software: text(wallet_software),
                    network: text(network),
                    addresses: labeled(addresses),
                    recovery_phrase: secret_update(
                        recovery_phrase,
                        o.and_then(|w| w.recovery_phrase.as_ref()),
                    ),
                    wallet_password: secret_update(
                        wallet_password,
                        o.and_then(|w| w.wallet_password.as_ref()),
                    ),
                    private_key: secret_update(private_key, o.and_then(|w| w.private_key.as_ref())),
                    derivation_path: text(derivation_path),
                })
            }
            DataInput::SecureNote { body } => {
                let o = match old {
                    Some(ItemData::SecureNote(n)) => Some(n),
                    Some(_) => return Err(wrong()),
                    None => None,
                };
                ItemData::SecureNote(SecureNote {
                    body: match (body, o) {
                        (Some(b), _) => SecretString::new(b),
                        (None, Some(o)) => o.body.clone(),
                        (None, None) => SecretString::new(""),
                    },
                })
            }
            DataInput::Totp {
                issuer,
                account_name,
            } => match old {
                Some(ItemData::Totp(t)) => ItemData::Totp(TotpRecord {
                    config: t.config.clone(),
                    issuer: text(issuer),
                    account_name: text(account_name),
                }),
                Some(_) => return Err(wrong()),
                None => {
                    return Err(Error::Validation(
                        "create TOTP items with create_totp".into(),
                    ))
                }
            },
            DataInput::Ed25519Key { comment } => match old {
                Some(ItemData::Ed25519Key(k)) => ItemData::Ed25519Key(Ed25519KeyRecord {
                    key: k.key.clone(),
                    comment: text(comment),
                }),
                Some(_) => return Err(wrong()),
                None => {
                    return Err(Error::Validation(
                        "generate Ed25519 keys with generate_ed25519".into(),
                    ))
                }
            },
        })
    }

    fn new_item(&mut self, title: String, data: ItemData) -> Result<Item> {
        let _ = self.v()?;
        Item::new(title, data, &mut OsRandom)
    }

    pub fn create_item(&mut self, input: ItemInput) -> Result<String> {
        let data = Self::data(input.data, None)?;
        let mut item = self.new_item(input.title, data)?;
        item.tags = input.tags.into_iter().filter(|t| !t.is_empty()).collect();
        item.notes = text(input.notes).map(SecretString::new);
        item.custom_fields = Self::custom(input.custom_fields, &[])?;
        Ok(self.vm()?.insert(item)?.to_string())
    }

    pub fn update_item(&mut self, id: &str, input: ItemInput) -> Result<()> {
        let id = parse_id(id)?;
        let old = self.v()?.get(&id)?.clone();
        let data = Self::data(input.data, Some(&old.data))?;
        let custom = Self::custom(input.custom_fields, &old.custom_fields)?;
        let notes = secret_update(input.notes, old.notes.as_ref());
        let tags: Vec<String> = input.tags.into_iter().filter(|t| !t.is_empty()).collect();
        self.vm()?.update(&id, |it| {
            it.title = input.title;
            it.tags = tags;
            it.notes = notes;
            it.custom_fields = custom;
            it.data = data;
        })
    }

    pub fn delete_item(&mut self, id: &str) -> Result<()> {
        self.vm()?.remove(&parse_id(id)?).map(|_| ())
    }

    /// TOTP from an `otpauth://totp/...` URI or a Base32 secret.
    pub fn create_totp(
        &mut self,
        title: &str,
        input: &str,
        issuer: &str,
        account: &str,
    ) -> Result<String> {
        let input = input.trim();
        let rec = if input.to_ascii_lowercase().starts_with("otpauth://") {
            let p = parse_otpauth_uri(input)?;
            TotpRecord {
                config: p.config,
                issuer: text(Some(issuer.into())).or(p.issuer),
                account_name: text(Some(account.into())).or(p.account_name),
            }
        } else {
            TotpRecord {
                config: TotpConfig::with_defaults(parse_base32_secret(input)?)?,
                issuer: text(Some(issuer.into())),
                account_name: text(Some(account.into())),
            }
        };
        let item = self.new_item(title.into(), ItemData::Totp(rec))?;
        Ok(self.vm()?.insert(item)?.to_string())
    }

    /// Code at `unix_time` (the caller's injected clock).
    pub fn totp_code(&self, id: &str, unix_time: u64) -> Result<(String, u32)> {
        let item = self.v()?.get(&parse_id(id)?)?;
        let ItemData::Totp(t) = &item.data else {
            return Err(Error::Validation("not a TOTP item".into()));
        };
        let c = code_now(&t.config, &FixedClock(unix_time))?;
        Ok((c.code, c.seconds_remaining))
    }

    /// New Ed25519 key generated and stored inside the vault. Only the public
    /// key is ever visible.
    pub fn generate_ed25519(&mut self, title: &str, comment: &str) -> Result<String> {
        let rec = Ed25519KeyRecord {
            key: Ed25519KeyPair::generate(&mut OsRandom)?,
            comment: text(Some(comment.into())),
        };
        let item = self.new_item(title.into(), ItemData::Ed25519Key(rec))?;
        Ok(self.vm()?.insert(item)?.to_string())
    }

    /// Sign exactly the bytes `message` stands for (`encoding`: "utf8" as
    /// typed, or "hex") with the stored key of Ed25519 item `id`. Requires
    /// an unlocked vault; the seed never leaves the core.
    pub fn sign_ed25519(&self, id: &str, message: &str, encoding: &str) -> Result<SignatureOut> {
        let item = self.v()?.get(&parse_id(id)?)?;
        let ItemData::Ed25519Key(k) = &item.data else {
            return Err(Error::Validation("not an Ed25519 key item".into()));
        };
        let bytes = ed25519::message_bytes(message, MessageEncoding::parse(encoding)?)?;
        let sig = k.key.sign(&bytes)?;
        Ok(SignatureOut {
            hex: data_encoding::HEXLOWER.encode(&sig),
            base58: ed25519::base58(&sig),
            message_bytes: bytes.len(),
        })
    }

    /// Random secret generated and stored without leaving WASM memory.
    pub fn generate_secret_item(
        &mut self,
        title: &str,
        n_bytes: usize,
        encoding: &str,
        service: &str,
    ) -> Result<String> {
        let enc = parse_encoding(encoding)?;
        let secret = generate_secret(n_bytes, enc, &mut OsRandom)?;
        let data = ItemData::Secret(SecretCredential {
            secret,
            format: SecretFormat::Encoded(enc),
            origin: SecretOrigin::Generated,
            username: None,
            service: text(Some(service.into())),
            expires_at: None,
        });
        let item = self.new_item(title.into(), data)?;
        Ok(self.vm()?.insert(item)?.to_string())
    }

    /// Password generated and stored as a Secret item without leaving WASM.
    pub fn generate_password_item(
        &mut self,
        title: &str,
        profile: &str,
        service: &str,
    ) -> Result<String> {
        let pw = generate_password(
            &PasswordPolicy::profile(parse_profile(profile)?),
            &mut OsRandom,
        )?;
        let data = ItemData::Secret(SecretCredential {
            secret: pw,
            format: SecretFormat::Text,
            origin: SecretOrigin::Generated,
            username: None,
            service: text(Some(service.into())),
            expires_at: None,
        });
        let item = self.new_item(title.into(), data)?;
        Ok(self.vm()?.insert(item)?.to_string())
    }

    /// Like [`Session::generate_password_item`], with user settings
    /// (validated before any random number is drawn).
    pub fn generate_password_item_with(
        &mut self,
        title: &str,
        options_json: &str,
        service: &str,
    ) -> Result<String> {
        let pw = generate_password(&parse_password_options(options_json)?, &mut OsRandom)?;
        let data = ItemData::Secret(SecretCredential {
            secret: pw,
            format: SecretFormat::Text,
            origin: SecretOrigin::Generated,
            username: None,
            service: text(Some(service.into())),
            expires_at: None,
        });
        let item = self.new_item(title.into(), data)?;
        Ok(self.vm()?.insert(item)?.to_string())
    }

    /// Generate a password with user settings (validated before any random
    /// number is drawn) and keep it as the current password preview. The
    /// returned copy is what the user sees; [`Session::save_preview`] stores
    /// exactly this value.
    pub fn preview_password(&mut self, options_json: &str) -> Result<Zeroizing<String>> {
        self.v()?;
        self.previews.password = None;
        let pw = gen_password_with(options_json)?;
        let shown = Zeroizing::new(pw.expose().to_owned());
        self.previews.password = Some(pw);
        Ok(shown)
    }

    /// Like [`Session::preview_password`], for a passphrase (JSON
    /// `{words, separator}`).
    pub fn preview_passphrase(&mut self, options_json: &str) -> Result<Zeroizing<String>> {
        self.v()?;
        self.previews.passphrase = None;
        let p = gen_passphrase(options_json)?;
        let shown = Zeroizing::new(p.expose().to_owned());
        self.previews.passphrase = Some(p);
        Ok(shown)
    }

    /// Like [`Session::preview_password`], for an encoded random secret.
    pub fn preview_secret(&mut self, n_bytes: usize, encoding: &str) -> Result<Zeroizing<String>> {
        self.v()?;
        self.previews.secret = None;
        let enc = parse_encoding(encoding)?;
        let secret = generate_secret(n_bytes, enc, &mut OsRandom)?;
        let shown = Zeroizing::new(secret.expose().to_owned());
        self.previews.secret = Some((secret, enc));
        Ok(shown)
    }

    /// Store the current preview of `kind` ("password", "passphrase" or "secret") as a
    /// generated Secret item. `shown` must equal that preview exactly, so a
    /// replaced, discarded or already saved preview is refused instead of
    /// silently storing something else. The preview is consumed on success
    /// and kept when validation fails.
    pub fn save_preview(
        &mut self,
        kind: &str,
        shown: &str,
        title: &str,
        service: &str,
    ) -> Result<String> {
        self.v()?;
        let (secret, format) = match kind {
            "password" => (self.previews.password.as_ref(), SecretFormat::Text),
            "passphrase" => (self.previews.passphrase.as_ref(), SecretFormat::Text),
            "secret" => match &self.previews.secret {
                Some((v, enc)) => (Some(v), SecretFormat::Encoded(*enc)),
                None => (None, SecretFormat::Text),
            },
            _ => return Err(Error::Validation("unknown preview".into())),
        };
        let secret = match secret {
            Some(v) if bool::from(v.expose().as_bytes().ct_eq(shown.as_bytes())) => v.clone(),
            _ => {
                return Err(Error::Validation(
                    "generated value is no longer available".into(),
                ))
            }
        };
        let data = ItemData::Secret(SecretCredential {
            secret,
            format,
            origin: SecretOrigin::Generated,
            username: None,
            service: text(Some(service.into())),
            expires_at: None,
        });
        let item = self.new_item(title.into(), data)?;
        let id = self.vm()?.insert(item)?.to_string();
        match kind {
            "password" => self.previews.password = None,
            "passphrase" => self.previews.passphrase = None,
            _ => self.previews.secret = None,
        }
        Ok(id)
    }

    /// Forget all previews (the generator view was closed).
    pub fn discard_previews(&mut self) {
        self.previews = Previews::default();
    }

    /// Seal the next revision without changing the session. The caller
    /// persists the bytes and then calls [`Session::commit`].
    ///
    /// The envelope must fit the same size bound [`Session::open`] accepts.
    /// On any failure nothing is published (no pending revision) and the
    /// in-memory vault is rolled back to the last committed state.
    pub fn seal(&mut self, key: &DemoKey) -> Result<(Vec<u8>, u64)> {
        self.seal_with(|v| v.seal_next(key.provider(), &mut OsRandom))
    }

    /// v2 counterpart of [`Session::seal`] (no key provider: the slots are
    /// part of the vault). Refused before the recovery code is confirmed.
    pub fn seal_protected(&mut self) -> Result<(Vec<u8>, u64)> {
        if !self.v()?.is_protected() {
            return Err(Error::KeyProvider(
                "demo vault needs its key provider".into(),
            ));
        }
        self.seal_with(|v| v.seal_next_protected(&mut OsRandom))
    }

    fn seal_with(
        &mut self,
        f: impl FnOnce(&Vault) -> Result<(Vec<u8>, u64)>,
    ) -> Result<(Vec<u8>, u64)> {
        self.pending = None;
        let sealed = f(self.v()?).and_then(|(bytes, rev)| {
            if bytes.len() > self.max_bytes {
                Err(Error::Format(
                    "vault would exceed the maximum size; the change was discarded".into(),
                ))
            } else {
                Ok((bytes, rev))
            }
        });
        match sealed {
            Ok((bytes, rev)) => {
                self.pending = Some(rev);
                Ok((bytes, rev))
            }
            Err(e) => {
                // Back to the last committed state (for a new vault: as created).
                self.vault = self.committed.clone();
                Err(e)
            }
        }
    }

    /// Record that `revision` (from the last [`Session::seal`]) was written.
    pub fn commit(&mut self, revision: u64) -> Result<()> {
        match self.pending.take() {
            Some(r) if r == revision => {
                self.vm()?.mark_persisted(revision)?;
                self.committed = self.vault.clone();
                Ok(())
            }
            _ => Err(Error::Integrity("no matching sealed revision".into())),
        }
    }
}

/// Parameters for a passkey enrolment (public).
#[derive(Debug, Serialize)]
pub struct PrfEnrolment {
    pub slot_id: String,
    /// PRF input, base64url (32 bytes).
    pub salt: String,
    pub vault_id: String,
}

fn prf32(b: &[u8]) -> Result<Zeroizing<[u8; PRF_LEN]>> {
    let a: [u8; PRF_LEN] = b
        .try_into()
        .map_err(|_| Error::Validation("PRF output must be 32 bytes".into()))?;
    Ok(Zeroizing::new(a))
}

/// Quick-unlock slots of a stored envelope (public), for `get()`.
pub fn prf_request(bytes: &[u8]) -> Result<Vec<PrfRequest>> {
    check_size(bytes)?;
    envelope_prf_request(bytes)
}

pub fn parse_profile(p: &str) -> Result<PasswordProfile> {
    match p {
        "default" | "" => Ok(PasswordProfile::Default),
        "strong" => Ok(PasswordProfile::Strong),
        _ => Err(Error::Policy("unknown password profile".into())),
    }
}

pub fn parse_encoding(e: &str) -> Result<SecretEncoding> {
    match e {
        "hex" | "" => Ok(SecretEncoding::Hex),
        "base64url" => Ok(SecretEncoding::Base64Url),
        "base32" => Ok(SecretEncoding::Base32),
        _ => Err(Error::Policy("unknown encoding".into())),
    }
}

pub fn gen_password(profile: &str, length: usize, alphabet: &str) -> Result<SecretString> {
    let pol = if alphabet.is_empty() {
        PasswordPolicy::profile(parse_profile(profile)?)
    } else {
        PasswordPolicy::allowlist(length, alphabet)?
    };
    generate_password(&pol, &mut OsRandom)
}

/// Largest accepted password-options JSON; bounds parsing work.
pub const MAX_OPTIONS_JSON: usize = 2048;

/// Strict JSON `PasswordOptions` (camelCase, no unknown or missing fields)
/// to a validated policy.
pub fn parse_password_options(json: &str) -> Result<PasswordPolicy> {
    if json.len() > MAX_OPTIONS_JSON {
        return Err(Error::Policy("password options too large".into()));
    }
    let o: PasswordOptions = serde_json::from_str(json)
        .map_err(|_| Error::Policy("malformed password options".into()))?;
    PasswordPolicy::from_options(&o)
}

pub fn gen_password_with(options_json: &str) -> Result<SecretString> {
    generate_password(&parse_password_options(options_json)?, &mut OsRandom)
}

/// Validate settings and describe them; draws no random numbers.
pub fn password_policy_summary(options_json: &str) -> Result<PolicySummary> {
    Ok(parse_password_options(options_json)?.summary())
}

pub fn gen_secret(n_bytes: usize, encoding: &str) -> Result<SecretString> {
    generate_secret(n_bytes, parse_encoding(encoding)?, &mut OsRandom)
}

// --- Ed25519 sign / verify, passphrases (M5 B) -------------------------------

#[derive(Debug, Serialize)]
pub struct SignatureOut {
    pub hex: String,
    pub base58: String,
    pub message_bytes: usize,
}

/// The exact bytes a message stands for, for display before signing or
/// verifying: their count and hex (the first 512 bytes; `truncated` beyond).
#[derive(Debug, Serialize, PartialEq)]
pub struct MessagePreview {
    pub bytes: usize,
    pub hex: String,
    pub truncated: bool,
}

pub const PREVIEW_BYTES: usize = 512;

pub fn message_preview(message: &str, encoding: &str) -> Result<MessagePreview> {
    let b = ed25519::message_bytes(message, MessageEncoding::parse(encoding)?)?;
    let shown = &b[..b.len().min(PREVIEW_BYTES)];
    Ok(MessagePreview {
        bytes: b.len(),
        hex: data_encoding::HEXLOWER.encode(shown),
        truncated: b.len() > PREVIEW_BYTES,
    })
}

/// Outcome of a strict verification. A malformed input is reported as such
/// and is never "valid".
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Valid,
    Invalid,
    BadPublicKey,
    BadSignature,
    BadMessage,
}

/// Stateless strict verification (works without an unlocked vault).
pub fn verify_ed25519(public_key: &str, message: &str, encoding: &str, signature: &str) -> Verdict {
    let Ok(pk) = ed25519::parse_public_key(public_key) else {
        return Verdict::BadPublicKey;
    };
    let Ok(sig) = ed25519::parse_signature(signature) else {
        return Verdict::BadSignature;
    };
    let Ok(msg) = MessageEncoding::parse(encoding).and_then(|e| ed25519::message_bytes(message, e))
    else {
        return Verdict::BadMessage;
    };
    match ed25519::verify(&pk, &msg, &sig) {
        Ok(()) => Verdict::Valid,
        Err(_) => Verdict::Invalid,
    }
}

fn parse_passphrase_options(json: &str) -> Result<PassphraseOptions> {
    serde_json::from_str(json).map_err(|_| Error::Policy("invalid passphrase settings".into()))
}

/// Passphrase from JSON `{words, separator: "space" | "period"}`.
pub fn gen_passphrase(options_json: &str) -> Result<SecretString> {
    passphrase::generate_passphrase(&parse_passphrase_options(options_json)?, &mut OsRandom)
}

pub fn passphrase_summary(options_json: &str) -> Result<PassphraseSummary> {
    parse_passphrase_options(options_json)?.summary()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(j: serde_json::Value) -> ItemInput {
        serde_json::from_value(j).unwrap()
    }

    fn session() -> (DemoKey, Session) {
        let k = DemoKey::fixture();
        let s = Session::create(&k).unwrap();
        (k, s)
    }

    fn persist(s: &mut Session, k: &DemoKey) -> Vec<u8> {
        let (b, r) = s.seal(k).unwrap();
        s.commit(r).unwrap();
        b
    }

    #[test]
    fn create_every_kind_and_round_trip() {
        let (k, mut s) = session();
        let login = s
            .create_item(input(serde_json::json!({
                "title": "SYNTH-TITLE Login", "tags": ["t"], "notes": "SYNTH-NOTE",
                "custom_fields": [{"label": "pin", "concealed": true, "value": "SYNTH-PIN"},
                                  {"label": "plan", "value": "basic"}],
                "data": {"kind": "login", "username": "u", "password": "SYNTH-PW",
                         "urls": ["https://SYNTH-URL.example.test"], "recovery_codes": ["RC1"]}})))
            .unwrap();
        s.create_item(input(
            serde_json::json!({"title": "S", "data": {"kind": "secret", "secret": "SYNTH-SECRET"}}),
        ))
        .unwrap();
        s.create_item(input(serde_json::json!({"title": "C", "data": {"kind": "contact", "full_name": "SYNTHADA-Lovelace",
            "emails": [{"label": "w", "value": "a@example.test"}, {"label": null, "value": "b@example.test"}],
            "phones": [{"label": null, "value": "+1 555 0100"}]}}))).unwrap();
        s.create_item(input(
            serde_json::json!({"title": "W", "data": {"kind": "crypto_wallet", "network": "testnet",
            "addresses": [{"label": null, "value": "addr1"}], "recovery_phrase": "SYNTH-WORDS"}}),
        ))
        .unwrap();
        s.create_item(input(serde_json::json!({"title": "N", "data": {"kind": "secure_note", "body": "SYNTH-BODY"}}))).unwrap();
        let totp = s
            .create_totp(
                "T",
                "otpauth://totp/Ex:u?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Ex&digits=8",
                "",
                "",
            )
            .unwrap();
        let ed = s.generate_ed25519("K", "c").unwrap();
        s.generate_secret_item("G", 32, "hex", "svc").unwrap();
        s.generate_password_item("P", "strong", "").unwrap();
        assert_eq!(s.list("", "").unwrap().len(), 9);

        let bytes = persist(&mut s, &k);
        let raw = String::from_utf8(bytes.clone()).unwrap();
        // Markers are long enough not to occur by chance in base64 ciphertext
        // (a 3-letter "Ada" did, once in CI).
        for m in ["SYNTH", "GEZDGNBV", "example.test", "SYNTHADA-Lovelace"] {
            assert!(!raw.contains(m), "{m} in envelope");
        }
        let s2 = Session::open(&bytes, &k).unwrap();
        assert_eq!(s2.list("", "").unwrap().len(), 9);
        assert_eq!(&*s2.reveal(&login, "password").unwrap(), "SYNTH-PW");
        assert_eq!(&*s2.reveal(&login, "custom:0").unwrap(), "SYNTH-PIN");
        assert_eq!(&*s2.reveal(&login, "recovery_code:0").unwrap(), "RC1");
        assert_eq!(s2.totp_code(&totp, 59).unwrap(), ("94287082".into(), 1));
        // Views never contain secret values.
        let v = serde_json::to_string(&s2.get(&login).unwrap()).unwrap();
        assert!(!v.contains("SYNTH-PW") && !v.contains("SYNTH-PIN") && !v.contains("SYNTH-NOTE"));
        assert!(v.contains("basic"), "non-concealed custom value visible");
        let ev = serde_json::to_string(&s2.get(&ed).unwrap()).unwrap();
        assert!(ev.contains("ssh-ed25519 "));
        assert!(s2.reveal(&ed, "seed").is_err(), "no seed reveal");
    }

    #[test]
    fn update_keep_clear_set_semantics() {
        let (_k, mut s) = session();
        let id = s
            .create_item(input(serde_json::json!({"title": "L", "notes": "N1",
                "custom_fields": [{"label": "pin", "concealed": true, "value": "P1"}],
                "data": {"kind": "login", "password": "PW1"}})))
            .unwrap();
        // Keep password and custom value, clear notes, rename.
        s.update_item(
            &id,
            input(serde_json::json!({"title": "L2", "notes": "",
            "custom_fields": [{"label": "pin2", "concealed": true, "value": null, "existing": 0}],
            "data": {"kind": "login", "username": "u"}})),
        )
        .unwrap();
        assert_eq!(&*s.reveal(&id, "password").unwrap(), "PW1");
        assert_eq!(&*s.reveal(&id, "custom:0").unwrap(), "P1");
        assert!(s.reveal(&id, "notes").is_err());
        let v = s.get(&id).unwrap();
        assert_eq!(v.title, "L2");
        assert_eq!(v.rev, 2);
        // Kind cannot change; validation errors leave the item untouched.
        assert!(s
            .update_item(
                &id,
                input(
                    serde_json::json!({"title": "x", "data": {"kind": "secure_note", "body": "b"}})
                )
            )
            .is_err());
        assert!(s
            .update_item(
                &id,
                input(serde_json::json!({"title": "", "data": {"kind": "login"}}))
            )
            .is_err());
        assert_eq!(s.get(&id).unwrap().title, "L2");
    }

    #[test]
    fn search_and_filter() {
        let (_k, mut s) = session();
        s.create_item(input(serde_json::json!({"title": "Alpha", "data": {"kind": "login", "username": "zed", "urls": ["https://bank.example.test"]}}))).unwrap();
        s.create_item(input(serde_json::json!({"title": "Beta", "data": {"kind": "secure_note", "body": "bank secret"}}))).unwrap();
        assert_eq!(
            s.list("BANK", "").unwrap().len(),
            1,
            "url hit; note bodies not searched"
        );
        assert_eq!(s.list("zed", "").unwrap().len(), 1);
        assert_eq!(s.list("", "secure_note").unwrap().len(), 1);
        assert!(s.list("", "bogus").is_err());
    }

    #[test]
    fn summaries_carry_the_first_login_url_only() {
        let (_k, mut s) = session();
        s.create_item(input(serde_json::json!({"title": "A", "data": {"kind": "login", "urls": ["https://a.example.test/x?q=1", "https://b.example.test"]}}))).unwrap();
        s.create_item(input(
            serde_json::json!({"title": "B", "data": {"kind": "login", "username": "u"}}),
        ))
        .unwrap();
        s.create_item(input(serde_json::json!({"title": "C", "data": {"kind": "secret", "secret": "s", "service": "https://svc.example.test"}}))).unwrap();
        let urls: Vec<_> = s.list("", "").unwrap().into_iter().map(|x| x.url).collect();
        assert_eq!(
            urls,
            vec![Some("https://a.example.test/x?q=1".to_string()), None, None],
            "first URL of logins only; other kinds never expose one"
        );
    }

    #[test]
    fn locked_session_rejects_everything() {
        let (k, mut s) = session();
        let id = s
            .create_item(input(
                serde_json::json!({"title": "A", "data": {"kind": "secure_note", "body": "b"}}),
            ))
            .unwrap();
        s.lock();
        assert!(s.is_locked());
        assert!(s.list("", "").is_err());
        assert!(s.get(&id).is_err());
        assert!(s.reveal(&id, "body").is_err());
        assert!(s
            .create_item(input(
                serde_json::json!({"title": "B", "data": {"kind": "secure_note", "body": "b"}})
            ))
            .is_err());
        assert!(s.delete_item(&id).is_err());
        assert!(s.generate_ed25519("k", "").is_err());
        assert!(s.generate_secret_item("g", 32, "hex", "").is_err());
        assert!(s
            .create_totp("t", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "", "")
            .is_err());
        assert!(s.totp_code(&id, 0).is_err());
        assert!(s.seal(&k).is_err());
        assert!(s.commit(1).is_err());
    }

    #[test]
    fn seal_commit_protocol() {
        let (k, mut s) = session();
        let (_b, r) = s.seal(&k).unwrap();
        assert_eq!(r, 1);
        assert!(s.commit(2).is_err());
        assert!(
            s.commit(1).is_err(),
            "pending consumed by the failed commit"
        );
        let (_b, r) = s.seal(&k).unwrap();
        s.commit(r).unwrap();
        assert_eq!(s.revision().unwrap(), 1);
        let (_b, r) = s.seal(&k).unwrap();
        assert_eq!(r, 2);
    }

    #[test]
    fn wrong_key_corrupt_unknown_and_oversize_fail() {
        let (k, mut s) = session();
        s.create_item(input(
            serde_json::json!({"title": "A", "data": {"kind": "secure_note", "body": "b"}}),
        ))
        .unwrap();
        let bytes = persist(&mut s, &k);
        let other = DemoKey::ephemeral().unwrap();
        assert!(Session::open(&bytes, &other).is_err());
        assert!(Session::open(&bytes[..bytes.len() / 2], &k).is_err());
        assert!(Session::open(b"{\"format\":\"x\"}", &k).is_err());
        assert!(Session::open(&vec![b' '; MAX_ENVELOPE_BYTES + 1], &k).is_err());
        let info = inspect_envelope(&bytes).unwrap();
        assert_eq!(info.revision, 1);
        assert_eq!(info.kek_id.as_deref(), Some(FixtureKeyProvider::KEY_ID));
        assert_eq!(info.version, 1);
    }

    #[test]
    fn oversize_seal_is_refused_and_rolls_back() {
        let k = DemoKey::fixture();
        let mut s = Session::create(&k).unwrap();
        s.create_item(input(
            serde_json::json!({"title": "small", "data": {"kind": "secure_note", "body": "x"}}),
        ))
        .unwrap();
        let good = persist(&mut s, &k);
        // A limit just above the current envelope: the next big item cannot fit.
        let limit = good.len() + 2048;
        s.set_max_bytes_for_tests(limit);
        let big = "y".repeat(8192);
        s.create_item(input(
            serde_json::json!({"title": "big", "data": {"kind": "secure_note", "body": big}}),
        ))
        .unwrap();
        let err = s.seal(&k).unwrap_err();
        assert!(matches!(err, Error::Format(_)), "{err:?}");
        // No pending revision was published and the change was rolled back.
        assert!(s.commit(2).is_err());
        assert_eq!(s.revision().unwrap(), 1);
        let titles: Vec<String> = s
            .list("", "")
            .unwrap()
            .into_iter()
            .map(|x| x.title)
            .collect();
        assert_eq!(titles, ["small"]);
        // The previously persisted envelope still opens (production limit).
        assert_eq!(
            Session::open(&good, &k)
                .unwrap()
                .list("", "")
                .unwrap()
                .len(),
            1
        );
        // A change that fits still works afterwards, at the next revision.
        s.create_item(input(
            serde_json::json!({"title": "ok", "data": {"kind": "secure_note", "body": "z"}}),
        ))
        .unwrap();
        let (b, r) = s.seal(&k).unwrap();
        assert!(b.len() <= limit);
        assert_eq!(r, 2);
        s.commit(r).unwrap();
    }

    #[test]
    fn exactly_at_limit_seals_and_reopens() {
        let k = DemoKey::fixture();
        let mut s = Session::create(&k).unwrap();
        s.create_item(input(
            serde_json::json!({"title": "a", "data": {"kind": "secure_note", "body": "x"}}),
        ))
        .unwrap();
        let (b, _) = s.seal(&k).unwrap();
        // Sealed size is deterministic for fixed content (fresh nonces, same lengths).
        s.set_max_bytes_for_tests(b.len());
        let (b2, r) = s.seal(&k).unwrap();
        assert_eq!(b2.len(), b.len());
        s.commit(r).unwrap();
        s.set_max_bytes_for_tests(b.len() - 1);
        assert!(s.seal(&k).is_err());
    }

    #[test]
    fn production_seal_limit_matches_open_limit() {
        let k = DemoKey::fixture();
        let s = Session::create(&k).unwrap();
        assert_eq!(s.max_bytes, MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn fixture_key_is_stable_and_ephemeral_differs() {
        let (k, mut s) = session();
        let bytes = persist(&mut s, &k);
        // A fresh fixture provider (e.g. after reload) opens it.
        assert!(Session::open(&bytes, &DemoKey::fixture()).is_ok());
        let e = DemoKey::ephemeral().unwrap();
        let mut se = Session::create(&e).unwrap();
        let eb = persist(&mut se, &e);
        assert!(Session::open(&eb, &DemoKey::ephemeral().unwrap()).is_err());
        assert!(Session::open(&eb, &e).is_ok());
    }

    fn opts(j: serde_json::Value) -> String {
        let mut base = serde_json::json!({
            "length": 24, "lowercase": true, "uppercase": true, "digits": true, "symbols": true,
            "symbolSet": "!#$%&()*+,-./:;<=>?@[]^_{|}~", "excludeAmbiguous": false, "requireEachClass": true
        });
        for (k, v) in j.as_object().unwrap() {
            base[k] = v.clone();
        }
        base.to_string()
    }

    #[test]
    fn password_options_api_is_strict_and_typed() {
        let pw = gen_password_with(&opts(serde_json::json!({"length": 40, "lowercase": false,
            "symbolSet": "#@!", "excludeAmbiguous": true})))
        .unwrap();
        let s = pw.expose();
        assert_eq!(s.chars().count(), 40);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || "#@!".contains(c)));
        assert!(!s.chars().any(|c| "Il1O0o".contains(c)));
        // Unknown, missing, wrongly typed or oversized options are refused.
        let mut extra: serde_json::Value =
            serde_json::from_str(&opts(serde_json::json!({}))).unwrap();
        extra["alphabet"] = "ab".into();
        assert!(gen_password_with(&extra.to_string()).is_err());
        let mut missing = extra.clone();
        missing.as_object_mut().unwrap().remove("alphabet");
        missing.as_object_mut().unwrap().remove("requireEachClass");
        assert!(gen_password_with(&missing.to_string()).is_err());
        assert!(gen_password_with(&opts(serde_json::json!({"length": 24.5}))).is_err());
        assert!(gen_password_with(&opts(serde_json::json!({"length": -1}))).is_err());
        assert!(gen_password_with(&opts(serde_json::json!({"symbols": "yes"}))).is_err());
        let huge = opts(serde_json::json!({"symbolSet": "!".repeat(MAX_OPTIONS_JSON)}));
        assert!(gen_password_with(&huge)
            .unwrap_err()
            .to_string()
            .contains("too large"));
        assert!(
            gen_password_with(&opts(serde_json::json!({"symbolSet": "ab"})))
                .unwrap_err()
                .to_string()
                .contains("ASCII punctuation")
        );
    }

    #[test]
    fn password_policy_summary_validates_without_generating() {
        let s = password_policy_summary(&opts(serde_json::json!({"symbolSet": "!!@@"}))).unwrap();
        assert_eq!((s.length, s.alphabet_size, s.classes), (24, 64, 4));
        assert!(s.min_entropy_bits >= 64.0 && s.min_entropy_bits < s.upper_bound_bits);
        let j = serde_json::to_value(&s).unwrap();
        assert!(j["minEntropyBits"].is_f64() && j["upperBoundBits"].is_f64());
        // Reviewer's case: upper bound above 64, real output below; refused.
        assert!(password_policy_summary(&opts(
            serde_json::json!({"length": 11, "symbolSet": "!"})
        ))
        .unwrap_err()
        .to_string()
        .contains("entropy"));
        assert!(
            password_policy_summary(&opts(serde_json::json!({"length": 8})))
                .unwrap_err()
                .to_string()
                .contains("entropy")
        );
    }

    #[test]
    fn generated_password_item_uses_the_options_and_round_trips() {
        let (k, mut s) = session();
        let o = opts(
            serde_json::json!({"length": 30, "lowercase": false, "uppercase": false,
            "symbols": false, "digits": true}),
        );
        let id = s
            .generate_password_item_with("Synthetic PIN-like", &o, "svc")
            .unwrap();
        let bytes = persist(&mut s, &k);
        let s2 = Session::open(&bytes, &DemoKey::fixture()).unwrap();
        let pw = s2.reveal(&id, "secret").unwrap();
        assert_eq!(pw.chars().count(), 30);
        assert!(pw.chars().all(|c| c.is_ascii_digit()));
        // Invalid options change nothing.
        let before = s2.list("", "").unwrap().len();
        let mut s3 = s2;
        assert!(s3
            .generate_password_item_with("x", &opts(serde_json::json!({"length": 8})), "")
            .is_err());
        assert_eq!(s3.list("", "").unwrap().len(), before);
    }

    #[test]
    fn generators() {
        assert_eq!(
            gen_password("default", 0, "")
                .unwrap()
                .expose()
                .chars()
                .count(),
            24
        );
        assert_eq!(
            gen_password("strong", 0, "")
                .unwrap()
                .expose()
                .chars()
                .count(),
            32
        );
        assert!(gen_password("x", 0, "").is_err());
        assert!(gen_password("", 4, "ab").is_err());
        assert_eq!(gen_secret(32, "hex").unwrap().len(), 64);
        assert!(gen_secret(32, "rot13").is_err());
    }

    #[test]
    fn previewed_password_is_saved_exactly_and_only_once() {
        let (k, mut s) = session();
        let o = opts(serde_json::json!({"length": 40, "lowercase": false}));
        let shown = s.preview_password(&o).unwrap();
        assert_eq!(shown.chars().count(), 40);
        let id = s
            .save_preview("password", &shown, "Synthetic preview", "svc")
            .unwrap();
        // Saved once: a second click (or a stale tab) has nothing to save.
        assert!(s.save_preview("password", &shown, "again", "").is_err());
        assert_eq!(s.list("", "").unwrap().len(), 1);
        let bytes = persist(&mut s, &k);
        let s2 = Session::open(&bytes, &DemoKey::fixture()).unwrap();
        assert!(s2.reveal(&id, "secret").unwrap().as_str() == shown.as_str());
        let v = s2.get(&id).unwrap();
        assert_eq!(v.data["origin"], "generated");
        assert_eq!(v.data["format"], "text");
        assert_eq!(v.data["service"], "svc");
    }

    #[test]
    fn save_preview_accepts_only_the_current_preview() {
        let (_k, mut s) = session();
        let o = opts(serde_json::json!({}));
        // Nothing generated yet.
        assert!(s.save_preview("password", "x", "t", "").is_err());
        let first = s.preview_password(&o).unwrap();
        let second = s.preview_password(&o).unwrap();
        // A replaced preview, or any other value, is refused; nothing stored.
        assert!(s.save_preview("password", &first, "t", "").is_err());
        assert!(s
            .save_preview("password", "not-the-preview", "t", "")
            .is_err());
        assert!(s.save_preview("secret", &second, "t", "").is_err());
        assert!(s.save_preview("bogus", &second, "t", "").is_err());
        // A validation failure keeps the preview for a corrected retry.
        assert!(s.save_preview("password", &second, "", "").is_err());
        assert!(s.list("", "").unwrap().is_empty());
        assert!(s.save_preview("password", &second, "ok", "").is_ok());
        // Invalid settings draw nothing and leave no preview behind.
        assert!(s
            .preview_password(&opts(serde_json::json!({"length": 8})))
            .is_err());
        assert!(s.save_preview("password", &second, "t", "").is_err());
    }

    #[test]
    fn previewed_random_secret_keeps_its_encoding() {
        let (_k, mut s) = session();
        let shown = s.preview_secret(32, "hex").unwrap();
        assert_eq!(shown.len(), 64);
        let pw = s.preview_password(&opts(serde_json::json!({}))).unwrap();
        // Separate slots: the password preview did not replace the secret.
        let id = s
            .save_preview("secret", &shown, "Synthetic hex", "")
            .unwrap();
        assert!(s.reveal(&id, "secret").unwrap().as_str() == shown.as_str());
        assert_eq!(s.get(&id).unwrap().data["format"], "hex");
        assert_eq!(s.get(&id).unwrap().data["origin"], "generated");
        assert!(s.save_preview("password", &pw, "pw", "").is_ok());
        assert!(s.preview_secret(8, "hex").is_err());
        assert!(s.preview_secret(32, "rot13").is_err());
    }

    #[test]
    fn discard_and_lock_drop_previews() {
        let (_k, mut s) = session();
        let o = opts(serde_json::json!({}));
        let shown = s.preview_password(&o).unwrap();
        s.discard_previews();
        assert!(s.save_preview("password", &shown, "t", "").is_err());
        let shown = s.preview_password(&o).unwrap();
        s.lock();
        assert!(s.save_preview("password", &shown, "t", "").is_err());
        assert!(s.preview_password(&o).is_err());
        assert!(s.preview_secret(32, "hex").is_err());
    }

    // --- v2 ---------------------------------------------------------------------

    const PW: &str = "synthetic bridge passphrase";

    fn derive(pw: &str, r: &KdfRequest) -> Zeroizing<[u8; 32]> {
        derive_password_key(pw, &serde_json::to_string(r).unwrap()).unwrap()
    }

    fn new_protected() -> (Session, String) {
        let c = ProtectedCreation::new().unwrap();
        let key = derive(PW, &c.request());
        let mut s = Session::create_protected(&c, &key[..]).unwrap();
        let code = s.shown_recovery_code().unwrap().as_str().to_owned();
        assert!(
            s.seal_protected().is_err(),
            "unconfirmed vault is never sealed"
        );
        assert!(s.confirm_recovery("AAAA").is_err());
        assert!(s.shown_recovery_code().is_ok(), "kept after a wrong entry");
        s.confirm_recovery(&code).unwrap();
        assert!(
            s.shown_recovery_code().is_err(),
            "shown only until confirmed"
        );
        (s, code)
    }

    fn persist_v2(s: &mut Session) -> Vec<u8> {
        let (b, r) = s.seal_protected().unwrap();
        s.commit(r).unwrap();
        b
    }

    #[test]
    fn protected_create_confirm_persist_and_reopen() {
        let (mut s, code) = new_protected();
        assert!(s.is_protected().unwrap());
        s.create_item(input(serde_json::json!({"title": "SYNTH-T", "data": {"kind": "secure_note", "body": "SYNTH-B"}})))
            .unwrap();
        let bytes = persist_v2(&mut s);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("SYNTH-") && !text.contains(PW));
        assert!(!text.contains(&code) && !text.contains(&code.replace('-', "")));
        assert_eq!(inspect_envelope(&bytes).unwrap().version, 2);
        assert_eq!(inspect_envelope(&bytes).unwrap().kek_id, None);
        let req = password_request(&bytes).unwrap();
        let a = Session::open_with_password_key(&bytes, &derive(PW, &req)[..]).unwrap();
        let b = Session::open_with_recovery(&bytes, &code).unwrap();
        assert_eq!(a.list("", "").unwrap().len(), 1);
        assert_eq!(b.list("", "").unwrap().len(), 1);
        assert!(
            Session::open_with_password_key(&bytes, &derive("synthetic wrong one", &req)[..])
                .is_err()
        );
        assert!(Session::open_with_password_key(&bytes, &[0u8; 31]).is_err());
        // Demo sealing never applies to a password vault and vice versa.
        assert!(s.seal(&DemoKey::fixture()).is_err());
        let (_k, mut demo) = session();
        assert!(demo.seal_protected().is_err());
        assert!(password_request(&persist(&mut demo, &DemoKey::fixture())).is_err());
    }

    #[test]
    fn protected_password_change_needs_core_held_setup_and_authority() {
        let (mut s, code) = new_protected();
        let old = persist_v2(&mut s);
        let cur_req = s.current_password_request().unwrap();
        let cur = derive(PW, &cur_req);
        // No pending setup: refused.
        assert!(s.change_password_with_key(&cur[..], &[1; 32]).is_err());
        let new_req = s.begin_password_change().unwrap();
        assert_ne!(new_req.salt, cur_req.salt);
        let new_pw = "synthetic bridge passphrase two";
        let new = derive(new_pw, &new_req);
        // Wrong current key: refused and the pending setup is consumed.
        assert!(s.change_password_with_key(&[9; 32], &new[..]).is_err());
        assert!(s.change_password_with_key(&cur[..], &new[..]).is_err());
        let new_req = s.begin_password_change().unwrap();
        let new = derive(new_pw, &new_req);
        s.change_password_with_key(&cur[..], &new[..]).unwrap();
        // Failed write: roll back to the committed slots.
        s.rollback().unwrap();
        let after_rollback = persist_v2(&mut s);
        let req = password_request(&after_rollback).unwrap();
        assert!(Session::open_with_password_key(&after_rollback, &derive(PW, &req)[..]).is_ok());
        // Recovery authority path.
        let new_req = s.begin_password_change().unwrap();
        let new = derive(new_pw, &new_req);
        assert!(s.change_password_with_recovery("AAAA", &new[..]).is_err());
        let new_req = s.begin_password_change().unwrap();
        let new = derive(new_pw, &new_req);
        s.change_password_with_recovery(&code, &new[..]).unwrap();
        let bytes = persist_v2(&mut s);
        let req = password_request(&bytes).unwrap();
        assert!(Session::open_with_password_key(&bytes, &derive(new_pw, &req)[..]).is_ok());
        assert!(Session::open_with_password_key(&bytes, &derive(PW, &req)[..]).is_err());
        // The earlier envelope keeps its old password (rewrap semantics).
        let req = password_request(&old).unwrap();
        assert!(Session::open_with_password_key(&old, &derive(PW, &req)[..]).is_ok());
    }

    #[test]
    fn protected_recovery_change_and_lock_drop_pending_state() {
        let (mut s, code) = new_protected();
        persist_v2(&mut s);
        let cur = derive(PW, &s.current_password_request().unwrap());
        assert!(s.begin_recovery_change(&[3; 32]).is_err());
        s.begin_recovery_change(&cur[..]).unwrap();
        let new_code = s.shown_recovery_code().unwrap().as_str().to_owned();
        assert_ne!(new_code, code);
        assert!(s.finish_recovery_change(&code).is_err());
        s.finish_recovery_change(&new_code).unwrap();
        let bytes = persist_v2(&mut s);
        assert!(Session::open_with_recovery(&bytes, &new_code).is_ok());
        assert!(Session::open_with_recovery(&bytes, &code).is_err());
        s.begin_recovery_change(&cur[..]).unwrap();
        s.begin_password_change().unwrap();
        s.lock();
        assert!(s.shown_recovery_code().is_err());
        assert!(s.finish_recovery_change(&new_code).is_err());
        assert!(s.seal_protected().is_err());
        assert!(s.current_password_request().is_err());
    }

    #[test]
    fn kdf_requests_are_strict_and_bounded() {
        let ok =
            serde_json::json!({"salt": "AAAAAAAAAAAAAAAAAAAAAA", "mKib": 65536, "t": 3, "p": 1});
        assert!(derive_password_key(PW, &ok.to_string()).is_ok());
        for bad in [
            serde_json::json!({"salt": "AAAAAAAAAAAAAAAAAAAAAA", "mKib": 4194304, "t": 3, "p": 1}),
            serde_json::json!({"salt": "AAAAAAAAAAAAAAAAAAAAAA", "mKib": 65536, "t": 100, "p": 1}),
            serde_json::json!({"salt": "AAAAAAAAAAAAAAAAAAAAAA", "mKib": 1024, "t": 3, "p": 1}),
            serde_json::json!({"salt": "AAAA", "mKib": 65536, "t": 3, "p": 1}),
            serde_json::json!({"salt": "AAAAAAAAAAAAAAAAAAAAAA", "mKib": 65536, "t": 3, "p": 1, "x": 1}),
            serde_json::json!({"salt": "AAAAAAAAAAAAAAAAAAAAAA", "mKib": 65536, "t": 3}),
        ] {
            let t = std::time::Instant::now();
            assert!(derive_password_key(PW, &bad.to_string()).is_err(), "{bad}");
            assert!(t.elapsed() < std::time::Duration::from_millis(100));
        }
        assert!(derive_password_key(PW, &"x".repeat(1000)).is_err());
        assert!(check_new_password("short").is_err());
        assert!(check_new_password(PW).is_ok());
    }

    #[test]
    fn ed25519_sign_verify_through_the_bridge() {
        let (_k, mut s) = session();
        let id = s.generate_ed25519("Synthetic signer", "").unwrap();
        let view = serde_json::to_value(s.get(&id).unwrap()).unwrap();
        let pk58 = view["data"]["public_key_base58"]
            .as_str()
            .unwrap()
            .to_owned();
        let pkhex = view["data"]["public_key_hex"].as_str().unwrap().to_owned();
        assert_eq!(
            ed25519::parse_public_key(&pk58).unwrap(),
            ed25519::parse_public_key(&pkhex).unwrap()
        );
        // The view carries no seed.
        assert!(!serde_json::to_string(&view).unwrap().contains("seed"));

        let out = s.sign_ed25519(&id, "synthetic message", "utf8").unwrap();
        assert_eq!(out.message_bytes, 17);
        assert_eq!(out.hex.len(), 128);
        for (k, sig) in [(&pk58, &out.hex), (&pkhex, &out.base58)] {
            assert_eq!(
                verify_ed25519(k, "synthetic message", "utf8", sig),
                Verdict::Valid
            );
        }
        // Same bytes written as hex verify too; other bytes do not.
        let hexmsg = data_encoding::HEXLOWER.encode(b"synthetic message");
        assert_eq!(
            verify_ed25519(&pk58, &hexmsg, "hex", &out.hex),
            Verdict::Valid
        );
        assert_eq!(
            verify_ed25519(&pk58, "synthetic message ", "utf8", &out.hex),
            Verdict::Invalid
        );
        assert_eq!(
            verify_ed25519("nope", "m", "utf8", &out.hex),
            Verdict::BadPublicKey
        );
        assert_eq!(
            verify_ed25519(&pk58, "m", "utf8", "nope"),
            Verdict::BadSignature
        );
        assert_eq!(
            verify_ed25519(&pk58, "zz", "hex", &out.hex),
            Verdict::BadMessage
        );
        assert_eq!(
            verify_ed25519(&pk58, "m", "base64", &out.hex),
            Verdict::BadMessage
        );

        // Only Ed25519 items sign; a bad message is refused; locked refuses.
        let note = s
            .create_item(input(serde_json::json!({"title": "n", "data": {"kind": "secure_note", "body": "synthetic"}})))
            .unwrap();
        assert!(s.sign_ed25519(&note, "m", "utf8").is_err());
        assert!(s.sign_ed25519(&id, "abc", "hex").is_err());
        s.lock();
        assert!(s.sign_ed25519(&id, "m", "utf8").is_err());
    }

    #[test]
    fn message_preview_shows_exact_bytes() {
        let p = message_preview("e\u{301}", "utf8").unwrap();
        assert_eq!(
            p,
            MessagePreview {
                bytes: 3,
                hex: "65cc81".into(),
                truncated: false
            }
        );
        let long = message_preview(&"ab".repeat(600), "hex").unwrap();
        assert_eq!(
            (long.bytes, long.hex.len(), long.truncated),
            (600, 1024, true)
        );
        assert!(message_preview("x", "hex").is_err());
    }

    #[test]
    fn passphrases_through_the_bridge() {
        let p = gen_passphrase(r#"{"words":7,"separator":"period"}"#).unwrap();
        assert_eq!(p.expose().split('.').count(), 7);
        let sum = passphrase_summary(r#"{"words":5,"separator":"space"}"#).unwrap();
        assert!(!sum.master_ok);
        assert!((sum.entropy_bits - 64.62).abs() < 0.01);
        for bad in [
            r#"{"words":3,"separator":"space"}"#,
            r#"{"words":6,"separator":"hyphen"}"#,
            r#"{"words":6}"#,
            r#"{"words":6,"separator":"space","x":1}"#,
            "nope",
        ] {
            assert!(gen_passphrase(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn v2_rotation_session_flow_rollback_and_lock() {
        let (mut s, code) = new_protected();
        s.create_item(input(
            serde_json::json!({"title": "n", "data": {"kind": "secure_note", "body": "SYNTH-ROT"}}),
        ))
        .unwrap();
        let b1 = persist_v2(&mut s);
        let cur = derive(PW, &s.current_password_request().unwrap());
        const PW_NEW: &str = "synthetic bridge rotated passphrase";
        // Without fresh parameters: refused.
        assert!(s.begin_rotation(&cur[..], &[0u8; 32]).is_err());
        let req = s.begin_password_change().unwrap();
        let new = derive(PW_NEW, &req);
        // Wrong current key: refused, the parameters are consumed.
        assert!(s.begin_rotation(&[7u8; 32], &new[..]).is_err());
        let req = s.begin_password_change().unwrap();
        let new = derive(PW_NEW, &req);
        s.begin_rotation(&cur[..], &new[..]).unwrap();
        assert!(s.rotation_pending());
        let shown = s.shown_recovery_code().unwrap().as_str().to_owned();
        assert_ne!(shown, code);
        // Mistyped (or old) code: still pending, nothing switched.
        assert!(s.finish_rotation(&code).is_err());
        assert!(s.rotation_pending());
        s.finish_rotation(&shown).unwrap();
        // A failed write: rollback returns to the stored (old) credentials.
        s.rollback().unwrap();
        let (b, r) = s.seal_protected().unwrap();
        assert!(Session::open_with_recovery(&b, &code).is_ok());
        s.commit(r).unwrap();
        // Again, persisted this time.
        let req = s.begin_password_change().unwrap();
        let new = derive(PW_NEW, &req);
        let cur = derive(PW, &s.current_password_request().unwrap());
        s.begin_rotation(&cur[..], &new[..]).unwrap();
        let shown = s.shown_recovery_code().unwrap().as_str().to_owned();
        s.finish_rotation(&shown).unwrap();
        let b2 = persist_v2(&mut s);
        let k_new = derive(PW_NEW, &password_request(&b2).unwrap());
        let w = Session::open_with_password_key(&b2, &k_new[..]).unwrap();
        assert_eq!(w.list("", "").unwrap().len(), 1);
        assert!(Session::open_with_recovery(&b2, &shown).is_ok());
        assert!(Session::open_with_recovery(&b2, &code).is_err());
        assert!(Session::open_with_recovery(&b1, &code).is_ok());
        // Lock drops a pending rotation.
        let req = s.begin_password_change().unwrap();
        let new2 = derive("synthetic third passphrase here", &req);
        let cur2 = derive(PW_NEW, &s.current_password_request().unwrap());
        s.begin_rotation(&cur2[..], &new2[..]).unwrap();
        s.lock();
        assert!(!s.rotation_pending());
        assert!(s.finish_rotation(&shown).is_err());
    }

    #[test]
    fn passphrase_preview_is_saved_exactly_once() {
        let (_k, mut s) = session();
        let shown = s
            .preview_passphrase(r#"{"words":6,"separator":"space"}"#)
            .unwrap();
        assert!(s.save_preview("passphrase", "not it", "t", "").is_err());
        let id = s
            .save_preview("passphrase", &shown, "Synthetic passphrase", "")
            .unwrap();
        assert_eq!(s.reveal(&id, "secret").unwrap().as_str(), shown.as_str());
        assert!(s.save_preview("passphrase", &shown, "again", "").is_err());
        assert!(s
            .preview_passphrase(r#"{"words":2,"separator":"space"}"#)
            .is_err());
        s.lock();
        assert!(s
            .preview_passphrase(r#"{"words":6,"separator":"space"}"#)
            .is_err());
    }

    #[test]
    fn prf_enrolment_unlock_and_removal_through_the_bridge() {
        use sha2::{Digest, Sha256};
        let (mut s, code) = new_protected();
        let b0 = persist_v2(&mut s);
        let cur = derive(PW, &s.current_password_request().unwrap());
        // Enrolment needs the parameters the core issued first.
        assert!(s
            .finish_prf_enrolment(&cur[..], &[3; 16], "keymesh.cloud", false, "k", &[1; 32])
            .is_err());
        assert!(
            s.begin_prf_enrolment(&[7; 32]).is_err(),
            "wrong password: refused before any ceremony"
        );
        let e = s.begin_prf_enrolment(&cur[..]).unwrap();
        assert_eq!(
            data_encoding::BASE64URL_NOPAD
                .decode(e.salt.as_bytes())
                .unwrap()
                .len(),
            32
        );
        // Wrong current password: refused (and the parameters are consumed).
        assert!(s
            .finish_prf_enrolment(&[7; 32], &[3; 16], "keymesh.cloud", false, "k", &[1; 32])
            .is_err());
        s.begin_prf_enrolment(&cur[..]).unwrap();
        assert!(s
            .finish_prf_enrolment(&cur[..], &[3; 16], "keymesh.cloud", false, "k", &[1; 31])
            .is_err());
        s.begin_prf_enrolment(&cur[..]).unwrap();
        s.finish_prf_enrolment(
            &cur[..],
            &[3; 16],
            "keymesh.cloud",
            false,
            "Synthetic key",
            &[1; 32],
        )
        .unwrap();
        let b1 = persist_v2(&mut s);
        let req = prf_request(&b1).unwrap();
        assert_eq!(req.len(), 1);
        assert!(prf_request(&b0).unwrap().is_empty());
        let mut ad = Sha256::digest(b"keymesh.cloud").to_vec();
        ad.extend_from_slice(&[0x05, 0, 0, 0, 1]);
        let u = Session::open_with_prf(&b1, &[3; 16], &ad, &[1; 32], "keymesh.cloud").unwrap();
        assert_eq!(u.prf_slots().unwrap().len(), 1);
        assert!(Session::open_with_prf(&b1, &[3; 16], &ad, &[2; 32], "keymesh.cloud").is_err());
        // Rotation with a passkey: refused unless revoking.
        let req = s.begin_password_change().unwrap();
        let new = derive("synthetic bridge prf rotation pw", &req);
        assert!(s.begin_rotation(&cur[..], &new[..]).is_err());
        let req = s.begin_password_change().unwrap();
        let new = derive("synthetic bridge prf rotation pw", &req);
        s.begin_rotation_revoking_quick_unlock(&cur[..], &new[..])
            .unwrap();
        s.cancel_rotation();
        // Removal.
        let id = s.prf_slots().unwrap()[0].slot_id.clone();
        s.remove_prf_slot(&cur[..], &id).unwrap();
        let b2 = persist_v2(&mut s);
        assert!(Session::open_with_prf(&b2, &[3; 16], &ad, &[1; 32], "keymesh.cloud").is_err());
        assert!(Session::open_with_recovery(&b2, &code).is_ok());
        s.lock();
        assert!(s.begin_prf_enrolment(&cur[..]).is_err());
    }

    /// Review fix C-CORE-1 through the bridge: finish + seal + commit, then
    /// reopen with password, recovery and PRF, for long credential ids.
    #[test]
    fn long_prf_credential_ids_persist_and_reopen_through_the_bridge() {
        use sha2::{Digest, Sha256};
        for n in [49usize, 64, 1023] {
            let (mut s, code) = new_protected();
            let cur = derive(PW, &s.current_password_request().unwrap());
            s.begin_prf_enrolment(&cur[..]).unwrap();
            let cred: Vec<u8> = (0..n).map(|i| (i * 7 % 256) as u8).collect();
            s.finish_prf_enrolment(&cur[..], &cred, "keymesh.cloud", false, "long", &[9; 32])
                .unwrap();
            let b = persist_v2(&mut s);
            assert_eq!(prf_request(&b).unwrap()[0].credential_id, cred, "{n}");
            let k = derive(PW, &password_request(&b).unwrap());
            assert!(
                Session::open_with_password_key(&b, &k[..]).is_ok(),
                "{n}: password"
            );
            assert!(
                Session::open_with_recovery(&b, &code).is_ok(),
                "{n}: recovery"
            );
            let mut ad = Sha256::digest(b"keymesh.cloud").to_vec();
            ad.extend_from_slice(&[0x05, 0, 0, 0, 1]);
            assert!(
                Session::open_with_prf(&b, &cred, &ad, &[9; 32], "keymesh.cloud").is_ok(),
                "{n}: prf"
            );
        }
    }
}
