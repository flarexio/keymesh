//! In-memory vault and its versioned encrypted file formats.
//!
//! ```text
//! v1 (demo/test key providers only; read and written for synthetic data)
//!   format = "keymesh.vault", version = 1, aead = "xchacha20poly1305"
//!   vault_id (random 128-bit hex), kek_id (key provider id), revision (u64)
//!   wrapped_dek : Seal(KEK, AAD = dek_aad(vault_id, kek_id), DEK)
//!   manifest    : Seal(DEK, AAD = header_aad(..revision..), [{id, rev, sha256(item sealed)}])
//!   items[]     : {id, rev, sealed: Seal(DEK, AAD = item_aad(vault_id, id, rev), Item JSON)}
//!
//! v2 (password + recovery key slots; see `keyslot` and docs/adr/0002-envelope-v2.md)
//!   format = "keymesh.vault", version = 2, aead = "xchacha20poly1305"
//!   vault_id, revision
//!   slots[]     : exactly one password slot and one recovery slot, each
//!                 wrapping the same DEK
//!   manifest    : Seal(DEK, AAD = fields(.."manifest"..vault_id, revision, slots_digest), …)
//!   items[]     : {id, rev, sealed: Seal(DEK, AAD = fields(.."item"..vault_id, id, rev), Item JSON)}
//! ```
//!
//! Public metadata is limited to the header, the key slots' public KDF
//! parameters and each item's random id and revision. Titles, URLs, notes,
//! kinds and all secret fields are encrypted. The manifest is bound to the
//! header revision (and in v2 to the exact slot list) and lists every item
//! record's digest, so dropping, duplicating, or swapping individual item
//! records or key slots is detected. Rolling back the *entire* file to an
//! older valid version cannot be detected without external state
//! (documented limitation).
//!
//! The version is chosen by the file, never by the caller: a v1 file opens
//! only with a [`KeyProvider`], a v2 file only with its password or recovery
//! code, and an unknown version is refused.

use crate::crypto::{self, Key256, KeyProvider, Sealed, AEAD_ALG};
use crate::error::{Error, Result};
use crate::kdf::fields;
use crate::keyslot::{
    Authority, PasswordSetup, PrfSetup, Slot, SlotKind, SlotRecord, SlotSet, PRF_LEN,
};
use crate::model::{Item, ItemData, ItemId, ItemKind};
use crate::recovery::RecoveryCode;
use crate::rng::{random_array, RandomSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const FORMAT: &str = "keymesh.vault";
pub const VERSION: u32 = 1;
pub const VERSION_V2: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    format: String,
    version: u32,
    aead: String,
    vault_id: String,
    kek_id: String,
    revision: u64,
    wrapped_dek: Sealed,
    manifest: Sealed,
    items: Vec<ItemRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFileV2 {
    format: String,
    version: u32,
    aead: String,
    vault_id: String,
    revision: u64,
    slots: Vec<SlotRecord>,
    manifest: Sealed,
    items: Vec<ItemRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemRecord {
    id: ItemId,
    rev: u64,
    sealed: Sealed,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manifest {
    vault_id: String,
    revision: u64,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManifestEntry {
    id: ItemId,
    rev: u64,
    sha256: String,
}

/// Minimal header readable without keys. Used to refuse unknown formats and
/// to detect concurrent writers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    pub version: u32,
    pub vault_id: String,
    /// v1 only: the key provider id. `None` for v2 (key slots).
    pub kek_id: Option<String>,
    pub revision: u64,
}

fn dek_aad(vault_id: &str, kek_id: &str) -> Vec<u8> {
    format!("{FORMAT}\0v{VERSION}\0dek\0{AEAD_ALG}\0{vault_id}\0{kek_id}").into_bytes()
}

fn header_aad(vault_id: &str, kek_id: &str, revision: u64) -> Vec<u8> {
    format!("{FORMAT}\0v{VERSION}\0manifest\0{AEAD_ALG}\0{vault_id}\0{kek_id}\0{revision}")
        .into_bytes()
}

fn item_aad(vault_id: &str, id: &ItemId, rev: u64) -> Vec<u8> {
    format!("{FORMAT}\0v{VERSION}\0item\0{AEAD_ALG}\0{vault_id}\0{id}\0{rev}").into_bytes()
}

fn header_aad_v2(vault_id: &str, revision: u64, slots: &SlotSet) -> Vec<u8> {
    fields(&[
        FORMAT.as_bytes(),
        b"2",
        b"manifest",
        AEAD_ALG.as_bytes(),
        vault_id.as_bytes(),
        &revision.to_be_bytes(),
        &slots.digest(),
    ])
}

fn item_aad_v2(vault_id: &str, id: &ItemId, rev: u64) -> Vec<u8> {
    fields(&[
        FORMAT.as_bytes(),
        b"2",
        b"item",
        AEAD_ALG.as_bytes(),
        vault_id.as_bytes(),
        id.to_string().as_bytes(),
        &rev.to_be_bytes(),
    ])
}

fn sha256_hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(b))
}

fn valid_vault_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

enum ParsedFile {
    V1(VaultFile),
    V2(VaultFileV2, SlotSet),
}

/// Walks a JSON document from its original bytes and fails on any object
/// that repeats a member name, at any depth. `serde_json::Value` keeps only
/// the last of duplicate names, so this must run on the raw text first.
struct NoDuplicates;

impl<'de> serde::de::DeserializeSeed<'de> for NoDuplicates {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for NoDuplicates {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON")
    }
    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<(), A::Error> {
        while seq.next_element_seed(NoDuplicates)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<(), A::Error> {
        let mut names = std::collections::BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate member name"));
            }
            map.next_value_seed(NoDuplicates)?;
        }
        Ok(())
    }
}

fn reject_duplicate_members(bytes: &[u8]) -> Result<()> {
    use serde::de::DeserializeSeed;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    NoDuplicates
        .deserialize(&mut de)
        .and_then(|()| de.end())
        .map_err(|_| {
            Error::Format("not a keymesh vault (malformed or duplicate JSON members)".into())
        })
}

/// Parse and validate the unencrypted envelope without decrypting. Every
/// bound (version, algorithm, ids, key slots and their KDF cost) is checked
/// here, before any key derivation. Duplicate JSON member names anywhere in
/// the envelope are refused first, so every reader sees one unambiguous value.
fn parse_any(bytes: &[u8]) -> Result<ParsedFile> {
    reject_duplicate_members(bytes)?;
    // Check format/version before strict parsing so future versions produce a
    // clear "unknown format" error rather than a schema error.
    let probe: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::Format("not a keymesh vault (unparseable)".into()))?;
    let fmt = probe.get("format").and_then(|v| v.as_str());
    let ver = probe.get("version").and_then(|v| v.as_u64());
    if fmt != Some(FORMAT) {
        return Err(Error::Format("not a keymesh vault".into()));
    }
    let parsed = match ver {
        Some(v) if v == u64::from(VERSION) => {
            let f: VaultFile = serde_json::from_value(probe)
                .map_err(|_| Error::Format("malformed keymesh vault envelope".into()))?;
            if f.aead != AEAD_ALG {
                return Err(Error::Format("unsupported AEAD algorithm".into()));
            }
            ParsedFile::V1(f)
        }
        Some(v) if v == u64::from(VERSION_V2) => {
            let f: VaultFileV2 = serde_json::from_value(probe)
                .map_err(|_| Error::Format("malformed keymesh vault envelope".into()))?;
            if f.aead != AEAD_ALG {
                return Err(Error::Format("unsupported AEAD algorithm".into()));
            }
            if !valid_vault_id(&f.vault_id) {
                return Err(Error::Format("invalid vault id".into()));
            }
            let slots = SlotSet::from_records(f.slots.clone())?;
            ParsedFile::V2(f, slots)
        }
        _ => return Err(Error::Format("unsupported vault version".into())),
    };
    Ok(parsed)
}

pub fn read_header(bytes: &[u8]) -> Result<VaultHeader> {
    Ok(match parse_any(bytes)? {
        ParsedFile::V1(f) => VaultHeader {
            version: VERSION,
            vault_id: f.vault_id,
            kek_id: Some(f.kek_id),
            revision: f.revision,
        },
        ParsedFile::V2(f, _) => VaultHeader {
            version: VERSION_V2,
            vault_id: f.vault_id,
            kek_id: None,
            revision: f.revision,
        },
    })
}

/// Public parameters for deriving the password key of a v2 envelope (the
/// browser runs Argon2id in a worker with them). Bounds are already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRequest {
    pub vault_id: String,
    pub setup: PasswordSetup,
}

pub fn password_request(bytes: &[u8]) -> Result<PasswordRequest> {
    match parse_any(bytes)? {
        ParsedFile::V2(f, slots) => Ok(PasswordRequest {
            vault_id: f.vault_id,
            setup: slots.get(SlotKind::Password).password_setup()?,
        }),
        ParsedFile::V1(_) => Err(Error::Format(
            "this is a demo vault without a password".into(),
        )),
    }
}

/// What a browser needs to ask for a quick-unlock assertion: per stored
/// `webauthn-prf` slot, its credential id and PRF input. Public data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrfRequest {
    pub slot_id: String,
    #[serde(serialize_with = "ser_b64")]
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    #[serde(serialize_with = "ser_b64")]
    pub salt: Vec<u8>,
    pub label: String,
    pub be: bool,
}

fn ser_b64<S: serde::Serializer>(v: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(v))
}

impl PrfRequest {
    fn of(slot: &Slot) -> Option<Self> {
        let p = slot.prf_params()?;
        Some(Self {
            slot_id: slot.id().to_owned(),
            credential_id: p.credential_id.to_vec(),
            rp_id: p.rp_id.to_owned(),
            salt: p.salt.to_vec(),
            label: p.label.to_owned(),
            be: p.be,
        })
    }
}

pub fn prf_request(bytes: &[u8]) -> Result<Vec<PrfRequest>> {
    match parse_any(bytes)? {
        ParsedFile::V2(_, slots) => Ok(slots.prf_slots().filter_map(PrfRequest::of).collect()),
        ParsedFile::V1(_) => Err(Error::Format(
            "this is a demo vault without a password".into(),
        )),
    }
}

/// WebAuthn authenticator data flags: user present, user verified.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// rpIdHash and UP/UV flags of an assertion's authenticator data.
fn check_assertion(authenticator_data: &[u8], rp_id: &str) -> Result<()> {
    if authenticator_data.len() < 37 {
        return Err(Error::Decrypt);
    }
    let rp_hash: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    let ok_hash = bool::from(authenticator_data[..32].ct_eq(&rp_hash));
    let flags = authenticator_data[32];
    if !ok_hash || flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(Error::Decrypt);
    }
    Ok(())
}

/// How a vault's data key is protected.
#[derive(Clone)]
enum Keys {
    /// v1: one KEK from a key provider (demo/test only).
    Provider { kek_id: String },
    /// v2: password + recovery slots. `recovery_confirmed` is false for a
    /// new vault until its recovery code was entered back; sealing (and so
    /// persisting) is refused until then.
    Slots {
        slots: SlotSet,
        recovery_confirmed: bool,
    },
}

/// A new recovery code waiting for confirmation before it replaces the
/// vault's recovery slot.
pub struct PendingRecovery {
    code: RecoveryCode,
    slot: Slot,
}

impl PendingRecovery {
    pub fn code(&self) -> &RecoveryCode {
        &self.code
    }
}

/// A quick-unlock enrolment in progress: core-issued parameters, bound to
/// the vault state its authority was checked against.
pub struct PendingPrf {
    setup: PrfSetup,
    vault_id: String,
    source_slots: [u8; 32],
    source_dek: Key256,
}

impl PendingPrf {
    pub fn setup(&self) -> &PrfSetup {
        &self.setup
    }
}

/// A data-key rotation waiting for its new recovery code to be typed back.
/// Holds the new DEK and the new password and recovery slots; the vault it
/// came from is unchanged until [`Vault::finish_rotation`].
pub struct PendingRotation {
    vault_id: String,
    /// Digest of the slots the authority was verified against, and the data
    /// key it unwrapped: the rotation can only finish on that exact vault and
    /// credential state (never on another vault, or after another change).
    source_slots: [u8; 32],
    source_dek: Key256,
    dek: Key256,
    slots: SlotSet,
    code: RecoveryCode,
}

impl PendingRotation {
    /// The new recovery code, shown once.
    pub fn code(&self) -> &RecoveryCode {
        &self.code
    }
}

/// `Clone` lets storage adapters keep a last-committed checkpoint; clones hold
/// their own copy of the data key, zeroized on drop like the original.
#[derive(Clone)]
pub struct Vault {
    vault_id: String,
    keys: Keys,
    /// Revision of the file this vault was decrypted from (0 for a new vault).
    loaded_revision: u64,
    /// SHA-256 of the exact bytes last read or written (compare-and-swap).
    snapshot: Option<[u8; 32]>,
    dek: Key256,
    items: BTreeMap<ItemId, Item>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.vault_id)
            .field("revision", &self.loaded_revision)
            .field("items", &self.items.len())
            .finish()
    }
}

/// Public parameters for creating a new password-protected vault: its id
/// and the password slot's id, salt and KDF cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSetup {
    pub vault_id: String,
    pub password: PasswordSetup,
}

impl ProtectedSetup {
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Self {
            vault_id: data_encoding::HEXLOWER.encode(&random_array::<16>(rng)?),
            password: PasswordSetup::generate(rng)?,
        })
    }
}

impl Vault {
    /// New empty v1 vault with a fresh random data key (demo/test providers).
    pub fn create(provider: &dyn KeyProvider, rng: &mut dyn RandomSource) -> Result<Self> {
        crypto::validate_key_id(provider.key_id())?;
        // Ensure the provider is usable before we hand out a vault.
        provider.key_encryption_key()?;
        Ok(Self {
            vault_id: data_encoding::HEXLOWER.encode(&random_array::<16>(rng)?),
            keys: Keys::Provider {
                kek_id: provider.key_id().to_owned(),
            },
            loaded_revision: 0,
            snapshot: None,
            dek: Key256::generate(rng)?,
            items: BTreeMap::new(),
        })
    }

    /// New empty v2 vault with a fresh random data key, a password slot from
    /// `password_key` (Argon2id output for `setup.password`) and a fresh
    /// recovery code. The vault cannot be sealed until
    /// [`Vault::confirm_recovery`] succeeds with that code.
    pub fn create_protected(
        setup: &ProtectedSetup,
        password_key: &[u8; 32],
        rng: &mut dyn RandomSource,
    ) -> Result<(Self, RecoveryCode)> {
        if !valid_vault_id(&setup.vault_id) {
            return Err(Error::validation("invalid vault id"));
        }
        let dek = Key256::generate(rng)?;
        let code = RecoveryCode::generate(rng)?;
        let pw = Slot::new_password(&setup.vault_id, &setup.password, password_key, &dek, rng)?;
        let rc = Slot::new_recovery(&setup.vault_id, &code, &dek, rng)?;
        let v = Self {
            vault_id: setup.vault_id.clone(),
            keys: Keys::Slots {
                slots: SlotSet::new(pw, rc)?,
                recovery_confirmed: false,
            },
            loaded_revision: 0,
            snapshot: None,
            dek,
            items: BTreeMap::new(),
        };
        Ok((v, code))
    }

    /// Native convenience: run Argon2id and create a v2 vault.
    pub fn create_with_password(
        password: &str,
        rng: &mut dyn RandomSource,
    ) -> Result<(Self, RecoveryCode)> {
        crate::kdf::check_new_password(password)?;
        let setup = ProtectedSetup::generate(rng)?;
        let key = setup.password.derive(password)?;
        Self::create_protected(&setup, &key, rng)
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn revision(&self) -> u64 {
        self.loaded_revision
    }
    /// True for a v2 (password + recovery) vault.
    pub fn is_protected(&self) -> bool {
        matches!(self.keys, Keys::Slots { .. })
    }
    /// v2: whether the recovery code has been confirmed (always true for an
    /// opened vault). v1: true.
    pub fn recovery_confirmed(&self) -> bool {
        match &self.keys {
            Keys::Slots {
                recovery_confirmed, ..
            } => *recovery_confirmed,
            Keys::Provider { .. } => true,
        }
    }
    /// SHA-256 of the exact envelope bytes last read or written.
    pub fn snapshot_digest(&self) -> Option<[u8; 32]> {
        self.snapshot
    }

    fn slots(&self) -> Result<&SlotSet> {
        match &self.keys {
            Keys::Slots { slots, .. } => Ok(slots),
            Keys::Provider { .. } => Err(Error::Format(
                "this is a demo vault without a password".into(),
            )),
        }
    }

    /// Public parameters of the current password slot (to derive the key
    /// for [`Authority::PasswordKey`]).
    pub fn password_setup(&self) -> Result<PasswordSetup> {
        self.slots()?.get(SlotKind::Password).password_setup()
    }

    /// Prove that `code` is this vault's recovery code (by unwrapping the
    /// recovery slot); a new vault becomes sealable after this succeeds.
    pub fn confirm_recovery(&mut self, code: &RecoveryCode) -> Result<()> {
        Authority::Recovery(code)
            .verify(&self.vault_id, self.slots()?, &self.dek)
            .map_err(|_| Error::validation("recovery code does not match"))?;
        if let Keys::Slots {
            recovery_confirmed, ..
        } = &mut self.keys
        {
            *recovery_confirmed = true;
        }
        Ok(())
    }

    /// Replace the password slot (rewrap; the data key is unchanged, so
    /// backups made earlier still open with the old password). Requires
    /// `authority` over this vault; `new_password_key` is Argon2id output
    /// for `setup`, which must use a fresh slot id and salt.
    pub fn change_password(
        &mut self,
        authority: Authority<'_>,
        setup: &PasswordSetup,
        new_password_key: &[u8; 32],
        rng: &mut dyn RandomSource,
    ) -> Result<()> {
        let slots = self.slots()?;
        authority.verify(&self.vault_id, slots, &self.dek)?;
        let old = slots.get(SlotKind::Password).password_setup()?;
        if old.slot_id == setup.slot_id || bool::from(old.salt.ct_eq(&setup.salt)) {
            return Err(Error::validation("a new password needs a fresh salt"));
        }
        let slot = Slot::new_password(&self.vault_id, setup, new_password_key, &self.dek, rng)?;
        let next = slots.replace(slot)?;
        if let Keys::Slots { slots, .. } = &mut self.keys {
            *slots = next;
        }
        Ok(())
    }

    /// Start replacing the recovery code. Nothing changes until
    /// [`Vault::finish_recovery_change`] gets the new code back.
    pub fn begin_recovery_change(
        &self,
        authority: Authority<'_>,
        rng: &mut dyn RandomSource,
    ) -> Result<PendingRecovery> {
        let slots = self.slots()?;
        authority.verify(&self.vault_id, slots, &self.dek)?;
        let code = RecoveryCode::generate(rng)?;
        let slot = Slot::new_recovery(&self.vault_id, &code, &self.dek, rng)?;
        Ok(PendingRecovery { code, slot })
    }

    /// Install a pending recovery code once the user entered it back.
    ///
    /// The pending wrapper must belong to THIS vault: it is unwrapped with
    /// this vault's id and the confirmed code, and the result must equal this
    /// vault's DEK (constant time). A pending code made for another vault (or
    /// any wrapper that does not open to this DEK) is refused and nothing
    /// changes. A pending code stays valid across a password change of the
    /// same vault, because the DEK is unchanged.
    pub fn finish_recovery_change(
        &mut self,
        pending: PendingRecovery,
        confirmation: &RecoveryCode,
    ) -> Result<()> {
        if !pending.code.ct_eq(confirmation) {
            return Err(Error::validation("recovery code does not match"));
        }
        let wrong_vault = || Error::validation("this recovery code was made for another vault");
        let dek = pending
            .slot
            .unwrap(&self.vault_id, confirmation.secret())
            .map_err(|_| wrong_vault())?;
        if !bool::from(dek.as_bytes().ct_eq(self.dek.as_bytes())) {
            return Err(wrong_vault());
        }
        let next = self.slots()?.replace(pending.slot)?;
        if let Keys::Slots {
            slots,
            recovery_confirmed,
        } = &mut self.keys
        {
            *slots = next;
            *recovery_confirmed = true;
        }
        Ok(())
    }

    /// Check `authority` over this vault without changing anything (so a
    /// wrong password is refused BEFORE an external ceremony, e.g. creating
    /// a passkey that could not then be added).
    pub fn verify_authority(&self, authority: Authority<'_>) -> Result<()> {
        authority.verify(&self.vault_id, self.slots()?, &self.dek)
    }

    /// Start a quick-unlock enrolment: `authority` is checked first (so a
    /// wrong password never reaches a passkey ceremony), then fresh public
    /// parameters are issued, bound to THIS vault's id, exact slot set and
    /// DEK. The enrolment can only finish on that same state.
    pub fn begin_prf(
        &self,
        authority: Authority<'_>,
        rng: &mut dyn RandomSource,
    ) -> Result<PendingPrf> {
        let slots = self.slots()?;
        authority.verify(&self.vault_id, slots, &self.dek)?;
        Ok(PendingPrf {
            setup: PrfSetup::generate(rng)?,
            vault_id: self.vault_id.clone(),
            source_slots: slots.digest(),
            source_dek: self.dek.clone(),
        })
    }

    /// Quick-unlock slots of this vault (public data).
    pub fn prf_slots(&self) -> Result<Vec<PrfRequest>> {
        Ok(self
            .slots()?
            .prf_slots()
            .filter_map(PrfRequest::of)
            .collect())
    }

    /// Enrol a quick-unlock passkey: a new `webauthn-prf` slot wrapping this
    /// vault's DEK under the authenticator's PRF output. Needs `authority`
    /// (the master password: a sensitive operation, ADR 0003 §4.4). The new
    /// slot is unwrapped again in memory and must yield this DEK (constant
    /// time) before it is added. Nothing else changes.
    #[allow(clippy::too_many_arguments)]
    pub fn add_prf_slot(
        &mut self,
        authority: Authority<'_>,
        pending: &PendingPrf,
        credential_id: &[u8],
        rp_id: &str,
        be: bool,
        label: &str,
        prf_output: &[u8; PRF_LEN],
        rng: &mut dyn RandomSource,
    ) -> Result<()> {
        let slots = self.slots()?;
        authority.verify(&self.vault_id, slots, &self.dek)?;
        if pending.vault_id != self.vault_id
            || slots.digest() != pending.source_slots
            || !bool::from(pending.source_dek.as_bytes().ct_eq(self.dek.as_bytes()))
        {
            return Err(Error::validation(
                "this enrolment was started for another vault or credential state",
            ));
        }
        let setup = &pending.setup;
        if slots.records().iter().any(|r| r.id == setup.slot_id) {
            return Err(Error::validation("a new key slot needs a fresh id"));
        }
        let slot = Slot::new_prf(
            &self.vault_id,
            setup,
            credential_id,
            rp_id,
            be,
            label,
            prf_output,
            &self.dek,
            rng,
        )?;
        let back = slot.unwrap(&self.vault_id, &prf_output[..])?;
        if !bool::from(back.as_bytes().ct_eq(self.dek.as_bytes())) {
            return Err(Error::Integrity(
                "quick-unlock slot does not open this vault".into(),
            ));
        }
        let next = slots.with_prf(slot)?;
        if let Keys::Slots { slots, .. } = &mut self.keys {
            *slots = next;
        }
        Ok(())
    }

    /// Remove one quick-unlock slot. Needs `authority`. Copies of the vault
    /// made earlier still contain the slot (not revoked).
    pub fn remove_prf_slot(&mut self, authority: Authority<'_>, slot_id: &str) -> Result<()> {
        let slots = self.slots()?;
        authority.verify(&self.vault_id, slots, &self.dek)?;
        let next = slots.without_prf(slot_id)?;
        if let Keys::Slots { slots, .. } = &mut self.keys {
            *slots = next;
        }
        Ok(())
    }

    /// Start a compromise rotation of a v2 vault: a fresh data key, and fresh
    /// password and recovery slots for it (ADR 0002 §8). Needs `authority`
    /// over this vault; `setup` must be fresh (new slot id and salt) and
    /// `new_password_key` its Argon2id output. A new recovery code is always
    /// generated. Nothing changes in `self`.
    ///
    /// Extension point: only password and recovery slots exist today. When
    /// other slot kinds are added, each must be re-established here from a
    /// re-authenticated capability or explicitly revoked by the caller; the
    /// parser keeps refusing unknown kinds, so none can be dropped silently.
    pub fn begin_rotation(
        &self,
        authority: Authority<'_>,
        setup: &PasswordSetup,
        new_password_key: &[u8; 32],
        rng: &mut dyn RandomSource,
    ) -> Result<PendingRotation> {
        self.begin_rotation_with(authority, setup, new_password_key, false, rng)
    }

    /// [`Vault::begin_rotation`] for a vault with quick-unlock (PRF) slots:
    /// they wrap the old DEK and their authenticators are not present, so
    /// rotation REVOKES them (the rotated vault has none; enrol again
    /// afterwards). The caller passes this only after the user confirmed.
    pub fn begin_rotation_revoking_quick_unlock(
        &self,
        authority: Authority<'_>,
        setup: &PasswordSetup,
        new_password_key: &[u8; 32],
        rng: &mut dyn RandomSource,
    ) -> Result<PendingRotation> {
        self.begin_rotation_with(authority, setup, new_password_key, true, rng)
    }

    fn begin_rotation_with(
        &self,
        authority: Authority<'_>,
        setup: &PasswordSetup,
        new_password_key: &[u8; 32],
        revoke_quick_unlock: bool,
        rng: &mut dyn RandomSource,
    ) -> Result<PendingRotation> {
        let slots = self.slots()?;
        authority.verify(&self.vault_id, slots, &self.dek)?;
        if slots.prf_slots().next().is_some() && !revoke_quick_unlock {
            return Err(Error::validation(
                "rotation would revoke quick-unlock passkeys; confirm first",
            ));
        }
        let old = slots.get(SlotKind::Password).password_setup()?;
        if old.slot_id == setup.slot_id || bool::from(old.salt.ct_eq(&setup.salt)) {
            return Err(Error::validation("a new password needs a fresh salt"));
        }
        let dek = Key256::generate(rng)?;
        if bool::from(dek.as_bytes().ct_eq(self.dek.as_bytes())) {
            return Err(Error::Rng);
        }
        let code = RecoveryCode::generate(rng)?;
        let pw = Slot::new_password(&self.vault_id, setup, new_password_key, &dek, rng)?;
        let rc = Slot::new_recovery(&self.vault_id, &code, &dek, rng)?;
        Ok(PendingRotation {
            vault_id: self.vault_id.clone(),
            source_slots: slots.digest(),
            source_dek: self.dek.clone(),
            dek,
            slots: SlotSet::new(pw, rc)?,
            code,
        })
    }

    /// Finish a rotation once the new recovery code was typed back. Returns
    /// the rotated vault: same id, items, revision and snapshot (so the
    /// usual compare-and-swap applies when it is saved), with the new data
    /// key and slots. `self` stays as it was; the caller saves the rotated
    /// vault and only then replaces its own. The pending rotation is only
    /// borrowed, so a mistyped code can be retried.
    pub fn finish_rotation(
        &self,
        pending: &PendingRotation,
        confirmation: &RecoveryCode,
    ) -> Result<Vault> {
        let same_source = match self.slots() {
            Ok(slots) => {
                pending.vault_id == self.vault_id
                    && slots.digest() == pending.source_slots
                    && bool::from(pending.source_dek.as_bytes().ct_eq(self.dek.as_bytes()))
            }
            Err(_) => false,
        };
        if !same_source {
            return Err(Error::validation(
                "this rotation was started for another vault or credential state",
            ));
        }
        if !pending.code.ct_eq(confirmation) {
            return Err(Error::validation("recovery code does not match"));
        }
        Authority::Recovery(confirmation)
            .verify(&self.vault_id, &pending.slots, &pending.dek)
            .map_err(|_| Error::validation("recovery code does not match"))?;
        Ok(Vault {
            vault_id: self.vault_id.clone(),
            keys: Keys::Slots {
                slots: pending.slots.clone(),
                recovery_confirmed: true,
            },
            loaded_revision: self.loaded_revision,
            snapshot: self.snapshot,
            dek: pending.dek.clone(),
            items: self.items.clone(),
        })
    }

    /// Decrypt and fully verify a v1 vault file with a key provider. Any
    /// failure is an error; a failed decrypt never yields an empty vault.
    pub fn decrypt(bytes: &[u8], provider: &dyn KeyProvider) -> Result<Self> {
        let f = match parse_any(bytes)? {
            ParsedFile::V1(f) => f,
            ParsedFile::V2(..) => {
                return Err(Error::Format(
                    "this vault opens with its password or recovery code".into(),
                ))
            }
        };
        if provider.key_id() != f.kek_id {
            return Err(Error::KeyProvider(
                "key provider id does not match vault".into(),
            ));
        }
        let kek = provider.key_encryption_key()?;
        let dek_bytes = crypto::open(&kek, &f.wrapped_dek, &dek_aad(&f.vault_id, &f.kek_id))?;
        let dek_arr: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity("data key has wrong length".into()))?;
        let dek = Key256::from_bytes(dek_arr);
        let maad = header_aad(&f.vault_id, &f.kek_id, f.revision);
        let items = open_items(
            &dek,
            &f.manifest,
            &maad,
            &f.vault_id,
            f.revision,
            &f.items,
            |id, rev| item_aad(&f.vault_id, id, rev),
        )?;
        let v = Self {
            vault_id: f.vault_id,
            keys: Keys::Provider { kek_id: f.kek_id },
            loaded_revision: f.revision,
            snapshot: Some(Sha256::digest(bytes).into()),
            dek,
            items,
        };
        v.validate_references()?;
        Ok(v)
    }

    /// Open a v2 envelope with Argon2id output for its password slot (see
    /// [`password_request`]).
    pub fn open_with_password_key(bytes: &[u8], password_key: &[u8; 32]) -> Result<Self> {
        Self::open_v2(bytes, SlotKind::Password, &password_key[..])
    }

    /// Native convenience: derive the password key and open.
    pub fn open_with_password(bytes: &[u8], password: &str) -> Result<Self> {
        let req = password_request(bytes)?;
        let key = req.setup.derive(password)?;
        Self::open_with_password_key(bytes, &key)
    }

    pub fn open_with_recovery(bytes: &[u8], code: &RecoveryCode) -> Result<Self> {
        Self::open_v2(bytes, SlotKind::Recovery, code.secret())
    }

    fn open_v2(bytes: &[u8], kind: SlotKind, ikm: &[u8]) -> Result<Self> {
        Self::open_v2_with(bytes, |slots| Ok(slots.get(kind)), ikm)
    }

    /// Open a v2 file with a quick-unlock (WebAuthn PRF) assertion.
    ///
    /// Fail closed, before any decryption, unless: the credential id names
    /// exactly one stored `webauthn-prf` slot; `authenticator_data` is at
    /// least 37 bytes, its rpIdHash equals SHA-256 of BOTH the slot's stored
    /// rp id and `rp_id` (this origin), and its flags show user presence
    /// (0x01) and user verification (0x04); the PRF output is 32 bytes. The
    /// assertion signature is not verified (no server; the PRF output itself
    /// is the secret), which is a stated limit.
    pub fn open_with_prf(
        bytes: &[u8],
        credential_id: &[u8],
        authenticator_data: &[u8],
        prf_output: &[u8; crate::keyslot::PRF_LEN],
        rp_id: &str,
    ) -> Result<Self> {
        check_assertion(authenticator_data, rp_id)?;
        Self::open_v2_with(
            bytes,
            |slots| {
                let slot = slots.prf_slot(credential_id).ok_or(Error::Decrypt)?;
                let stored = slot.prf_params().ok_or(Error::Decrypt)?;
                if stored.rp_id != rp_id {
                    return Err(Error::Decrypt);
                }
                Ok(slot)
            },
            &prf_output[..],
        )
    }

    fn open_v2_with(
        bytes: &[u8],
        pick: impl FnOnce(&SlotSet) -> Result<&Slot>,
        ikm: &[u8],
    ) -> Result<Self> {
        let (f, slots) = match parse_any(bytes)? {
            ParsedFile::V2(f, slots) => (f, slots),
            ParsedFile::V1(_) => {
                return Err(Error::Format(
                    "this is a demo vault without a password".into(),
                ))
            }
        };
        let dek = pick(&slots)?.unwrap(&f.vault_id, ikm)?;
        let maad = header_aad_v2(&f.vault_id, f.revision, &slots);
        let items = open_items(
            &dek,
            &f.manifest,
            &maad,
            &f.vault_id,
            f.revision,
            &f.items,
            |id, rev| item_aad_v2(&f.vault_id, id, rev),
        )?;
        // The other slots cannot be checked without their secrets; the
        // manifest (sealed with this DEK) binds their exact bytes, so only
        // someone who already held the DEK could have written them.
        let v = Self {
            vault_id: f.vault_id,
            keys: Keys::Slots {
                slots,
                recovery_confirmed: true,
            },
            loaded_revision: f.revision,
            snapshot: Some(Sha256::digest(bytes).into()),
            dek,
            items,
        };
        v.validate_references()?;
        Ok(v)
    }

    /// Encrypt to the next revision and advance the in-memory revision.
    /// Storage code uses [`Vault::seal_next`] so the revision only advances
    /// after the bytes are durably written.
    pub fn encrypt(
        &mut self,
        provider: &dyn KeyProvider,
        rng: &mut dyn RandomSource,
    ) -> Result<Vec<u8>> {
        let (bytes, rev) = self.seal_next(provider, rng)?;
        self.mark_written(rev, &bytes)?;
        Ok(bytes)
    }

    /// For storage adapters: record that the bytes from [`Vault::seal_next`]
    /// for `revision` were durably written. Only the next revision is accepted.
    pub fn mark_persisted(&mut self, revision: u64) -> Result<()> {
        if revision != self.loaded_revision + 1 {
            return Err(Error::Integrity("unexpected persisted revision".into()));
        }
        self.loaded_revision = revision;
        Ok(())
    }

    /// [`Vault::mark_persisted`] plus the exact bytes, for byte-level
    /// compare-and-swap on the next save.
    pub fn mark_written(&mut self, revision: u64, bytes: &[u8]) -> Result<()> {
        self.mark_persisted(revision)?;
        self.snapshot = Some(Sha256::digest(bytes).into());
        Ok(())
    }

    /// v1: encrypt to revision `self.revision() + 1` without mutating the
    /// vault. Every item and the manifest get fresh nonces. Storage adapters
    /// write the bytes, then call [`Vault::mark_persisted`].
    pub fn seal_next(
        &self,
        provider: &dyn KeyProvider,
        rng: &mut dyn RandomSource,
    ) -> Result<(Vec<u8>, u64)> {
        let kek_id = match &self.keys {
            Keys::Provider { kek_id } => kek_id,
            Keys::Slots { .. } => {
                return Err(Error::KeyProvider(
                    "a password vault is sealed with its key slots, not a key provider".into(),
                ))
            }
        };
        if provider.key_id() != kek_id {
            return Err(Error::KeyProvider(
                "key provider id does not match vault".into(),
            ));
        }
        self.validate_references()?;
        let revision = self.loaded_revision + 1;
        let kek = provider.key_encryption_key()?;
        let wrapped_dek = crypto::seal(
            &kek,
            rng,
            &dek_aad(&self.vault_id, kek_id),
            self.dek.as_bytes(),
        )?;
        let (records, manifest) = self.seal_items(
            rng,
            revision,
            &header_aad(&self.vault_id, kek_id, revision),
            |id, rev| item_aad(&self.vault_id, id, rev),
        )?;
        let file = VaultFile {
            format: FORMAT.into(),
            version: VERSION,
            aead: AEAD_ALG.into(),
            vault_id: self.vault_id.clone(),
            kek_id: kek_id.clone(),
            revision,
            wrapped_dek,
            manifest,
            items: records,
        };
        let out = serde_json::to_vec_pretty(&file)
            .map_err(|_| Error::Integrity("serialize vault".into()))?;
        Ok((out, revision))
    }

    /// v2: encrypt to the next revision with the current key slots. Refused
    /// for a new vault whose recovery code was not confirmed yet.
    pub fn seal_next_protected(&self, rng: &mut dyn RandomSource) -> Result<(Vec<u8>, u64)> {
        let (slots, confirmed) = match &self.keys {
            Keys::Slots {
                slots,
                recovery_confirmed,
            } => (slots, *recovery_confirmed),
            Keys::Provider { .. } => {
                return Err(Error::KeyProvider(
                    "demo vault needs its key provider".into(),
                ))
            }
        };
        if !confirmed {
            return Err(Error::validation(
                "confirm the recovery code before saving the vault",
            ));
        }
        self.validate_references()?;
        let revision = self.loaded_revision + 1;
        let (records, manifest) = self.seal_items(
            rng,
            revision,
            &header_aad_v2(&self.vault_id, revision, slots),
            |id, rev| item_aad_v2(&self.vault_id, id, rev),
        )?;
        let file = VaultFileV2 {
            format: FORMAT.into(),
            version: VERSION_V2,
            aead: AEAD_ALG.into(),
            vault_id: self.vault_id.clone(),
            revision,
            slots: slots.records(),
            manifest,
            items: records,
        };
        let out = serde_json::to_vec_pretty(&file)
            .map_err(|_| Error::Integrity("serialize vault".into()))?;
        Ok((out, revision))
    }

    fn seal_items(
        &self,
        rng: &mut dyn RandomSource,
        revision: u64,
        manifest_aad: &[u8],
        item_aad: impl Fn(&ItemId, u64) -> Vec<u8>,
    ) -> Result<(Vec<ItemRecord>, Sealed)> {
        let mut records = Vec::with_capacity(self.items.len());
        let mut entries = Vec::with_capacity(self.items.len());
        for item in self.items.values() {
            item.validate()?;
            let pt = Zeroizing::new(
                serde_json::to_vec(item).map_err(|_| Error::Integrity("serialize item".into()))?,
            );
            let sealed = crypto::seal(&self.dek, rng, &item_aad(&item.id, item.rev), &pt)?;
            entries.push(ManifestEntry {
                id: item.id.clone(),
                rev: item.rev,
                sha256: sha256_hex(&sealed.digest_input()),
            });
            records.push(ItemRecord {
                id: item.id.clone(),
                rev: item.rev,
                sealed,
            });
        }
        let manifest = Manifest {
            vault_id: self.vault_id.clone(),
            revision,
            entries,
        };
        let manifest_pt = serde_json::to_vec(&manifest)
            .map_err(|_| Error::Integrity("serialize manifest".into()))?;
        let manifest = crypto::seal(&self.dek, rng, manifest_aad, &manifest_pt)?;
        Ok((records, manifest))
    }

    /// v1 only: replace the data key; all items are re-encrypted on the next
    /// save. v2 vaults rotate with [`Vault::begin_rotation`], which also
    /// replaces every slot; this never relabels a demo vault.
    pub fn rotate_data_key(&mut self, rng: &mut dyn RandomSource) -> Result<()> {
        if self.is_protected() {
            return Err(Error::validation(
                "data key rotation for password vaults is not supported yet",
            ));
        }
        self.dek = Key256::generate(rng)?;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }
    pub fn get(&self, id: &ItemId) -> Result<&Item> {
        self.items.get(id).ok_or(Error::NotFound)
    }

    pub fn insert(&mut self, item: Item) -> Result<ItemId> {
        item.validate()?;
        if self.items.contains_key(&item.id) {
            return Err(Error::validation("item id already exists"));
        }
        self.check_refs_of(&item)?;
        let id = item.id.clone();
        self.items.insert(id.clone(), item);
        Ok(id)
    }

    /// Apply `f` to a copy of the item; commit only if the result validates.
    pub fn update(&mut self, id: &ItemId, f: impl FnOnce(&mut Item)) -> Result<()> {
        let mut copy = self.get(id)?.clone();
        f(&mut copy);
        if copy.id != *id {
            return Err(Error::validation("item id cannot change"));
        }
        copy.rev = self.get(id)?.rev + 1;
        copy.updated_at = crate::model::unix_now();
        copy.validate()?;
        self.check_refs_of(&copy)?;
        self.items.insert(id.clone(), copy);
        Ok(())
    }

    pub fn remove(&mut self, id: &ItemId) -> Result<Item> {
        let referenced = self.items.values().any(|i| match &i.data {
            ItemData::Login(l) => l.totp_item.as_ref() == Some(id),
            _ => false,
        });
        if referenced {
            return Err(Error::validation("item is referenced by a login"));
        }
        self.items.remove(id).ok_or(Error::NotFound)
    }

    /// Put back a previously cloned item verbatim (import rollback).
    pub(crate) fn restore_item(&mut self, item: Item) {
        self.items.insert(item.id.clone(), item);
    }

    pub fn find_by_source(&self, provider: &str, source_id: &str) -> Option<&Item> {
        self.items.values().find(|i| {
            i.source
                .as_ref()
                .is_some_and(|s| s.provider == provider && s.source_id == source_id)
        })
    }

    fn check_refs_of(&self, item: &Item) -> Result<()> {
        if let ItemData::Login(l) = &item.data {
            if let Some(t) = &l.totp_item {
                match self.items.get(t) {
                    Some(target) if target.kind() == ItemKind::Totp => {}
                    _ => {
                        return Err(Error::validation(
                            "login totp reference must point to a TOTP item",
                        ))
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_references(&self) -> Result<()> {
        for i in self.items.values() {
            self.check_refs_of(i)?;
        }
        Ok(())
    }
}

/// Verify the manifest and decrypt every item record (shared by v1 and v2).
fn open_items(
    dek: &Key256,
    manifest: &Sealed,
    manifest_aad: &[u8],
    vault_id: &str,
    revision: u64,
    records: &[ItemRecord],
    item_aad: impl Fn(&ItemId, u64) -> Vec<u8>,
) -> Result<BTreeMap<ItemId, Item>> {
    let manifest_pt = crypto::open(dek, manifest, manifest_aad)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_pt)
        .map_err(|_| Error::Integrity("malformed manifest".into()))?;
    if manifest.vault_id != vault_id || manifest.revision != revision {
        return Err(Error::Integrity("manifest does not match header".into()));
    }
    if manifest.entries.len() != records.len() {
        return Err(Error::Integrity(
            "item count does not match manifest".into(),
        ));
    }
    let mut items = BTreeMap::new();
    for (rec, entry) in records.iter().zip(&manifest.entries) {
        if rec.id != entry.id
            || rec.rev != entry.rev
            || sha256_hex(&rec.sealed.digest_input()) != entry.sha256
        {
            return Err(Error::Integrity(
                "item record does not match manifest".into(),
            ));
        }
        let pt = crypto::open(dek, &rec.sealed, &item_aad(&rec.id, rec.rev))?;
        let item: Item = serde_json::from_slice(&pt)
            .map_err(|_| Error::Integrity("malformed item payload".into()))?;
        if item.id != rec.id || item.rev != rec.rev {
            return Err(Error::Integrity(
                "item payload does not match record".into(),
            ));
        }
        item.validate()?;
        if items.insert(item.id.clone(), item).is_some() {
            return Err(Error::Integrity("duplicate item id".into()));
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EphemeralKeyProvider;
    use crate::model::{Login, SecureNote, TotpRecord};
    use crate::rng::OsRandom;
    use crate::secret::{SecretBytes, SecretString};
    use crate::totp::TotpConfig;

    fn provider() -> EphemeralKeyProvider {
        EphemeralKeyProvider::generate("test-ephemeral", &mut OsRandom).unwrap()
    }

    fn note(title: &str, body: &str) -> Item {
        Item::new(
            title,
            ItemData::SecureNote(SecureNote {
                body: SecretString::new(body),
            }),
            &mut OsRandom,
        )
        .unwrap()
    }

    fn sample(p: &EphemeralKeyProvider) -> (Vault, Vec<u8>) {
        let mut v = Vault::create(p, &mut OsRandom).unwrap();
        v.insert(note("Synthetic title A", "SYNTHETIC-BODY-A"))
            .unwrap();
        v.insert(note("Synthetic title B", "SYNTHETIC-BODY-B"))
            .unwrap();
        let bytes = v.encrypt(p, &mut OsRandom).unwrap();
        (v, bytes)
    }

    #[test]
    fn round_trip_and_no_plaintext_in_file() {
        let p = provider();
        let (_v, bytes) = sample(&p);
        let s = String::from_utf8(bytes.clone()).unwrap();
        for needle in ["SYNTHETIC-BODY", "Synthetic title", "secure_note"] {
            assert!(!s.contains(needle), "{needle} leaked");
        }
        let back = Vault::decrypt(&bytes, &p).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.revision(), 1);
    }

    #[test]
    fn wrong_key_fails_closed() {
        let p = provider();
        let (_v, bytes) = sample(&p);
        let other = provider();
        assert!(matches!(
            Vault::decrypt(&bytes, &other),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn corrupted_truncated_and_unknown_formats_fail() {
        let p = provider();
        let (_v, bytes) = sample(&p);
        assert!(Vault::decrypt(&bytes[..bytes.len() / 2], &p).is_err());
        assert!(Vault::decrypt(b"", &p).is_err());
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        j["version"] = 2.into();
        assert!(matches!(
            Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p),
            Err(Error::Format(_))
        ));
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        j["format"] = "other".into();
        assert!(matches!(
            Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p),
            Err(Error::Format(_))
        ));
        // Flip a ciphertext character in the first item.
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ct = j["items"][0]["sealed"]["ct"].as_str().unwrap().to_owned();
        let flipped = if ct.starts_with('A') { "B" } else { "A" };
        j["items"][0]["sealed"]["ct"] = format!("{flipped}{}", &ct[1..]).into();
        assert!(Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p).is_err());
        // Tamper with public revision: manifest AAD no longer matches.
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        j["revision"] = 99.into();
        assert!(matches!(
            Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn dropped_or_reordered_items_detected() {
        let p = provider();
        let (_v, bytes) = sample(&p);
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        j["items"].as_array_mut().unwrap().pop();
        assert!(matches!(
            Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p),
            Err(Error::Integrity(_))
        ));
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        j["items"].as_array_mut().unwrap().swap(0, 1);
        assert!(Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p).is_err());
        // Swap ciphertexts between records (AAD binds id+rev).
        let mut j: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let a = j["items"][0]["sealed"].clone();
        j["items"][0]["sealed"] = j["items"][1]["sealed"].clone();
        j["items"][1]["sealed"] = a;
        assert!(Vault::decrypt(&serde_json::to_vec(&j).unwrap(), &p).is_err());
    }

    #[test]
    fn edit_increments_revisions_and_persists() {
        let p = provider();
        let (mut v, _) = sample(&p);
        let id = v.items().next().unwrap().id.clone();
        v.update(&id, |i| i.title = "Edited synthetic".into())
            .unwrap();
        assert!(v.update(&id, |i| i.title = String::new()).is_err());
        let bytes = v.encrypt(&p, &mut OsRandom).unwrap();
        let back = Vault::decrypt(&bytes, &p).unwrap();
        assert_eq!(back.revision(), 2);
        let it = back.get(&id).unwrap();
        assert_eq!(it.title, "Edited synthetic");
        assert_eq!(it.rev, 2);
    }

    #[test]
    fn data_key_rotation_round_trips() {
        let p = provider();
        let (mut v, before) = sample(&p);
        v.rotate_data_key(&mut OsRandom).unwrap();
        let after = v.encrypt(&p, &mut OsRandom).unwrap();
        assert_ne!(before, after);
        assert_eq!(Vault::decrypt(&after, &p).unwrap().len(), 2);
    }

    #[test]
    fn login_totp_reference_integrity() {
        let p = provider();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        let totp = Item::new(
            "otp",
            ItemData::Totp(TotpRecord {
                config: TotpConfig::with_defaults(SecretBytes::new(vec![9; 20])).unwrap(),
                issuer: None,
                account_name: None,
            }),
            &mut OsRandom,
        )
        .unwrap();
        let note_id = v.insert(note("n", "b")).unwrap();
        let totp_id = v.insert(totp).unwrap();
        let mk = |r: ItemId| {
            Item::new(
                "login",
                ItemData::Login(Login {
                    username: None,
                    password: None,
                    urls: vec![],
                    totp_item: Some(r),
                    recovery_codes: vec![],
                }),
                &mut OsRandom,
            )
            .unwrap()
        };
        assert!(v.insert(mk(note_id)).is_err());
        v.insert(mk(totp_id.clone())).unwrap();
        assert!(v.remove(&totp_id).is_err());
        let bytes = v.encrypt(&p, &mut OsRandom).unwrap();
        assert_eq!(Vault::decrypt(&bytes, &p).unwrap().len(), 3);
    }

    #[test]
    fn key_id_mismatch_rejected() {
        let p = provider();
        let (mut v, bytes) = sample(&p);
        let other = EphemeralKeyProvider::generate("other-id", &mut OsRandom).unwrap();
        assert!(Vault::decrypt(&bytes, &other).is_err());
        assert!(v.encrypt(&other, &mut OsRandom).is_err());
    }

    // --- v2: password + recovery key slots ---------------------------------

    use crate::keyslot::{Authority, PasswordSetup};
    use crate::recovery::RecoveryCode;
    use std::sync::OnceLock;

    const PW: &str = "synthetic river lamp ferry";

    /// One real-strength Argon2id run shared by the tests (same setup is
    /// reused, so the derived key is too).
    fn shared() -> &'static (ProtectedSetup, Zeroizing<[u8; 32]>) {
        static S: OnceLock<(ProtectedSetup, Zeroizing<[u8; 32]>)> = OnceLock::new();
        S.get_or_init(|| {
            let setup = ProtectedSetup::generate(&mut OsRandom).unwrap();
            let key = setup.password.derive(PW).unwrap();
            (setup, key)
        })
    }

    fn protected() -> (Vault, RecoveryCode, Vec<u8>) {
        let (setup, key) = shared();
        let (mut v, code) = Vault::create_protected(setup, key, &mut OsRandom).unwrap();
        v.confirm_recovery(&code).unwrap();
        v.insert(note("Synthetic title A", "SYNTHETIC-BODY-A"))
            .unwrap();
        let (bytes, rev) = v.seal_next_protected(&mut OsRandom).unwrap();
        v.mark_written(rev, &bytes).unwrap();
        (v, code, bytes)
    }

    fn json(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).unwrap()
    }

    fn bytes_of(j: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(j).unwrap()
    }

    #[test]
    fn v2_new_vault_needs_recovery_confirmation_before_sealing() {
        let (setup, key) = shared();
        let (mut v, code) = Vault::create_protected(setup, key, &mut OsRandom).unwrap();
        assert!(v.is_protected());
        assert!(!v.recovery_confirmed());
        assert!(v.seal_next_protected(&mut OsRandom).is_err());
        let other = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert!(v.confirm_recovery(&other).is_err());
        assert!(v.seal_next_protected(&mut OsRandom).is_err());
        v.confirm_recovery(&code).unwrap();
        assert!(v.seal_next_protected(&mut OsRandom).is_ok());
    }

    #[test]
    fn v2_opens_with_password_or_recovery_and_hides_secrets() {
        let (v, code, bytes) = protected();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for needle in [
            "SYNTHETIC-BODY",
            "Synthetic title",
            PW,
            code.to_text().as_str(),
        ] {
            assert!(!text.contains(needle), "leaked");
        }
        let code_raw = code.to_text().replace('-', "");
        assert!(!text.to_uppercase().contains(&code_raw[..20]));
        let a = Vault::open_with_password(&bytes, PW).unwrap();
        let b = Vault::open_with_recovery(&bytes, &code).unwrap();
        for o in [&a, &b] {
            assert_eq!(o.len(), 1);
            assert_eq!(o.vault_id(), v.vault_id());
            assert_eq!(o.revision(), 1);
            assert!(o.recovery_confirmed());
        }
        let h = read_header(&bytes).unwrap();
        assert_eq!((h.version, h.kek_id, h.revision), (2, None, 1));
    }

    #[test]
    fn v2_wrong_credentials_fail_closed() {
        let (_v, _code, bytes) = protected();
        assert!(matches!(
            Vault::open_with_password(&bytes, "synthetic wrong password"),
            Err(Error::Decrypt)
        ));
        let other = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert!(matches!(
            Vault::open_with_recovery(&bytes, &other),
            Err(Error::Decrypt)
        ));
        // Formats never cross: v2 needs slots, v1 needs a provider.
        assert!(matches!(
            Vault::decrypt(&bytes, &provider()),
            Err(Error::Format(_))
        ));
        let (_v1, v1_bytes) = sample(&provider());
        assert!(matches!(
            Vault::open_with_password(&v1_bytes, PW),
            Err(Error::Format(_))
        ));
        assert!(password_request(&v1_bytes).is_err());
    }

    #[test]
    fn v2_hostile_kdf_parameters_are_rejected_before_derivation() {
        let (_v, _code, bytes) = protected();
        for (field, value) in [
            ("m_kib", serde_json::json!(4_294_967_295u64)),
            ("m_kib", serde_json::json!(1024 * 1024)),
            ("t", serde_json::json!(1_000_000)),
            ("t", serde_json::json!(1)),
            ("p", serde_json::json!(64)),
            ("m_kib", serde_json::json!(-1)),
            ("v", serde_json::json!(16)),
            ("salt", serde_json::json!("AAAA")),
        ] {
            let mut j = json(&bytes);
            j["slots"][0]["kdf"][field] = value;
            let t = std::time::Instant::now();
            let r = Vault::open_with_password(&bytes_of(&j), PW);
            assert!(matches!(r, Err(Error::Format(_))), "{field}");
            assert!(password_request(&bytes_of(&j)).is_err());
            assert!(
                t.elapsed() < std::time::Duration::from_millis(200),
                "no KDF ran"
            );
        }
    }

    #[test]
    fn v2_tampered_slots_fail() {
        let (_v, code, bytes) = protected();
        // KDF parameter changed within bounds: the slot AAD no longer matches.
        let mut j = json(&bytes);
        j["slots"][0]["kdf"]["t"] = 4.into();
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Decrypt)
        ));
        // Recovery slot altered: opening with the PASSWORD still fails,
        // because the manifest binds every slot's bytes.
        let mut j = json(&bytes);
        let ct = j["slots"][1]["wrapped"]["ct"].as_str().unwrap().to_owned();
        let flipped = if ct.starts_with('A') { "B" } else { "A" };
        j["slots"][1]["wrapped"]["ct"] = format!("{flipped}{}", &ct[1..]).into();
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Decrypt)
        ));
        // Recovery slot salt changed.
        let mut j = json(&bytes);
        j["slots"][1]["kdf"]["salt"] = "AAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(Vault::open_with_recovery(&bytes_of(&j), &code).is_err());
        assert!(Vault::open_with_password(&bytes_of(&j), PW).is_err());
        // Slot ids swapped / changed.
        let mut j = json(&bytes);
        j["slots"][0]["id"] = "0123456789abcdef".into();
        assert!(Vault::open_with_password(&bytes_of(&j), PW).is_err());
        // Slot order swapped: digest differs.
        let mut j = json(&bytes);
        j["slots"].as_array_mut().unwrap().swap(0, 1);
        assert!(Vault::open_with_password(&bytes_of(&j), PW).is_err());
        // Header fields bound by the manifest AAD.
        let mut j = json(&bytes);
        j["revision"] = 7.into();
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Decrypt)
        ));
        let mut j = json(&bytes);
        j["vault_id"] = "00000000000000000000000000000000".into();
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn v2_malformed_duplicate_removed_and_unknown_slots_are_refused() {
        let (_v, _code, bytes) = protected();
        type Edit = Box<dyn Fn(&mut serde_json::Value)>;
        let edits: Vec<(&str, Edit)> = vec![
            (
                "removed",
                Box::new(|j| {
                    j["slots"].as_array_mut().unwrap().pop();
                }),
            ),
            ("none", Box::new(|j| j["slots"] = serde_json::json!([]))),
            (
                "duplicate",
                Box::new(|j| {
                    let a = j["slots"][0].clone();
                    j["slots"].as_array_mut().unwrap().push(a);
                }),
            ),
            (
                "second password slot",
                Box::new(|j| {
                    let mut a = j["slots"][0].clone();
                    a["id"] = "fedcba9876543210".into();
                    j["slots"].as_array_mut().unwrap().push(a);
                }),
            ),
            (
                "too many",
                Box::new(|j| {
                    let a = j["slots"][0].clone();
                    for _ in 0..10 {
                        j["slots"].as_array_mut().unwrap().push(a.clone());
                    }
                }),
            ),
            (
                "unknown kind",
                Box::new(|j| j["slots"][1]["kind"] = "passkey".into()),
            ),
            (
                "wrong alg for kind",
                Box::new(|j| j["slots"][0]["kind"] = "recovery".into()),
            ),
            (
                "unknown alg",
                Box::new(|j| j["slots"][0]["kdf"]["alg"] = "scrypt".into()),
            ),
            (
                "extra field",
                Box::new(|j| j["slots"][0]["note"] = "x".into()),
            ),
            ("bad id", Box::new(|j| j["slots"][0]["id"] = "../x".into())),
            (
                "short ct",
                Box::new(|j| j["slots"][0]["wrapped"]["ct"] = "AAAA".into()),
            ),
            (
                "short nonce",
                Box::new(|j| j["slots"][0]["wrapped"]["nonce"] = "AAAA".into()),
            ),
            ("bad vault id", Box::new(|j| j["vault_id"] = "x".into())),
            ("aead", Box::new(|j| j["aead"] = "aes-gcm".into())),
            ("future version", Box::new(|j| j["version"] = 3.into())),
            ("relabelled v1", Box::new(|j| j["version"] = 1.into())),
            (
                "extra top-level",
                Box::new(|j| j["kek_id"] = "synthetic-fixture-v1".into()),
            ),
        ];
        for (name, edit) in edits {
            let mut j = json(&bytes);
            edit(&mut j);
            let r = Vault::open_with_password(&bytes_of(&j), PW);
            assert!(matches!(r, Err(Error::Format(_))), "{name}: {r:?}");
        }
        assert!(Vault::open_with_password(&bytes[..bytes.len() / 2], PW).is_err());
        assert!(Vault::open_with_password(b"", PW).is_err());
    }

    #[test]
    fn v2_slot_from_another_vault_does_not_open() {
        let (a, _ca, bytes_a) = protected();
        // Same password slot id, salt and derived key; only the vault id differs.
        let (setup, key) = shared();
        let other = ProtectedSetup {
            vault_id: data_encoding::HEXLOWER.encode(&[0x11; 16]),
            password: setup.password.clone(),
        };
        assert_ne!(other.vault_id, a.vault_id());
        let (mut b, cb) = Vault::create_protected(&other, key, &mut OsRandom).unwrap();
        b.confirm_recovery(&cb).unwrap();
        let (bytes_b, _) = b.seal_next_protected(&mut OsRandom).unwrap();
        assert!(Vault::open_with_password(&bytes_b, PW).is_ok());
        let mut j = json(&bytes_a);
        j["slots"][0] = json(&bytes_b)["slots"][0].clone();
        assert_eq!(j["slots"][0]["id"], json(&bytes_a)["slots"][0]["id"]);
        // HKDF info and slot AAD bind the vault id: B's wrapper is useless in A.
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn v2_password_change_requires_authority_and_is_a_rewrap() {
        let (mut v, code, old_bytes) = protected();
        let new_pw = "synthetic second passphrase";
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let new_key = setup.derive(new_pw).unwrap();
        // Wrong authority: refused, vault unchanged.
        let wrong = [0u8; 32];
        assert!(v
            .change_password(
                Authority::PasswordKey(&wrong),
                &setup,
                &new_key,
                &mut OsRandom
            )
            .is_err());
        let other = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert!(v
            .change_password(Authority::Recovery(&other), &setup, &new_key, &mut OsRandom)
            .is_err());
        // Reusing the current slot's salt is refused.
        let mut reuse = setup.clone();
        reuse.salt = v.password_setup().unwrap().salt;
        assert!(v
            .change_password(Authority::Recovery(&code), &reuse, &new_key, &mut OsRandom)
            .is_err());
        v.change_password(Authority::Recovery(&code), &setup, &new_key, &mut OsRandom)
            .unwrap();
        let (bytes, rev) = v.seal_next_protected(&mut OsRandom).unwrap();
        v.mark_written(rev, &bytes).unwrap();
        assert!(Vault::open_with_password(&bytes, new_pw).is_ok());
        assert!(matches!(
            Vault::open_with_password(&bytes, PW),
            Err(Error::Decrypt)
        ));
        assert!(Vault::open_with_recovery(&bytes, &code).is_ok());
        // Rewrap, not rotation: the OLD file still opens with the old password.
        assert!(Vault::open_with_password(&old_bytes, PW).is_ok());
        assert!(v.rotate_data_key(&mut OsRandom).is_err());
        assert!(v.seal_next(&provider(), &mut OsRandom).is_err());
        // Current-password authority works with the derived key.
        let cur = v.password_setup().unwrap();
        let cur_key = cur.derive(new_pw).unwrap();
        let setup3 = PasswordSetup::generate(&mut OsRandom).unwrap();
        let k3 = setup3.derive(PW).unwrap();
        v.change_password(
            Authority::PasswordKey(&cur_key),
            &setup3,
            &k3,
            &mut OsRandom,
        )
        .unwrap();
    }

    /// A rotated vault's plaintext, item by item (JSON of each item).
    fn plaintext(v: &Vault) -> Vec<String> {
        v.items()
            .map(|i| serde_json::to_string(i).unwrap())
            .collect()
    }

    fn rotate(v: &Vault, code: &RecoveryCode, new_pw: &str) -> (Vault, RecoveryCode) {
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let key = setup.derive(new_pw).unwrap();
        let p = v
            .begin_rotation(Authority::Recovery(code), &setup, &key, &mut OsRandom)
            .unwrap();
        let new_code = RecoveryCode::parse(&p.code().to_text()).unwrap();
        let r = v.finish_rotation(&p, &new_code).unwrap();
        (r, new_code)
    }

    #[test]
    fn v2_rotation_replaces_the_data_key_and_every_slot() {
        let (mut v, code, old_bytes) = protected();
        for d in crate::model::tests::every_kind_data() {
            v.insert(Item::new("Synthetic every kind", d, &mut OsRandom).unwrap())
                .unwrap();
        }
        let (b1, r1) = v.seal_next_protected(&mut OsRandom).unwrap();
        v.mark_written(r1, &b1).unwrap();
        let before = plaintext(&v);
        let new_pw = "synthetic rotated passphrase";
        let (mut rv, new_code) = rotate(&v, &code, new_pw);
        // Same identity and CAS snapshot; different data key.
        assert_eq!(rv.vault_id(), v.vault_id());
        assert_eq!(rv.revision(), v.revision());
        assert_eq!(rv.snapshot_digest(), v.snapshot_digest());
        assert!(!bool::from(rv.dek.as_bytes().ct_eq(v.dek.as_bytes())));
        let (b2, r2) = rv.seal_next_protected(&mut OsRandom).unwrap();
        rv.mark_written(r2, &b2).unwrap();
        assert_eq!(r2, r1 + 1);

        // New file: new credentials only.
        let w = Vault::open_with_password(&b2, new_pw).unwrap();
        assert_eq!(plaintext(&w), before);
        assert_eq!(
            plaintext(&Vault::open_with_recovery(&b2, &new_code).unwrap()),
            before
        );
        assert!(matches!(
            Vault::open_with_password(&b2, PW),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            Vault::open_with_recovery(&b2, &code),
            Err(Error::Decrypt)
        ));
        // Old files: old credentials only (a retained backup is not revoked).
        for old in [&old_bytes, &b1] {
            assert!(Vault::open_with_password(old, PW).is_ok());
            assert!(Vault::open_with_recovery(old, &code).is_ok());
            assert!(Vault::open_with_password(old, new_pw).is_err());
            assert!(Vault::open_with_recovery(old, &new_code).is_err());
        }
        // Every slot, item ciphertext and the manifest changed; ids and revs did not.
        let (j1, j2) = (json(&b1), json(&b2));
        for k in 0..2 {
            assert_ne!(j1["slots"][k]["id"], j2["slots"][k]["id"]);
            assert_ne!(j1["slots"][k]["wrapped"], j2["slots"][k]["wrapped"]);
        }
        assert_ne!(j1["manifest"], j2["manifest"]);
        let (i1, i2) = (
            j1["items"].as_array().unwrap(),
            j2["items"].as_array().unwrap(),
        );
        assert_eq!(i1.len(), 8);
        for (a, b) in i1.iter().zip(i2) {
            assert_eq!((&a["id"], &a["rev"]), (&b["id"], &b["rev"]));
            assert_ne!(a["sealed"], b["sealed"]);
        }
        // Splicing an old slot (old data key) into the new file fails to open.
        let mut spliced = j2.clone();
        spliced["slots"][0] = j1["slots"][0].clone();
        assert!(Vault::open_with_password(&bytes_of(&spliced), PW).is_err());
        assert!(Vault::open_with_password(&bytes_of(&spliced), new_pw).is_err());
    }

    #[test]
    fn v2_rotation_needs_authority_a_fresh_setup_and_the_new_code() {
        let (v, code, _) = protected();
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let key = setup.derive("synthetic rotated passphrase").unwrap();
        let other = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert!(v
            .begin_rotation(Authority::Recovery(&other), &setup, &key, &mut OsRandom)
            .is_err());
        assert!(v
            .begin_rotation(
                Authority::PasswordKey(&[0u8; 32]),
                &setup,
                &key,
                &mut OsRandom
            )
            .is_err());
        let mut reuse = setup.clone();
        reuse.salt = v.password_setup().unwrap().salt;
        assert!(v
            .begin_rotation(Authority::Recovery(&code), &reuse, &key, &mut OsRandom)
            .is_err());
        // Current-password authority (the shared derived key).
        let (_, cur_key) = shared();
        let p = v
            .begin_rotation(Authority::PasswordKey(cur_key), &setup, &key, &mut OsRandom)
            .unwrap();
        let shown = RecoveryCode::parse(&p.code().to_text()).unwrap();
        // A mistyped (or the old) code keeps the rotation pending.
        let e = v.finish_rotation(&p, &code).err().unwrap();
        assert!(matches!(e, Error::Validation(_)));
        assert!(v.finish_rotation(&p, &other).is_err());
        // A rotation started for another vault, or for the same vault in
        // another credential state, is refused.
        let other_setup = ProtectedSetup::generate(&mut OsRandom).unwrap();
        let (w, _) = Vault::create_protected(&other_setup, &[9u8; 32], &mut OsRandom).unwrap();
        assert!(w.finish_rotation(&p, &shown).is_err());
        let mut changed = v.clone();
        let s2 = PasswordSetup::generate(&mut OsRandom).unwrap();
        changed
            .change_password(Authority::Recovery(&code), &s2, &[8u8; 32], &mut OsRandom)
            .unwrap();
        assert!(changed.finish_rotation(&p, &shown).is_err());
        // Same vault id, independently keyed (another DEK and slots): refused,
        // and its replacement wrappers never land in the other vault.
        let (twin, _, _) = protected();
        assert_eq!(twin.vault_id(), v.vault_id());
        assert!(twin.finish_rotation(&p, &shown).is_err());
        // Same id AND same slot records but another data key in memory: the
        // DEK binding alone refuses it.
        let mut other_key = v.clone();
        other_key.dek = Key256::generate(&mut OsRandom).unwrap();
        assert!(other_key.finish_rotation(&p, &shown).is_err());
        let rv = v.finish_rotation(&p, &shown).unwrap();
        // Made stale by a completed rotation: the rotated vault refuses it.
        assert!(rv.finish_rotation(&p, &shown).is_err());
        assert!(rv.recovery_confirmed());
        // The vault it came from is untouched: still the old credentials.
        let (b, _) = v.seal_next_protected(&mut OsRandom).unwrap();
        assert!(Vault::open_with_recovery(&b, &code).is_ok());
        assert!(Vault::open_with_recovery(&b, &shown).is_err());
    }

    #[test]
    fn v2_rotation_invalidates_an_older_pending_recovery_code() {
        let (v, code, _) = protected();
        let pending = v
            .begin_recovery_change(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        let pending_code = RecoveryCode::parse(&pending.code().to_text()).unwrap();
        let (mut rv, _) = rotate(&v, &code, "synthetic rotated passphrase");
        let r = rv.finish_recovery_change(pending, &pending_code);
        assert!(
            r.is_err(),
            "a code wrapped for the old data key must be refused"
        );
    }

    // --- webauthn-prf quick unlock (M5 C1) ---------------------------------

    const RP: &str = "keymesh.cloud";

    fn auth_data(rp: &str, flags: u8) -> Vec<u8> {
        let mut d: Vec<u8> = Sha256::digest(rp.as_bytes()).to_vec();
        d.push(flags);
        d.extend_from_slice(&[0, 0, 0, 7]);
        d
    }

    fn enrol(v: &mut Vault, code: &RecoveryCode, cred: &[u8], prf: &[u8; 32]) -> String {
        let setup = v
            .begin_prf(Authority::Recovery(code), &mut OsRandom)
            .unwrap();
        v.add_prf_slot(
            Authority::Recovery(code),
            &setup,
            cred,
            RP,
            false,
            "Synthetic key",
            prf,
            &mut OsRandom,
        )
        .unwrap();
        setup.setup().slot_id.clone()
    }

    fn sealed(v: &mut Vault) -> Vec<u8> {
        let (b, r) = v.seal_next_protected(&mut OsRandom).unwrap();
        v.mark_written(r, &b).unwrap();
        b
    }

    #[test]
    fn prf_slot_unlocks_only_with_the_right_assertion() {
        let (mut v, code, _) = protected();
        let cred = [0x11u8; 32];
        let prf = [0x5au8; 32];
        enrol(&mut v, &code, &cred, &prf);
        let b = sealed(&mut v);
        let ok = Vault::open_with_prf(&b, &cred, &auth_data(RP, 0x05), &prf, RP).unwrap();
        assert_eq!(ok.len(), v.len());
        // Password and recovery still open it.
        assert!(Vault::open_with_password(&b, PW).is_ok());
        assert!(Vault::open_with_recovery(&b, &code).is_ok());
        let fails = |cred: &[u8], ad: &[u8], prf: &[u8; 32], rp: &str| {
            matches!(
                Vault::open_with_prf(&b, cred, ad, prf, rp),
                Err(Error::Decrypt)
            )
        };
        assert!(
            fails(&cred, &auth_data(RP, 0x05), &[0x5b; 32], RP),
            "wrong PRF output"
        );
        assert!(fails(&cred, &auth_data(RP, 0x01), &prf, RP), "UV missing");
        assert!(fails(&cred, &auth_data(RP, 0x04), &prf, RP), "UP missing");
        assert!(
            fails(&cred, &auth_data("evil.example", 0x05), &prf, RP),
            "rpIdHash of another site"
        );
        assert!(
            fails(
                &cred,
                &auth_data("evil.example", 0x05),
                &prf,
                "evil.example"
            ),
            "slot is for another rp id"
        );
        assert!(
            fails(&[0x12; 32], &auth_data(RP, 0x05), &prf, RP),
            "unknown credential"
        );
        assert!(
            fails(&cred, &auth_data(RP, 0x05)[..36], &prf, RP),
            "short authenticator data"
        );
        // Public request data lists the slot.
        let req = prf_request(&b).unwrap();
        assert_eq!(req.len(), 1);
        assert_eq!(
            (
                req[0].credential_id.as_slice(),
                req[0].rp_id.as_str(),
                req[0].salt.len()
            ),
            (&cred[..], RP, 32)
        );
    }

    #[test]
    fn prf_slot_fields_are_authenticated() {
        let (mut v, code, _) = protected();
        let cred = [0x21u8; 20];
        let prf = [0x33u8; 32];
        enrol(&mut v, &code, &cred, &prf);
        let b = sealed(&mut v);
        let ad = auth_data(RP, 0x05);
        let i = json(&b)["slots"]
            .as_array()
            .unwrap()
            .iter()
            .position(|s| s["kind"] == "webauthn-prf")
            .unwrap();
        for (field, val) in [
            ("label", serde_json::json!("Renamed")),
            ("be", serde_json::json!(true)),
            (
                "salt",
                serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[9u8; 32])),
            ),
        ] {
            let mut j = json(&b);
            j["slots"][i]["kdf"][field] = val;
            let t = bytes_of(&j);
            assert!(
                Vault::open_with_prf(&t, &cred, &ad, &prf, RP).is_err(),
                "{field} via PRF"
            );
            assert!(
                Vault::open_with_password(&t, PW).is_err(),
                "{field} via password (manifest)"
            );
        }
        // Bounds and unknown fields are refused before any derivation.
        for (field, val) in [
            (
                "credential_id",
                serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[1u8; 8])),
            ),
            ("rp_id", serde_json::json!("KEYMESH.cloud")),
            ("rp_id", serde_json::json!("")),
            ("label", serde_json::json!("x".repeat(65))),
            ("label", serde_json::json!("bad\nlabel")),
            ("extra", serde_json::json!(1)),
        ] {
            let mut j = json(&b);
            j["slots"][i]["kdf"][field] = val;
            assert!(
                matches!(
                    Vault::open_with_password(&bytes_of(&j), PW),
                    Err(Error::Format(_))
                ),
                "{field}"
            );
        }
        let mut j = json(&b);
        j["slots"][i]["kdf"]["alg"] = serde_json::json!("hkdf-sha256");
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Format(_))
        ));
        let mut j = json(&b);
        j["slots"][i]["kind"] = serde_json::json!("webauthn-prf-v2");
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn prf_enrolment_needs_authority_and_bounds_and_removal_works() {
        let (mut v, code, _) = protected();
        let other = RecoveryCode::generate(&mut OsRandom).unwrap();
        // Wrong authority: refused before any parameters (no ceremony).
        assert!(v
            .begin_prf(Authority::Recovery(&other), &mut OsRandom)
            .is_err());
        let setup = v
            .begin_prf(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        assert!(v
            .add_prf_slot(
                Authority::Recovery(&other),
                &setup,
                &[1; 16],
                RP,
                false,
                "",
                &[1; 32],
                &mut OsRandom
            )
            .is_err());
        for (cred, rp, label) in [
            (&[1u8; 15][..], RP, ""),
            (&[1u8; 16][..], "Bad.Host", ""),
            (&[1u8; 16][..], RP, "a\u{7}b"),
        ] {
            assert!(v
                .add_prf_slot(
                    Authority::Recovery(&code),
                    &setup,
                    cred,
                    rp,
                    false,
                    label,
                    &[1; 32],
                    &mut OsRandom
                )
                .is_err());
        }
        let ids: Vec<String> = (0..4u8)
            .map(|k| enrol(&mut v, &code, &[k + 1; 16], &[k; 32]))
            .collect();
        // Duplicate credential and a fifth slot are refused.
        let s5 = v
            .begin_prf(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        assert!(v
            .add_prf_slot(
                Authority::Recovery(&code),
                &s5,
                &[1; 16],
                RP,
                false,
                "",
                &[9; 32],
                &mut OsRandom
            )
            .is_err());
        assert!(v
            .add_prf_slot(
                Authority::Recovery(&code),
                &s5,
                &[9; 16],
                RP,
                false,
                "",
                &[9; 32],
                &mut OsRandom
            )
            .is_err());
        assert_eq!(v.prf_slots().unwrap().len(), 4);
        // Removal needs authority; password/recovery slots can't be removed.
        assert!(v
            .remove_prf_slot(Authority::Recovery(&other), &ids[0])
            .is_err());
        let pw_id = v.password_setup().unwrap().slot_id;
        assert!(v
            .remove_prf_slot(Authority::Recovery(&code), &pw_id)
            .is_err());
        v.remove_prf_slot(Authority::Recovery(&code), &ids[0])
            .unwrap();
        let b = sealed(&mut v);
        assert!(Vault::open_with_prf(&b, &[1; 16], &auth_data(RP, 0x05), &[0; 32], RP).is_err());
        assert!(Vault::open_with_prf(&b, &[2; 16], &auth_data(RP, 0x05), &[1; 32], RP).is_ok());
    }

    #[test]
    fn prf_enrolment_is_bound_to_its_vault_and_credential_state() {
        let (mut v, code, _) = protected();
        let p = v
            .begin_prf(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        // Same vault id, independently keyed (the shared test setup): refused.
        let (mut twin, twin_code, _) = protected();
        assert_eq!(twin.vault_id(), v.vault_id());
        let add = |w: &mut Vault, c: &RecoveryCode, p: &PendingPrf| {
            w.add_prf_slot(
                Authority::Recovery(c),
                p,
                &[5; 16],
                RP,
                false,
                "x",
                &[5; 32],
                &mut OsRandom,
            )
        };
        assert!(add(&mut twin, &twin_code, &p).is_err());
        assert_eq!(
            twin.prf_slots().unwrap().len(),
            0,
            "no wrapper copied into another vault"
        );
        // Same vault, made stale by a password change after begin: refused.
        let mut changed = v.clone();
        let s2 = PasswordSetup::generate(&mut OsRandom).unwrap();
        changed
            .change_password(Authority::Recovery(&code), &s2, &[8; 32], &mut OsRandom)
            .unwrap();
        assert!(add(&mut changed, &code, &p).is_err());
        // Same slots, another DEK in memory: refused by the DEK binding alone.
        let mut other_key = v.clone();
        other_key.dek = Key256::generate(&mut OsRandom).unwrap();
        assert!(add(&mut other_key, &code, &p).is_err());
        // After a rotation: refused.
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let key = setup.derive("synthetic rotated passphrase").unwrap();
        let pr = v
            .begin_rotation(Authority::Recovery(&code), &setup, &key, &mut OsRandom)
            .unwrap();
        let nc = RecoveryCode::parse(&pr.code().to_text()).unwrap();
        let mut rotated = v.finish_rotation(&pr, &nc).unwrap();
        assert!(add(&mut rotated, &nc, &p).is_err());
        // The original state accepts it.
        add(&mut v, &code, &p).unwrap();
    }

    /// Review fix C-CORE-1: every credential id the writer accepts
    /// (16..=1023 bytes) must read back; 1024 is refused on write AND read.
    #[test]
    fn prf_credential_ids_of_every_accepted_length_round_trip() {
        for n in [16usize, 48, 49, 64, 255, 1023] {
            let (mut v, code, _) = protected();
            let cred: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let prf = [n as u8; 32];
            enrol(&mut v, &code, &cred, &prf);
            let b = sealed(&mut v);
            assert!(Vault::open_with_password(&b, PW).is_ok(), "{n}: password");
            assert!(
                Vault::open_with_recovery(&b, &code).is_ok(),
                "{n}: recovery"
            );
            let r = Vault::open_with_prf(&b, &cred, &auth_data(RP, 0x05), &prf, RP).unwrap();
            assert_eq!(r.prf_slots().unwrap()[0].credential_id, cred, "{n}: prf");
            assert_eq!(prf_request(&b).unwrap()[0].credential_id, cred);
        }
        // 1024 bytes: refused when enrolling...
        let (mut v, code, _) = protected();
        let p = v
            .begin_prf(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        assert!(v
            .add_prf_slot(
                Authority::Recovery(&code),
                &p,
                &[7; 1024],
                RP,
                false,
                "",
                &[1; 32],
                &mut OsRandom
            )
            .is_err());
        // ...and when a file carries one (strict, before any derivation).
        let (mut w, wc, _) = protected();
        enrol(&mut w, &wc, &[3; 16], &[3; 32]);
        let b = sealed(&mut w);
        let mut j = json(&b);
        let i = j["slots"]
            .as_array()
            .unwrap()
            .iter()
            .position(|s| s["kind"] == "webauthn-prf")
            .unwrap();
        j["slots"][i]["kdf"]["credential_id"] =
            serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[3u8; 1024]));
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Format(_))
        ));
        // Non-canonical base64url (padding, wrong alphabet, stray trailing bits) is refused.
        for bad in [
            "AwMDAwMDAwMDAwMDAwMDAw==",
            "AwMDAwMDAwMDAwMDAwMDAw+/",
            "AwMDAwMDAwMDAwMDAwMDAx",
        ] {
            j["slots"][i]["kdf"]["credential_id"] = serde_json::json!(bad);
            assert!(
                Vault::open_with_password(&bytes_of(&j), PW).is_err(),
                "{bad}"
            );
        }
        // Salt bounds are unchanged (still ≤ 64 encoded characters).
        j["slots"][i]["kdf"]["credential_id"] =
            serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[3u8; 16]));
        j["slots"][i]["kdf"]["salt"] = serde_json::json!("A".repeat(65));
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn rotation_never_silently_keeps_prf_slots() {
        let (mut v, code, _) = protected();
        let cred = [0x44u8; 16];
        let prf = [0x77u8; 32];
        enrol(&mut v, &code, &cred, &prf);
        let before = sealed(&mut v);
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let key = setup.derive("synthetic rotated passphrase").unwrap();
        // Without confirmation: refused.
        assert!(v
            .begin_rotation(Authority::Recovery(&code), &setup, &key, &mut OsRandom)
            .is_err());
        let p = v
            .begin_rotation_revoking_quick_unlock(
                Authority::Recovery(&code),
                &setup,
                &key,
                &mut OsRandom,
            )
            .unwrap();
        let new_code = RecoveryCode::parse(&p.code().to_text()).unwrap();
        let mut r = v.finish_rotation(&p, &new_code).unwrap();
        assert_eq!(r.prf_slots().unwrap().len(), 0);
        let after = sealed(&mut r);
        assert!(prf_request(&after).unwrap().is_empty());
        assert!(Vault::open_with_prf(&after, &cred, &auth_data(RP, 0x05), &prf, RP).is_err());
        // The old copy still has (and opens with) the slot: not revocable.
        assert!(Vault::open_with_prf(&before, &cred, &auth_data(RP, 0x05), &prf, RP).is_ok());
    }

    #[test]
    fn rotation_never_applies_to_demo_vaults() {
        let p = provider();
        let (v, _) = sample(&p);
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let code = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert!(v
            .begin_rotation(
                Authority::Recovery(&code),
                &setup,
                &[1u8; 32],
                &mut OsRandom
            )
            .is_err());
    }

    #[test]
    fn v2_recovery_change_needs_authority_and_confirmation() {
        let (mut v, code, old_bytes) = protected();
        let other = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert!(v
            .begin_recovery_change(Authority::Recovery(&other), &mut OsRandom)
            .is_err());
        let pending = v
            .begin_recovery_change(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        let new_code = RecoveryCode::parse(&pending.code().to_text()).unwrap();
        // Wrong confirmation: refused, old code stays in force.
        let pending2 = v
            .begin_recovery_change(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        assert!(v.finish_recovery_change(pending2, &other).is_err());
        v.finish_recovery_change(pending, &new_code).unwrap();
        let (bytes, rev) = v.seal_next_protected(&mut OsRandom).unwrap();
        v.mark_written(rev, &bytes).unwrap();
        assert!(Vault::open_with_recovery(&bytes, &new_code).is_ok());
        assert!(matches!(
            Vault::open_with_recovery(&bytes, &code),
            Err(Error::Decrypt)
        ));
        assert!(Vault::open_with_password(&bytes, PW).is_ok());
        assert!(Vault::open_with_recovery(&old_bytes, &code).is_ok());
    }

    #[test]
    fn v2_item_records_are_bound_like_v1() {
        let (mut v, _code, _) = protected();
        v.insert(note("Synthetic title B", "SYNTHETIC-BODY-B"))
            .unwrap();
        let (bytes, _) = v.seal_next_protected(&mut OsRandom).unwrap();
        let mut j = json(&bytes);
        j["items"].as_array_mut().unwrap().pop();
        assert!(matches!(
            Vault::open_with_password(&bytes_of(&j), PW),
            Err(Error::Integrity(_))
        ));
        let mut j = json(&bytes);
        let a = j["items"][0]["sealed"].clone();
        j["items"][0]["sealed"] = j["items"][1]["sealed"].clone();
        j["items"][1]["sealed"] = a;
        assert!(Vault::open_with_password(&bytes_of(&j), PW).is_err());
    }

    // --- review fixes: recovery binding, duplicate JSON members --------------

    #[test]
    fn v2_pending_recovery_from_another_vault_is_refused_and_changes_nothing() {
        let (mut a, code_a, _) = protected();
        let (setup, key) = shared();
        let other = ProtectedSetup {
            vault_id: data_encoding::HEXLOWER.encode(&[0x22; 16]),
            password: setup.password.clone(),
        };
        let (mut b, code_b) = Vault::create_protected(&other, key, &mut OsRandom).unwrap();
        b.confirm_recovery(&code_b).unwrap();
        let pending = a
            .begin_recovery_change(Authority::Recovery(&code_a), &mut OsRandom)
            .unwrap();
        let confirmation = RecoveryCode::parse(&pending.code().to_text()).unwrap();
        let before = b.slots().unwrap().clone();
        assert!(b.finish_recovery_change(pending, &confirmation).is_err());
        assert_eq!(b.slots().unwrap(), &before, "recovery slot untouched");
        let (bytes, _) = b.seal_next_protected(&mut OsRandom).unwrap();
        assert!(
            Vault::open_with_recovery(&bytes, &code_b).is_ok(),
            "old code still works"
        );
        assert!(Vault::open_with_recovery(&bytes, &confirmation).is_err());
        // An unconfirmed receiving vault is not marked confirmed by a foreign pending.
        let (mut c, _code_c) = Vault::create_protected(&other, key, &mut OsRandom).unwrap();
        let pending = a
            .begin_recovery_change(Authority::Recovery(&code_a), &mut OsRandom)
            .unwrap();
        let confirmation = RecoveryCode::parse(&pending.code().to_text()).unwrap();
        assert!(c.finish_recovery_change(pending, &confirmation).is_err());
        assert!(!c.recovery_confirmed());
        // The same pending still works in its own vault.
        let pending = a
            .begin_recovery_change(Authority::Recovery(&code_a), &mut OsRandom)
            .unwrap();
        let confirmation = RecoveryCode::parse(&pending.code().to_text()).unwrap();
        a.finish_recovery_change(pending, &confirmation).unwrap();
        let (bytes, _) = a.seal_next_protected(&mut OsRandom).unwrap();
        assert!(Vault::open_with_recovery(&bytes, &confirmation).is_ok());
    }

    #[test]
    fn v2_pending_recovery_stays_valid_across_a_password_change() {
        // Same vault, same DEK: a password rewrap in between does not
        // invalidate a pending recovery code (documented semantics).
        let (mut v, code, _) = protected();
        let pending = v
            .begin_recovery_change(Authority::Recovery(&code), &mut OsRandom)
            .unwrap();
        let confirmation = RecoveryCode::parse(&pending.code().to_text()).unwrap();
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let k = setup.derive("synthetic interim passphrase").unwrap();
        v.change_password(Authority::Recovery(&code), &setup, &k, &mut OsRandom)
            .unwrap();
        v.finish_recovery_change(pending, &confirmation).unwrap();
        let (bytes, _) = v.seal_next_protected(&mut OsRandom).unwrap();
        assert!(Vault::open_with_recovery(&bytes, &confirmation).is_ok());
        assert!(Vault::open_with_recovery(&bytes, &code).is_err());
    }

    /// Insert raw text (duplicate members cannot be built with `Value`).
    fn raw_dup(bytes: &[u8], find: &str, replace: &str) -> Vec<u8> {
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(s.contains(find), "fixture shape: {find}");
        s.replacen(find, replace, 1).into_bytes()
    }

    #[test]
    fn v2_duplicate_json_members_are_rejected_at_every_level() {
        let (_v, code, bytes) = protected();
        let cases = [
            (
                "top-level version",
                "\"version\": 2,",
                "\"version\": 999, \"version\": 2,",
            ),
            (
                "top-level revision",
                "\"revision\": 1,",
                "\"revision\": 1, \"revision\": 1,",
            ),
            (
                "slot kind",
                "\"kind\": \"password\",",
                "\"kind\": \"recovery\", \"kind\": \"password\",",
            ),
            (
                "kdf m_kib",
                "\"m_kib\": 65536,",
                "\"m_kib\": 4294967295, \"m_kib\": 65536,",
            ),
            (
                "kdf tag",
                "\"alg\": \"argon2id\",",
                "\"alg\": \"argon2id\", \"alg\": \"argon2id\",",
            ),
            (
                "wrapped nonce",
                "\"wrapped\": {",
                "\"wrapped\": { \"ct\": \"AAAA\",",
            ),
            ("item rev", "\"rev\": 1,", "\"rev\": 1, \"rev\": 1,"),
        ];
        for (name, find, replace) in cases {
            let dup = raw_dup(&bytes, find, replace);
            assert!(
                matches!(read_header(&dup), Err(Error::Format(_))),
                "{name}: header"
            );
            assert!(
                matches!(password_request(&dup), Err(Error::Format(_))),
                "{name}: request"
            );
            let r = Vault::open_with_password(&dup, PW);
            assert!(matches!(r, Err(Error::Format(_))), "{name}: {r:?}");
            assert!(
                Vault::open_with_recovery(&dup, &code).is_err(),
                "{name}: recovery"
            );
        }
        // The untouched envelope still opens (no false positives on valid input).
        assert!(Vault::open_with_password(&bytes, PW).is_ok());
    }

    #[test]
    fn v1_duplicate_json_members_are_rejected_and_valid_v1_still_opens() {
        let p = provider();
        let (_v, bytes) = sample(&p);
        for (find, replace) in [
            ("\"version\": 1,", "\"version\": 2, \"version\": 1,"),
            ("\"kek_id\": ", "\"kek_id\": \"x\", \"kek_id\": "),
        ] {
            let dup = raw_dup(&bytes, find, replace);
            assert!(
                matches!(Vault::decrypt(&dup, &p), Err(Error::Format(_))),
                "{find}"
            );
        }
        assert_eq!(Vault::decrypt(&bytes, &p).unwrap().len(), 2);
    }
}
