//! Envelope v2 key slots: independent wrappers of one data key (DEK).
//!
//! Each slot wraps the same random DEK with its own key-encryption key:
//!
//! ```text
//! password : KEK = HKDF-SHA256(salt = ∅, ikm = Argon2id(NFC(pw), salt, m, t, p), info)
//! recovery : KEK = HKDF-SHA256(salt,      ikm = recovery secret (256 bits),     info)
//! info     = fields("keymesh.vault", "2", "kek", kind, vault_id, slot_id)
//! wrapped  = XChaCha20-Poly1305(KEK, DEK, AAD = slot_aad)
//! slot_aad = fields("keymesh.vault", "2", "slot", aead, vault_id, slot_id, kind, canonical(kdf))
//! ```
//!
//! Before a slot is unlocked, everything it stores is checked against fixed
//! bounds (ids, kinds, algorithm, KDF cost, salt and ciphertext lengths). The
//! AAD binds the vault id, slot id, kind and canonical KDF parameters, so a
//! changed parameter or a slot moved between vaults fails to unwrap. After
//! unlock, the manifest (sealed with the DEK) binds [`slots_digest`] of the
//! whole slot list, so a removed, added, duplicated or altered slot is
//! detected even if the slot that was used is intact.

use crate::crypto::{self, Key256, Sealed, AEAD_ALG, KEY_LEN, NONCE_LEN};
use crate::error::{Error, Result};
use crate::kdf::{self, fields, KdfParams, SALT_LEN};
use crate::recovery::RecoveryCode;
use crate::rng::{random_array, RandomSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const KIND_PASSWORD: &str = "password";
pub const KIND_RECOVERY: &str = "recovery";
/// Quick unlock with a WebAuthn PRF passkey (M5 C1, ADR 0003 §4.1).
pub const KIND_WEBAUTHN_PRF: &str = "webauthn-prf";
pub const MAX_PRF_SLOTS: usize = 4;
pub const PRF_LEN: usize = 32;
pub const PRF_SALT_LEN: usize = 32;
pub const MAX_CREDENTIAL_ID: usize = 1023;
pub const MIN_CREDENTIAL_ID: usize = 16;
pub const MAX_RP_ID: usize = 253;
pub const MAX_PRF_LABEL: usize = 64;
/// Upper bound on slots read from a file (this version writes exactly two).
pub const MAX_SLOTS: usize = 8;
const WRAPPED_LEN: usize = KEY_LEN + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Password,
    Recovery,
    WebauthnPrf,
}

impl SlotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotKind::Password => KIND_PASSWORD,
            SlotKind::Recovery => KIND_RECOVERY,
            SlotKind::WebauthnPrf => KIND_WEBAUTHN_PRF,
        }
    }
}

/// Key-derivation record stored in a slot (wire form).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "alg", deny_unknown_fields)]
pub enum KdfRecord {
    #[serde(rename = "argon2id")]
    Argon2id {
        v: u32,
        m_kib: u32,
        t: u32,
        p: u32,
        #[serde(with = "b64")]
        salt: Vec<u8>,
    },
    #[serde(rename = "hkdf-sha256")]
    HkdfSha256 {
        #[serde(with = "b64")]
        salt: Vec<u8>,
    },
    /// PRF output (32 bytes) → HKDF-SHA256; every field is authenticated.
    #[serde(rename = "webauthn-prf-hkdf")]
    WebauthnPrfHkdf {
        #[serde(with = "b64")]
        credential_id: Vec<u8>,
        rp_id: String,
        #[serde(with = "b64")]
        salt: Vec<u8>,
        be: bool,
        label: String,
    },
}

impl KdfRecord {
    /// Unambiguous byte encoding bound into the slot AAD.
    fn canonical(&self) -> Vec<u8> {
        match self {
            KdfRecord::Argon2id {
                v,
                m_kib,
                t,
                p,
                salt,
            } => fields(&[
                b"argon2id",
                &v.to_be_bytes(),
                &m_kib.to_be_bytes(),
                &t.to_be_bytes(),
                &p.to_be_bytes(),
                salt,
            ]),
            KdfRecord::HkdfSha256 { salt } => fields(&[b"hkdf-sha256", salt]),
            KdfRecord::WebauthnPrfHkdf {
                credential_id,
                rp_id,
                salt,
                be,
                label,
            } => fields(&[
                b"webauthn-prf-hkdf",
                credential_id,
                rp_id.as_bytes(),
                salt,
                &[u8::from(*be)],
                label.as_bytes(),
            ]),
        }
    }
}

/// One slot as stored in the envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotRecord {
    pub id: String,
    pub kind: String,
    pub kdf: KdfRecord,
    pub wrapped: Sealed,
}

/// A validated slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    rec: SlotRecord,
    kind: SlotKind,
}

/// What the password KDF needs: public, non-secret parameters of a password
/// slot (existing or about to be created).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordSetup {
    pub slot_id: String,
    pub salt: [u8; SALT_LEN],
    pub params: KdfParams,
}

impl PasswordSetup {
    /// Fresh slot id and salt with the stored default parameters.
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Self {
            slot_id: new_slot_id(rng)?,
            salt: kdf::random_salt(rng)?,
            params: KdfParams::DEFAULT,
        })
    }

    /// Run Argon2id for this setup (native callers; the browser runs it in a
    /// worker through the same function).
    pub fn derive(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        kdf::argon2id(password, &self.salt, self.params)
    }
}

pub(crate) fn new_slot_id(rng: &mut dyn RandomSource) -> Result<String> {
    Ok(data_encoding::HEXLOWER.encode(&random_array::<8>(rng)?))
}

/// Public parameters of a stored quick-unlock slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrfParams<'a> {
    pub credential_id: &'a [u8],
    pub rp_id: &'a str,
    pub salt: &'a [u8],
    pub be: bool,
    pub label: &'a str,
}

/// Public parameters for a new quick-unlock slot, issued by the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfSetup {
    pub slot_id: String,
    pub salt: [u8; PRF_SALT_LEN],
}

impl PrfSetup {
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Self {
            slot_id: new_slot_id(rng)?,
            salt: random_array::<PRF_SALT_LEN>(rng)?,
        })
    }
}

/// A WebAuthn RP id as stored: lowercase ASCII host, bounded.
fn valid_rp_id(rp: &str) -> bool {
    !rp.is_empty()
        && rp.len() <= MAX_RP_ID
        && rp
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
        && !rp.starts_with('.')
        && !rp.ends_with('.')
}

fn valid_label(label: &str) -> bool {
    label.len() <= MAX_PRF_LABEL && !label.chars().any(char::is_control)
}

fn valid_slot_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn slot_aad(vault_id: &str, id: &str, kind: SlotKind, kdf: &KdfRecord) -> Vec<u8> {
    fields(&[
        b"keymesh.vault",
        b"2",
        b"slot",
        AEAD_ALG.as_bytes(),
        vault_id.as_bytes(),
        id.as_bytes(),
        kind.as_str().as_bytes(),
        &kdf.canonical(),
    ])
}

fn bad(msg: &str) -> Error {
    Error::Format(msg.into())
}

impl Slot {
    /// Validate one stored slot. Nothing is derived or allocated by size.
    fn validate(rec: SlotRecord) -> Result<Self> {
        if !valid_slot_id(&rec.id) {
            return Err(bad("invalid key slot id"));
        }
        let kind = match (rec.kind.as_str(), &rec.kdf) {
            (
                KIND_PASSWORD,
                KdfRecord::Argon2id {
                    v,
                    m_kib,
                    t,
                    p,
                    salt,
                },
            ) => {
                if *v != kdf::ARGON2_VERSION || salt.len() != SALT_LEN {
                    return Err(bad("unsupported password key slot"));
                }
                KdfParams {
                    m_kib: *m_kib,
                    t: *t,
                    p: *p,
                }
                .check()?;
                SlotKind::Password
            }
            (KIND_RECOVERY, KdfRecord::HkdfSha256 { salt }) => {
                if salt.len() != SALT_LEN {
                    return Err(bad("unsupported recovery key slot"));
                }
                SlotKind::Recovery
            }
            (
                KIND_WEBAUTHN_PRF,
                KdfRecord::WebauthnPrfHkdf {
                    credential_id,
                    rp_id,
                    salt,
                    label,
                    ..
                },
            ) => {
                if !(MIN_CREDENTIAL_ID..=MAX_CREDENTIAL_ID).contains(&credential_id.len())
                    || salt.len() != PRF_SALT_LEN
                    || !valid_rp_id(rp_id)
                    || !valid_label(label)
                {
                    return Err(bad("unsupported quick-unlock key slot"));
                }
                SlotKind::WebauthnPrf
            }
            (KIND_PASSWORD | KIND_RECOVERY | KIND_WEBAUTHN_PRF, _) => {
                return Err(bad("key slot uses an unexpected algorithm"))
            }
            _ => return Err(bad("unknown key slot kind")),
        };
        if rec.wrapped.nonce.len() != NONCE_LEN || rec.wrapped.ct.len() != WRAPPED_LEN {
            return Err(bad("malformed key slot"));
        }
        Ok(Self { rec, kind })
    }

    pub fn id(&self) -> &str {
        &self.rec.id
    }
    pub fn kind(&self) -> SlotKind {
        self.kind
    }
    pub fn record(&self) -> &SlotRecord {
        &self.rec
    }

    /// Public parameters needed to derive this password slot's key.
    pub fn password_setup(&self) -> Result<PasswordSetup> {
        match &self.rec.kdf {
            KdfRecord::Argon2id {
                m_kib, t, p, salt, ..
            } if self.kind == SlotKind::Password => Ok(PasswordSetup {
                slot_id: self.rec.id.clone(),
                salt: salt
                    .as_slice()
                    .try_into()
                    .map_err(|_| bad("invalid salt"))?,
                params: KdfParams {
                    m_kib: *m_kib,
                    t: *t,
                    p: *p,
                },
            }),
            _ => Err(bad("not a password key slot")),
        }
    }

    fn salt(&self) -> &[u8] {
        match &self.rec.kdf {
            KdfRecord::Argon2id { salt, .. }
            | KdfRecord::HkdfSha256 { salt }
            | KdfRecord::WebauthnPrfHkdf { salt, .. } => salt,
        }
    }

    fn kek(&self, vault_id: &str, ikm: &[u8]) -> Result<Key256> {
        match (&self.kind, &self.rec.kdf) {
            // Argon2id already consumed the slot salt.
            (SlotKind::Password, _) => {
                kdf::slot_kek(ikm, None, self.kind.as_str(), vault_id, &self.rec.id)
            }
            (SlotKind::Recovery, _) => kdf::slot_kek(
                ikm,
                Some(self.salt()),
                self.kind.as_str(),
                vault_id,
                &self.rec.id,
            ),
            // The PRF salt is the authenticator's input, not an HKDF salt;
            // the credential id is bound into `info`.
            (SlotKind::WebauthnPrf, KdfRecord::WebauthnPrfHkdf { credential_id, .. }) => {
                if ikm.len() != PRF_LEN {
                    return Err(Error::Decrypt);
                }
                kdf::slot_kek_with(
                    ikm,
                    None,
                    self.kind.as_str(),
                    vault_id,
                    &self.rec.id,
                    &[credential_id],
                )
            }
            _ => Err(bad("key slot uses an unexpected algorithm")),
        }
    }

    /// Public parameters of a `webauthn-prf` slot.
    pub fn prf_params(&self) -> Option<PrfParams<'_>> {
        match &self.rec.kdf {
            KdfRecord::WebauthnPrfHkdf {
                credential_id,
                rp_id,
                salt,
                be,
                label,
            } => Some(PrfParams {
                credential_id,
                rp_id,
                salt,
                be: *be,
                label,
            }),
            _ => None,
        }
    }

    /// Unwrap the DEK with key material for this slot (Argon2id output for a
    /// password slot, the recovery secret for a recovery slot).
    pub(crate) fn unwrap(&self, vault_id: &str, ikm: &[u8]) -> Result<Key256> {
        let kek = self.kek(vault_id, ikm)?;
        let aad = slot_aad(vault_id, &self.rec.id, self.kind, &self.rec.kdf);
        let pt = crypto::open(&kek, &self.rec.wrapped, &aad)?;
        let arr: [u8; KEY_LEN] = pt
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity("data key has wrong length".into()))?;
        Ok(Key256::from_bytes(arr))
    }

    fn wrap(
        vault_id: &str,
        id: String,
        kind: SlotKind,
        kdf: KdfRecord,
        ikm: &[u8],
        dek: &Key256,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        let mut s = Self {
            rec: SlotRecord {
                id,
                kind: kind.as_str().into(),
                kdf,
                wrapped: Sealed {
                    nonce: vec![],
                    ct: vec![],
                },
            },
            kind,
        };
        let kek = s.kek(vault_id, ikm)?;
        let aad = slot_aad(vault_id, &s.rec.id, kind, &s.rec.kdf);
        s.rec.wrapped = crypto::seal(&kek, rng, &aad, dek.as_bytes())?;
        Ok(s)
    }

    /// New password slot from the Argon2id output for `setup`.
    pub(crate) fn new_password(
        vault_id: &str,
        setup: &PasswordSetup,
        derived: &[u8; 32],
        dek: &Key256,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        setup.params.check()?;
        if !valid_slot_id(&setup.slot_id) {
            return Err(bad("invalid key slot id"));
        }
        let kdf = KdfRecord::Argon2id {
            v: kdf::ARGON2_VERSION,
            m_kib: setup.params.m_kib,
            t: setup.params.t,
            p: setup.params.p,
            salt: setup.salt.to_vec(),
        };
        Self::wrap(
            vault_id,
            setup.slot_id.clone(),
            SlotKind::Password,
            kdf,
            derived,
            dek,
            rng,
        )
    }

    /// New quick-unlock slot: wraps `dek` under the KEK derived from the
    /// authenticator's 32-byte PRF output for `setup.salt`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_prf(
        vault_id: &str,
        setup: &PrfSetup,
        credential_id: &[u8],
        rp_id: &str,
        be: bool,
        label: &str,
        prf_output: &[u8; PRF_LEN],
        dek: &Key256,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        if !valid_slot_id(&setup.slot_id)
            || !(MIN_CREDENTIAL_ID..=MAX_CREDENTIAL_ID).contains(&credential_id.len())
            || !valid_rp_id(rp_id)
            || !valid_label(label)
        {
            return Err(Error::validation("invalid quick-unlock parameters"));
        }
        let kdf = KdfRecord::WebauthnPrfHkdf {
            credential_id: credential_id.to_vec(),
            rp_id: rp_id.to_owned(),
            salt: setup.salt.to_vec(),
            be,
            label: label.to_owned(),
        };
        Self::wrap(
            vault_id,
            setup.slot_id.clone(),
            SlotKind::WebauthnPrf,
            kdf,
            prf_output,
            dek,
            rng,
        )
    }

    /// New recovery slot for `code`, with a fresh id and salt.
    pub(crate) fn new_recovery(
        vault_id: &str,
        code: &RecoveryCode,
        dek: &Key256,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        let id = new_slot_id(rng)?;
        let kdf = KdfRecord::HkdfSha256 {
            salt: kdf::random_salt(rng)?.to_vec(),
        };
        Self::wrap(
            vault_id,
            id,
            SlotKind::Recovery,
            kdf,
            code.secret(),
            dek,
            rng,
        )
    }
}

/// The validated slot list of one vault: exactly one password slot and one
/// recovery slot in this version, unique ids, bounded count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotSet(Vec<Slot>);

impl SlotSet {
    pub(crate) fn new(password: Slot, recovery: Slot) -> Result<Self> {
        Self::check(vec![password, recovery])
    }

    pub(crate) fn from_records(recs: Vec<SlotRecord>) -> Result<Self> {
        if recs.is_empty() || recs.len() > MAX_SLOTS {
            return Err(bad("unexpected number of key slots"));
        }
        Self::check(
            recs.into_iter()
                .map(Slot::validate)
                .collect::<Result<_>>()?,
        )
    }

    fn check(slots: Vec<Slot>) -> Result<Self> {
        let mut ids = BTreeSet::new();
        for s in &slots {
            if !ids.insert(s.id().to_owned()) {
                return Err(bad("duplicate key slot id"));
            }
        }
        let count = |k| slots.iter().filter(|s| s.kind == k).count();
        if count(SlotKind::Password) != 1 || count(SlotKind::Recovery) != 1 {
            return Err(bad(
                "a vault needs exactly one password slot and one recovery slot",
            ));
        }
        if count(SlotKind::WebauthnPrf) > MAX_PRF_SLOTS {
            return Err(bad("too many quick-unlock key slots"));
        }
        let mut creds = BTreeSet::new();
        for s in &slots {
            if let Some(p) = s.prf_params() {
                if !creds.insert(p.credential_id.to_vec()) {
                    return Err(bad("duplicate quick-unlock credential"));
                }
            }
        }
        Ok(Self(slots))
    }

    pub fn records(&self) -> Vec<SlotRecord> {
        self.0.iter().map(|s| s.rec.clone()).collect()
    }

    /// The quick-unlock slots, in file order.
    pub fn prf_slots(&self) -> impl Iterator<Item = &Slot> {
        self.0.iter().filter(|s| s.kind == SlotKind::WebauthnPrf)
    }

    /// The quick-unlock slot for exactly this credential id.
    pub fn prf_slot(&self, credential_id: &[u8]) -> Option<&Slot> {
        self.prf_slots().find(|s| {
            s.prf_params()
                .is_some_and(|p| p.credential_id == credential_id)
        })
    }

    /// Add a quick-unlock slot (refused past the bound or for a duplicate).
    pub(crate) fn with_prf(&self, slot: Slot) -> Result<Self> {
        let mut v = self.0.clone();
        v.push(slot);
        Self::check(v)
    }

    /// Remove one quick-unlock slot by id (password/recovery can't be removed).
    pub(crate) fn without_prf(&self, slot_id: &str) -> Result<Self> {
        if !self.prf_slots().any(|s| s.id() == slot_id) {
            return Err(Error::validation("no such quick-unlock key slot"));
        }
        Self::check(
            self.0
                .iter()
                .filter(|s| s.id() != slot_id)
                .cloned()
                .collect(),
        )
    }

    pub fn get(&self, kind: SlotKind) -> &Slot {
        // `check` guarantees exactly one of each kind.
        self.0
            .iter()
            .find(|s| s.kind == kind)
            .expect("validated slot set")
    }

    /// Replace the slot of the same kind (rewrap: the DEK is unchanged).
    /// Only for the single password and recovery slots.
    pub(crate) fn replace(&self, slot: Slot) -> Result<Self> {
        let kind = slot.kind;
        if kind == SlotKind::WebauthnPrf {
            return Err(Error::validation(
                "quick-unlock slots are added or removed, not replaced",
            ));
        }
        let mut v: Vec<Slot> = self.0.iter().filter(|s| s.kind != kind).cloned().collect();
        // Keep a stable order: password first.
        if kind == SlotKind::Password {
            v.insert(0, slot);
        } else {
            v.push(slot);
        }
        Self::check(v)
    }

    /// SHA-256 over the canonical encoding of every slot, in file order.
    /// Bound into the manifest AAD (see module docs).
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update((self.0.len() as u32).to_be_bytes());
        for s in &self.0 {
            h.update(fields(&[
                s.rec.id.as_bytes(),
                s.kind.as_str().as_bytes(),
                &s.rec.kdf.canonical(),
                &s.rec.wrapped.nonce,
                &s.rec.wrapped.ct,
            ]));
        }
        h.finalize().into()
    }
}

/// Proof of local authority over a vault, verified by unwrapping a slot and
/// comparing the result with the vault's DEK. A UI flag is never enough.
pub enum Authority<'a> {
    /// Argon2id output for the vault's CURRENT password slot.
    PasswordKey(&'a [u8; 32]),
    Recovery(&'a RecoveryCode),
}

impl Authority<'_> {
    pub(crate) fn verify(&self, vault_id: &str, slots: &SlotSet, dek: &Key256) -> Result<()> {
        let unwrapped = match self {
            Authority::PasswordKey(k) => slots.get(SlotKind::Password).unwrap(vault_id, &k[..]),
            Authority::Recovery(c) => slots.get(SlotKind::Recovery).unwrap(vault_id, c.secret()),
        }?;
        if bool::from(unwrapped.as_bytes().ct_eq(dek.as_bytes())) {
            Ok(())
        } else {
            Err(Error::Decrypt)
        }
    }
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > 64 {
            return Err(serde::de::Error::custom("salt too long"));
        }
        data_encoding::BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom("invalid base64url"))
    }
}

/// Zeroizing helper for callers holding derived key material.
pub type DerivedKey = Zeroizing<[u8; 32]>;
