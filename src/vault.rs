//! In-memory vault and its versioned encrypted file format (`keymesh.vault` v1).
//!
//! ```text
//! VaultFile (JSON)
//!   format = "keymesh.vault", version = 1, aead = "xchacha20poly1305"
//!   vault_id (random 128-bit hex), kek_id (key provider id), revision (u64)
//!   wrapped_dek : Seal(KEK, AAD = dek_aad(vault_id, kek_id), DEK)
//!   manifest    : Seal(DEK, AAD = header_aad(..revision..), [{id, rev, sha256(item sealed)}])
//!   items[]     : {id, rev, sealed: Seal(DEK, AAD = item_aad(vault_id, id, rev), Item JSON)}
//! ```
//!
//! Public metadata is limited to the header and each item's random id and
//! revision. Titles, URLs, notes, kinds and all secret fields are encrypted.
//! The manifest is bound to the header revision and lists every item record's
//! digest, so dropping, duplicating, or swapping individual item records is
//! detected. Rolling back the *entire* file to an older valid version cannot be
//! detected without external state (documented limitation).

use crate::crypto::{self, Key256, KeyProvider, Sealed, AEAD_ALG};
use crate::error::{Error, Result};
use crate::model::{Item, ItemData, ItemId, ItemKind};
use crate::rng::{random_array, RandomSource};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const FORMAT: &str = "keymesh.vault";
pub const VERSION: u32 = 1;

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
    pub vault_id: String,
    pub kek_id: String,
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

fn sha256_hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&Sha256::digest(b))
}

/// Parse and validate the unencrypted envelope without decrypting.
fn parse_file(bytes: &[u8]) -> Result<VaultFile> {
    // Check format/version before strict parsing so future versions produce a
    // clear "unknown format" error rather than a schema error.
    let probe: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| Error::Format("not a keymesh vault (unparseable)".into()))?;
    let fmt = probe.get("format").and_then(|v| v.as_str());
    let ver = probe.get("version").and_then(|v| v.as_u64());
    if fmt != Some(FORMAT) {
        return Err(Error::Format("not a keymesh vault".into()));
    }
    if ver != Some(u64::from(VERSION)) {
        return Err(Error::Format("unsupported vault version".into()));
    }
    let f: VaultFile = serde_json::from_value(probe)
        .map_err(|_| Error::Format("malformed keymesh vault envelope".into()))?;
    if f.aead != AEAD_ALG {
        return Err(Error::Format("unsupported AEAD algorithm".into()));
    }
    Ok(f)
}

pub fn read_header(bytes: &[u8]) -> Result<VaultHeader> {
    let f = parse_file(bytes)?;
    Ok(VaultHeader {
        vault_id: f.vault_id,
        kek_id: f.kek_id,
        revision: f.revision,
    })
}

/// `Clone` lets storage adapters keep a last-committed checkpoint; clones hold
/// their own copy of the data key, zeroized on drop like the original.
#[derive(Clone)]
pub struct Vault {
    vault_id: String,
    kek_id: String,
    /// Revision of the file this vault was decrypted from (0 for a new vault).
    loaded_revision: u64,
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

impl Vault {
    /// New empty vault with a fresh random data key.
    pub fn create(provider: &dyn KeyProvider, rng: &mut dyn RandomSource) -> Result<Self> {
        crypto::validate_key_id(provider.key_id())?;
        // Ensure the provider is usable before we hand out a vault.
        provider.key_encryption_key()?;
        Ok(Self {
            vault_id: data_encoding::HEXLOWER.encode(&random_array::<16>(rng)?),
            kek_id: provider.key_id().to_owned(),
            loaded_revision: 0,
            dek: Key256::generate(rng)?,
            items: BTreeMap::new(),
        })
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn revision(&self) -> u64 {
        self.loaded_revision
    }

    /// Decrypt and fully verify a vault file. Any failure is an error; a
    /// failed decrypt never yields an empty vault.
    pub fn decrypt(bytes: &[u8], provider: &dyn KeyProvider) -> Result<Self> {
        let f = parse_file(bytes)?;
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

        let manifest_pt = crypto::open(
            &dek,
            &f.manifest,
            &header_aad(&f.vault_id, &f.kek_id, f.revision),
        )?;
        let manifest: Manifest = serde_json::from_slice(&manifest_pt)
            .map_err(|_| Error::Integrity("malformed manifest".into()))?;
        if manifest.vault_id != f.vault_id || manifest.revision != f.revision {
            return Err(Error::Integrity("manifest does not match header".into()));
        }
        if manifest.entries.len() != f.items.len() {
            return Err(Error::Integrity(
                "item count does not match manifest".into(),
            ));
        }

        let mut items = BTreeMap::new();
        for (rec, entry) in f.items.iter().zip(&manifest.entries) {
            if rec.id != entry.id
                || rec.rev != entry.rev
                || sha256_hex(&rec.sealed.digest_input()) != entry.sha256
            {
                return Err(Error::Integrity(
                    "item record does not match manifest".into(),
                ));
            }
            let pt = crypto::open(&dek, &rec.sealed, &item_aad(&f.vault_id, &rec.id, rec.rev))?;
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
        let v = Self {
            vault_id: f.vault_id,
            kek_id: f.kek_id,
            loaded_revision: f.revision,
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
        self.loaded_revision = rev;
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

    /// Encrypt to revision `self.revision() + 1` without mutating the vault.
    /// Every item and the manifest get fresh nonces. Storage adapters write
    /// the bytes, then call [`Vault::mark_persisted`].
    pub fn seal_next(
        &self,
        provider: &dyn KeyProvider,
        rng: &mut dyn RandomSource,
    ) -> Result<(Vec<u8>, u64)> {
        if provider.key_id() != self.kek_id {
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
            &dek_aad(&self.vault_id, &self.kek_id),
            self.dek.as_bytes(),
        )?;
        let mut records = Vec::with_capacity(self.items.len());
        let mut entries = Vec::with_capacity(self.items.len());
        for item in self.items.values() {
            item.validate()?;
            let pt = Zeroizing::new(
                serde_json::to_vec(item).map_err(|_| Error::Integrity("serialize item".into()))?,
            );
            let sealed = crypto::seal(
                &self.dek,
                rng,
                &item_aad(&self.vault_id, &item.id, item.rev),
                &pt,
            )?;
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
        let manifest = crypto::seal(
            &self.dek,
            rng,
            &header_aad(&self.vault_id, &self.kek_id, revision),
            &manifest_pt,
        )?;
        let file = VaultFile {
            format: FORMAT.into(),
            version: VERSION,
            aead: AEAD_ALG.into(),
            vault_id: self.vault_id.clone(),
            kek_id: self.kek_id.clone(),
            revision,
            wrapped_dek,
            manifest,
            items: records,
        };
        let out = serde_json::to_vec_pretty(&file)
            .map_err(|_| Error::Integrity("serialize vault".into()))?;
        Ok((out, revision))
    }

    /// Replace the data key; all items are re-encrypted on the next save.
    pub fn rotate_data_key(&mut self, rng: &mut dyn RandomSource) -> Result<()> {
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
}
