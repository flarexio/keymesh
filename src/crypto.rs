//! Authenticated encryption primitives and the key-provider port.
//!
//! * AEAD: XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`), 256-bit keys,
//!   192-bit random nonces drawn fresh from the CSPRNG for every encryption.
//! * Key hierarchy: a [`KeyProvider`] supplies a key-encryption key (KEK). The
//!   KEK wraps a random per-vault data-encryption key (DEK). The DEK encrypts
//!   items and the manifest. Ed25519 signing keys stored in the vault are
//!   *data*; they are never used as, or derived from, the DEK/KEK.
//!
//! Production unlock (passphrase KDF, OS keystore, hardware keys) is **not
//! implemented in M1**. Only synthetic providers exist, clearly labelled.

use crate::error::{Error, Result};
use crate::rng::{random_array, RandomSource};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const AEAD_ALG: &str = "xchacha20poly1305";

/// A 256-bit symmetric key, zeroized on drop.
#[derive(Clone)]
pub struct Key256(Zeroizing<[u8; KEY_LEN]>);

impl Key256 {
    pub fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Key256(Zeroizing::new(b))
    }
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Key256(Zeroizing::new(random_array::<KEY_LEN>(rng)?)))
    }
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for Key256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key256(<redacted>)")
    }
}

/// Port through which the vault obtains its key-encryption key.
///
/// Implementations must not persist the KEK beside the vault ciphertext.
pub trait KeyProvider {
    /// Public, non-secret identifier recorded in the vault header.
    fn key_id(&self) -> &str;
    fn key_encryption_key(&self) -> Result<Key256>;
}

/// In-memory random KEK that disappears with the process. Intended for tests.
pub struct EphemeralKeyProvider {
    id: String,
    key: Key256,
}

impl EphemeralKeyProvider {
    pub fn generate(id: impl Into<String>, rng: &mut dyn RandomSource) -> Result<Self> {
        let id = id.into();
        validate_key_id(&id)?;
        Ok(Self {
            id,
            key: Key256::generate(rng)?,
        })
    }
}

impl KeyProvider for EphemeralKeyProvider {
    fn key_id(&self) -> &str {
        &self.id
    }
    fn key_encryption_key(&self) -> Result<Key256> {
        Ok(self.key.clone())
    }
}

/// **SYNTHETIC DEMO ONLY — NOT PRODUCTION UNLOCK.**
///
/// A KEK supplied by the caller as 64 hex characters (e.g. from an
/// environment variable set for a demo/test run). It is never written to disk
/// by Keymesh. It exists so the CLI harness can run across processes until a
/// real unlock mechanism is designed.
pub struct SyntheticDemoKeyProvider {
    id: String,
    key: Key256,
}

impl SyntheticDemoKeyProvider {
    pub const KEY_ID: &'static str = "synthetic-demo-v1";

    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = Zeroizing::new(hex.trim().to_ascii_lowercase());
        let bytes = Zeroizing::new(
            data_encoding::HEXLOWER
                .decode(hex.as_bytes())
                .map_err(|_| Error::KeyProvider("demo key must be 64 hex characters".into()))?,
        );
        let arr: [u8; KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::KeyProvider("demo key must be 64 hex characters".into()))?;
        Ok(Self {
            id: Self::KEY_ID.into(),
            key: Key256::from_bytes(arr),
        })
    }
}

impl KeyProvider for SyntheticDemoKeyProvider {
    fn key_id(&self) -> &str {
        &self.id
    }
    fn key_encryption_key(&self) -> Result<Key256> {
        Ok(self.key.clone())
    }
}

pub(crate) fn validate_key_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(Error::KeyProvider("invalid key id".into()))
    }
}

/// Nonce + ciphertext (which includes the 16-byte Poly1305 tag).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ct: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed({} bytes)", self.ct.len())
    }
}

impl Sealed {
    /// Bytes covered by manifest digests.
    pub(crate) fn digest_input(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.nonce.len() + self.ct.len());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ct);
        v
    }
}

pub fn seal(key: &Key256, rng: &mut dyn RandomSource, aad: &[u8], pt: &[u8]) -> Result<Sealed> {
    let nonce = random_array::<NONCE_LEN>(rng)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad })
        .map_err(|_| Error::Integrity("encryption failed".into()))?;
    Ok(Sealed {
        nonce: nonce.to_vec(),
        ct,
    })
}

pub fn open(key: &Key256, sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.nonce.len() != NONCE_LEN || sealed.ct.len() < 16 {
        return Err(Error::Decrypt);
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&data_encoding::BASE64URL_NOPAD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        data_encoding::BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom("invalid base64url"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::FailingRandom;
    use crate::rng::OsRandom;

    #[test]
    fn round_trip_and_aad_binding() {
        let k = Key256::generate(&mut OsRandom).unwrap();
        let s = seal(&k, &mut OsRandom, b"aad-1", b"synthetic plaintext").unwrap();
        assert_eq!(&*open(&k, &s, b"aad-1").unwrap(), b"synthetic plaintext");
        assert!(matches!(open(&k, &s, b"aad-2"), Err(Error::Decrypt)));
    }

    #[test]
    fn wrong_key_and_tamper_fail_closed() {
        let k = Key256::generate(&mut OsRandom).unwrap();
        let k2 = Key256::generate(&mut OsRandom).unwrap();
        let s = seal(&k, &mut OsRandom, b"", b"data").unwrap();
        assert!(matches!(open(&k2, &s, b""), Err(Error::Decrypt)));
        let mut t = s.clone();
        t.ct[0] ^= 1;
        assert!(matches!(open(&k, &t, b""), Err(Error::Decrypt)));
        let mut t = s.clone();
        t.ct.truncate(10);
        assert!(matches!(open(&k, &t, b""), Err(Error::Decrypt)));
        let mut t = s;
        t.nonce.pop();
        assert!(matches!(open(&k, &t, b""), Err(Error::Decrypt)));
    }

    #[test]
    fn nonces_are_fresh() {
        let k = Key256::generate(&mut OsRandom).unwrap();
        let a = seal(&k, &mut OsRandom, b"", b"x").unwrap();
        let b = seal(&k, &mut OsRandom, b"", b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ct, b.ct);
    }

    #[test]
    fn rng_failure_is_error() {
        assert!(Key256::generate(&mut FailingRandom).is_err());
        let k = Key256::generate(&mut OsRandom).unwrap();
        assert!(seal(&k, &mut FailingRandom, b"", b"x").is_err());
    }

    #[test]
    fn demo_provider_parses_hex_only() {
        assert!(SyntheticDemoKeyProvider::from_hex(&"ab".repeat(32)).is_ok());
        assert!(SyntheticDemoKeyProvider::from_hex("abcd").is_err());
        assert!(SyntheticDemoKeyProvider::from_hex(&"zz".repeat(32)).is_err());
    }
}
