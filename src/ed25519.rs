//! Ed25519 key generation and storage format (RFC 8032, via `ed25519-dalek`).
//!
//! Stored format: the 32-byte RFC 8032 private key ("seed") plus the 32-byte
//! public key, both raw bytes. This is **not** OpenSSH or PKCS#8. The only
//! standard-format adapter in M1 is OpenSSH *public key* line output
//! (`ssh-ed25519 AAAA...`). Private-key export formats are deferred.
//!
//! Keymesh deliberately exposes no general "sign arbitrary bytes" API and these
//! keys are not used for Keymesh login or vault encryption.

use crate::error::{Error, Result};
use crate::rng::{random_array, RandomSource};
use crate::secret::SecretBytes;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SEED_LEN: usize = 32;
pub const PUBLIC_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519KeyPair {
    /// RFC 8032 32-byte private key (seed).
    pub seed: SecretBytes,
    /// RFC 8032 32-byte public key, lowercase hex.
    pub public_key_hex: String,
}

impl Ed25519KeyPair {
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        let seed = Zeroizing::new(random_array::<SEED_LEN>(rng)?);
        Self::from_seed(&seed[..])
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: Zeroizing<[u8; SEED_LEN]> = Zeroizing::new(
            seed.try_into()
                .map_err(|_| Error::Ed25519("seed must be exactly 32 bytes".into()))?,
        );
        let sk = SigningKey::from_bytes(&seed);
        Ok(Self {
            seed: SecretBytes::new(seed.to_vec()),
            public_key_hex: data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()),
        })
    }

    /// Import a raw seed written as 64 hex characters.
    pub fn from_seed_hex(hex: &str) -> Result<Self> {
        let bytes = Zeroizing::new(
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(hex.trim().as_bytes())
                .map_err(|_| Error::Ed25519("seed must be 64 hex characters".into()))?,
        );
        Self::from_seed(&bytes)
    }

    pub fn public_key_bytes(&self) -> Result<[u8; PUBLIC_LEN]> {
        data_encoding::HEXLOWER
            .decode(self.public_key_hex.as_bytes())
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| Error::Ed25519("invalid public key encoding".into()))
    }

    /// Checks the stored public key matches the seed.
    pub fn validate(&self) -> Result<()> {
        let derived = Self::from_seed(self.seed.expose())?;
        if derived.public_key_hex != self.public_key_hex {
            return Err(Error::Ed25519("public key does not match seed".into()));
        }
        Ok(())
    }

    /// OpenSSH `authorized_keys` style public-key line.
    pub fn openssh_public_key(&self, comment: Option<&str>) -> Result<String> {
        let pk = self.public_key_bytes()?;
        let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&(PUBLIC_LEN as u32).to_be_bytes());
        blob.extend_from_slice(&pk);
        let mut line = format!("ssh-ed25519 {}", data_encoding::BASE64.encode(&blob));
        if let Some(c) = comment.filter(|c| !c.is_empty()) {
            if c.chars().any(|ch| ch.is_control()) {
                return Err(Error::Ed25519("comment contains control characters".into()));
            }
            line.push(' ');
            line.push_str(c);
        }
        Ok(line)
    }

    /// Test-only: M1 intentionally ships no signing API.
    #[cfg(test)]
    pub(crate) fn signing_key(&self) -> Result<SigningKey> {
        let seed: [u8; SEED_LEN] = self
            .seed
            .expose()
            .try_into()
            .map_err(|_| Error::Ed25519("seed must be exactly 32 bytes".into()))?;
        let seed = Zeroizing::new(seed);
        Ok(SigningKey::from_bytes(&seed))
    }
}

/// Verify an RFC 8032 Ed25519 signature (strict verification).
pub fn verify(public_key: &[u8; PUBLIC_LEN], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(public_key)
        .map_err(|_| Error::Ed25519("invalid public key".into()))?;
    let sig = Signature::from_slice(sig).map_err(|_| Error::Ed25519("invalid signature".into()))?;
    vk.verify_strict(msg, &sig)
        .map_err(|_| Error::Ed25519("signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::FailingRandom;
    use crate::rng::OsRandom;
    use ed25519_dalek::Signer;

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    // RFC 8032 §7.1 TEST 1, TEST 2, TEST 3.
    const VECTORS: &[(&str, &str, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
    ];

    #[test]
    fn rfc8032_vectors() {
        for (sk, pk, msg, sig) in VECTORS {
            let kp = Ed25519KeyPair::from_seed_hex(sk).unwrap();
            assert_eq!(kp.public_key_hex, *pk);
            let signature = kp.signing_key().unwrap().sign(&hex(msg));
            assert_eq!(data_encoding::HEXLOWER.encode(&signature.to_bytes()), *sig);
            verify(&kp.public_key_bytes().unwrap(), &hex(msg), &hex(sig)).unwrap();
        }
    }

    #[test]
    fn generated_key_signs_and_verifies() {
        let kp = Ed25519KeyPair::generate(&mut OsRandom).unwrap();
        kp.validate().unwrap();
        let sig = kp.signing_key().unwrap().sign(b"synthetic message");
        let pk = kp.public_key_bytes().unwrap();
        verify(&pk, b"synthetic message", &sig.to_bytes()).unwrap();
        assert!(verify(&pk, b"tampered message", &sig.to_bytes()).is_err());
        let mut bad = sig.to_bytes();
        bad[0] ^= 1;
        assert!(verify(&pk, b"synthetic message", &bad).is_err());
    }

    #[test]
    fn serde_round_trip_and_mismatch_detection() {
        let kp = Ed25519KeyPair::generate(&mut OsRandom).unwrap();
        let j = serde_json::to_string(&kp).unwrap();
        let back: Ed25519KeyPair = serde_json::from_str(&j).unwrap();
        assert_eq!(back, kp);
        back.validate().unwrap();
        let other = Ed25519KeyPair::generate(&mut OsRandom).unwrap();
        let forged = Ed25519KeyPair {
            seed: kp.seed.clone(),
            public_key_hex: other.public_key_hex,
        };
        assert!(forged.validate().is_err());
    }

    #[test]
    fn rejects_bad_lengths_and_rng_failure() {
        assert!(Ed25519KeyPair::from_seed(&[0u8; 31]).is_err());
        assert!(Ed25519KeyPair::from_seed(&[0u8; 64]).is_err());
        assert!(Ed25519KeyPair::from_seed_hex("abcd").is_err());
        assert!(Ed25519KeyPair::generate(&mut FailingRandom).is_err());
    }

    #[test]
    fn openssh_public_key_format() {
        let kp = Ed25519KeyPair::from_seed_hex(VECTORS[0].0).unwrap();
        let line = kp.openssh_public_key(Some("synthetic@test")).unwrap();
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(line.ends_with(" synthetic@test"));
        let b64 = line.split(' ').nth(1).unwrap();
        let blob = data_encoding::BASE64.decode(b64.as_bytes()).unwrap();
        assert_eq!(&blob[blob.len() - 32..], &hex(VECTORS[0].1)[..]);
        assert!(kp.openssh_public_key(Some("bad\ncomment")).is_err());
    }
}
