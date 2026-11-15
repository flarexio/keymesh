//! Ed25519 key generation and storage format (RFC 8032, via `ed25519-dalek`).
//!
//! Stored format: the 32-byte RFC 8032 private key ("seed") plus the 32-byte
//! public key, both raw bytes. This is **not** OpenSSH or PKCS#8. The only
//! standard-format adapter in M1 is OpenSSH *public key* line output
//! (`ssh-ed25519 AAAA...`). Private-key export formats are deferred.
//!
//! Display formats (M5 B): lowercase hex, and **raw Base58**: the 32 public-key
//! bytes in the Bitcoin Base58 alphabet with no version byte and no checksum.
//! That is an explicit raw encoding, not a chain address format in general.
//!
//! Signing (M5 B): pure Ed25519 (RFC 8032 §5.1, no prehash, no context) over the
//! exact message bytes the caller supplies, only through an explicit user
//! action on an unlocked vault item. The seed never leaves the core for this.
//! Verification is strict (`verify_strict`: canonical S, no small-order keys
//! or R). These keys are not used for Keymesh login or vault encryption.

use crate::error::{Error, Result};
use crate::rng::{random_array, RandomSource};
use crate::secret::SecretBytes;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const SEED_LEN: usize = 32;
pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// Largest message accepted for signing or verification (64 KiB).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Raw Base58 (Bitcoin alphabet, no version byte, no checksum).
pub fn base58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

/// Decode raw Base58 to exactly `N` bytes. Refuses other lengths and any
/// text that does not re-encode identically (so one value has one spelling).
fn from_base58<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.is_empty() || text.len() > 2 * N {
        return None;
    }
    let v = bs58::decode(text).into_vec().ok()?;
    let a: [u8; N] = v.try_into().ok()?;
    (base58(&a) == text).then_some(a)
}

fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != 2 * N {
        return None;
    }
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

/// A public key written as 64 hex characters or raw Base58 (32 bytes).
/// Surrounding whitespace is ignored; nothing else is.
pub fn parse_public_key(text: &str) -> Result<[u8; PUBLIC_LEN]> {
    let t = text.trim_matches(|c: char| c.is_ascii_whitespace());
    from_hex(t).or_else(|| from_base58(t)).ok_or_else(|| {
        Error::Ed25519("public key must be 64 hex characters or raw Base58 of 32 bytes".into())
    })
}

/// A signature written as 128 hex characters or raw Base58 (64 bytes).
pub fn parse_signature(text: &str) -> Result<[u8; SIGNATURE_LEN]> {
    let t = text.trim_matches(|c: char| c.is_ascii_whitespace());
    from_hex(t).or_else(|| from_base58(t)).ok_or_else(|| {
        Error::Ed25519("signature must be 128 hex characters or raw Base58 of 64 bytes".into())
    })
}

/// How a message is written: its UTF-8 text exactly as typed, or hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageEncoding {
    Utf8,
    Hex,
}

impl MessageEncoding {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "utf8" => Ok(Self::Utf8),
            "hex" => Ok(Self::Hex),
            _ => Err(Error::Ed25519(
                "message encoding must be utf8 or hex".into(),
            )),
        }
    }
}

/// The exact bytes a message stands for. UTF-8 text is used as is: no
/// normalisation, trimming or added newline. Hex is only `0-9a-fA-F` digits,
/// optionally separated by ASCII whitespace (ignored), and must decode to
/// whole bytes; anything else (`0x`, Unicode spaces, other characters) is
/// refused. The 64 KiB limit is enforced here, in the core, for every caller.
pub fn message_bytes(text: &str, encoding: MessageEncoding) -> Result<Vec<u8>> {
    let bytes = match encoding {
        MessageEncoding::Utf8 => text.as_bytes().to_vec(),
        MessageEncoding::Hex => {
            if text.len() > 3 * MAX_MESSAGE_BYTES + 2 {
                return Err(Error::Ed25519("message is larger than 64 KiB".into()));
            }
            let digits: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(digits.as_bytes())
                .map_err(|_| Error::Ed25519("message is not valid hex".into()))?
        }
    };
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Ed25519("message is larger than 64 KiB".into()));
    }
    Ok(bytes)
}

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

    /// Public key as raw Base58 (32 bytes, Bitcoin alphabet, no checksum).
    pub fn public_key_base58(&self) -> Result<String> {
        Ok(base58(&self.public_key_bytes()?))
    }

    /// RFC 8032 pure Ed25519 signature over exactly `msg`. The stored public
    /// key must match the seed (checked first), so a tampered record never
    /// signs under a key it does not display.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN]> {
        if msg.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Ed25519("message is larger than 64 KiB".into()));
        }
        self.validate()?;
        let sk = self.signing_key()?;
        Ok(ed25519_dalek::Signer::sign(&sk, msg).to_bytes())
    }

    fn signing_key(&self) -> Result<SigningKey> {
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
    if msg.len() > MAX_MESSAGE_BYTES {
        return Err(Error::Ed25519("message is larger than 64 KiB".into()));
    }
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

    // Base58 expectations computed independently (Python big-integer
    // implementation of the Bitcoin alphabet), not by the `bs58` crate.
    const B58: &[(&str, &str)] = &[
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "586Z7H2vpX9qNhN2T4e9Utugie3ogjbxzGaMtM3E6HR5",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "11111111111111111111111111111111",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "11111111111111111111111111111112",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG",
        ),
    ];
    const SIG1_B58: &str =
        "5awYiUvGiDFA33EJjj4TXJG44a5afJc8QjWRpGgQiu6b23jCr7yndW2fmp9ujwqJVe32J456wV3VF78Asb1obnTc";

    #[test]
    fn raw_base58_known_vectors_round_trip() {
        for (h, b) in B58 {
            assert_eq!(base58(&hex(h)), *b);
            assert_eq!(parse_public_key(b).unwrap().to_vec(), hex(h));
            assert_eq!(parse_public_key(h).unwrap().to_vec(), hex(h));
        }
        let kp = Ed25519KeyPair::from_seed_hex(VECTORS[0].0).unwrap();
        assert_eq!(kp.public_key_base58().unwrap(), B58[0].1);
        assert_eq!(base58(&hex(VECTORS[0].3)), SIG1_B58);
        assert_eq!(
            parse_signature(SIG1_B58).unwrap().to_vec(),
            hex(VECTORS[0].3)
        );
    }

    #[test]
    fn key_and_signature_text_is_strict() {
        let bad_keys = [
            "",
            "abcd",
            // 31 and 33 bytes in hex and Base58.
            &"00".repeat(31),
            &"00".repeat(33),
            "1111111111111111111111111111111",
            "111111111111111111111111111111111",
            // Not in the alphabet (0, O, I, l) and stray characters.
            "0Ven3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z",
            "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z!",
            "FVen3X669xLzsi6N2V91D iyzHzg1uAgqiT8jZ9nS96Z",
            // Checksummed or prefixed forms are not raw keys.
            "ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z",
        ];
        for k in bad_keys {
            assert!(parse_public_key(k).is_err(), "{k:?}");
        }
        assert!(parse_signature(B58[0].1).is_err()); // a 32-byte value
        assert!(parse_signature(&"ab".repeat(63)).is_err());
        assert!(parse_signature(&"ab".repeat(65)).is_err());
        // Whitespace around is fine; uppercase hex is fine.
        assert!(parse_public_key(&format!("  {}\n", B58[0].1)).is_ok());
        assert!(parse_public_key(&B58[0].0.to_uppercase()).is_ok());
    }

    #[test]
    fn sign_matches_rfc8032_and_rejects_tampered_records() {
        for (sk, _, msg, sig) in VECTORS {
            let kp = Ed25519KeyPair::from_seed_hex(sk).unwrap();
            assert_eq!(kp.sign(&hex(msg)).unwrap().to_vec(), hex(sig));
        }
        let kp = Ed25519KeyPair::from_seed_hex(VECTORS[0].0).unwrap();
        let forged = Ed25519KeyPair {
            seed: kp.seed.clone(),
            public_key_hex: VECTORS[1].1.into(),
        };
        assert!(forged.sign(b"x").is_err());
        assert!(kp.sign(&vec![0u8; MAX_MESSAGE_BYTES + 1]).is_err());
        assert!(kp.sign(&vec![0u8; MAX_MESSAGE_BYTES]).is_ok());
    }

    #[test]
    fn strict_verification_negatives() {
        let kp = Ed25519KeyPair::from_seed_hex(VECTORS[1].0).unwrap();
        let pk = kp.public_key_bytes().unwrap();
        let msg = hex(VECTORS[1].2);
        let sig = hex(VECTORS[1].3);
        verify(&pk, &msg, &sig).unwrap();
        // Non-canonical S: S + L (the group order) verifies under lax rules
        // in some libraries; strict verification must refuse it.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut s_plus_l = sig.clone();
        let mut carry = 0u16;
        for i in 0..32 {
            let v = s_plus_l[32 + i] as u16 + L[i] as u16 + carry;
            s_plus_l[32 + i] = v as u8;
            carry = v >> 8;
        }
        assert!(verify(&pk, &msg, &s_plus_l).is_err());
        // Small-order public key (the identity point) with any signature.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(verify(&identity, &msg, &sig).is_err());
        // Wrong message, flipped bits, wrong length, other key.
        assert!(verify(&pk, b"other", &sig).is_err());
        for i in [0, 31, 32, 63] {
            let mut b = sig.clone();
            b[i] ^= 0x01;
            assert!(verify(&pk, &msg, &b).is_err());
        }
        assert!(verify(&pk, &msg, &sig[..63]).is_err());
        let other = Ed25519KeyPair::from_seed_hex(VECTORS[2].0).unwrap();
        assert!(verify(&other.public_key_bytes().unwrap(), &msg, &sig).is_err());
        assert!(verify(&pk, &vec![0; MAX_MESSAGE_BYTES + 1], &sig).is_err());
    }

    #[test]
    fn message_bytes_are_exact() {
        // UTF-8: as typed, no trimming or normalisation (e + combining acute
        // stays three bytes; precomposed é is two).
        assert_eq!(
            message_bytes(" a\n", MessageEncoding::Utf8).unwrap(),
            b" a\n"
        );
        assert_eq!(
            message_bytes("e\u{301}", MessageEncoding::Utf8).unwrap(),
            vec![0x65, 0xcc, 0x81]
        );
        assert_eq!(
            message_bytes("\u{e9}", MessageEncoding::Utf8).unwrap(),
            vec![0xc3, 0xa9]
        );
        assert_eq!(
            message_bytes("AF 82\n", MessageEncoding::Hex).unwrap(),
            vec![0xaf, 0x82]
        );
        assert_eq!(
            message_bytes("", MessageEncoding::Hex).unwrap(),
            Vec::<u8>::new()
        );
        assert!(message_bytes("abc", MessageEncoding::Hex).is_err());
        assert!(message_bytes("zz", MessageEncoding::Hex).is_err());
        assert!(message_bytes("0x00", MessageEncoding::Hex).is_err());
        // Only ASCII whitespace separates hex digits; Unicode spaces do not.
        assert!(message_bytes("af\u{a0}82", MessageEncoding::Hex).is_err());
        assert!(message_bytes("af\u{3000}82", MessageEncoding::Hex).is_err());
        assert!(parse_public_key(&format!("\u{a0}{}", B58[0].1)).is_err());
        // The 64 KiB bound holds for hex too (and is checked before decoding).
        assert!(message_bytes(&"00".repeat(MAX_MESSAGE_BYTES + 1), MessageEncoding::Hex).is_err());
        assert!(message_bytes(&"00".repeat(MAX_MESSAGE_BYTES), MessageEncoding::Hex).is_ok());
        assert!(message_bytes(&"a".repeat(MAX_MESSAGE_BYTES + 1), MessageEncoding::Utf8).is_err());
        assert!(MessageEncoding::parse("base64").is_err());
    }
}
