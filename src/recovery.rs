//! Recovery code: a fresh 256-bit random secret in a human-readable form.
//!
//! ```text
//! payload = version (0x01) ‖ secret (32 bytes) ‖ check (2 bytes)
//! check   = SHA-256("keymesh recovery code" ‖ version ‖ secret)[0..2]
//! text    = RFC 4648 Base32 (A–Z, 2–7) of the 35-byte payload: 56 characters,
//!           shown as 14 groups of 4 separated by "-"
//! ```
//!
//! Parsing ignores case, spaces and hyphens and reads `0`, `1`, `8` as `O`,
//! `I`, `B` (characters Base32 never uses). An unknown version is refused,
//! and the 16-bit check catches typos before any decryption is attempted.
//! The code *is* the key material (via HKDF in its key slot): it is not a
//! signature, a wallet phrase or a password, and Keymesh never stores it.

use crate::error::{Error, Result};
use crate::rng::{random_array, RandomSource};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const VERSION: u8 = 1;
pub const SECRET_LEN: usize = 32;
const PAYLOAD_LEN: usize = 1 + SECRET_LEN + 2;
pub const TEXT_LEN: usize = 56;

pub struct RecoveryCode(Zeroizing<[u8; SECRET_LEN]>);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

fn check(secret: &[u8; SECRET_LEN]) -> [u8; 2] {
    let mut h = Sha256::new();
    h.update(b"keymesh recovery code");
    h.update([VERSION]);
    h.update(secret);
    let d = h.finalize();
    [d[0], d[1]]
}

impl RecoveryCode {
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(Self(Zeroizing::new(random_array::<SECRET_LEN>(rng)?)))
    }

    /// Wrap existing secret bytes (e.g. test vectors).
    pub fn from_secret(secret: [u8; SECRET_LEN]) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub(crate) fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// Display form: 14 groups of 4 Base32 characters.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
        payload[0] = VERSION;
        payload[1..=SECRET_LEN].copy_from_slice(&*self.0);
        payload[SECRET_LEN + 1..].copy_from_slice(&check(&self.0));
        let raw = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(&*payload));
        let mut out = Zeroizing::new(String::with_capacity(TEXT_LEN + 13));
        for (i, c) in raw.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }

    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 256 {
            return Err(Error::validation("recovery code is not valid"));
        }
        let mut clean = Zeroizing::new(String::with_capacity(TEXT_LEN));
        for c in text.chars() {
            match c {
                '-' | ' ' | '\t' | '\n' | '\r' => {}
                '0' => clean.push('O'),
                '1' => clean.push('I'),
                '8' => clean.push('B'),
                c => clean.push(c.to_ascii_uppercase()),
            }
        }
        if clean.len() != TEXT_LEN {
            return Err(Error::validation("recovery code is not valid"));
        }
        let bytes = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(clean.as_bytes())
                .map_err(|_| Error::validation("recovery code is not valid"))?,
        );
        if bytes.len() != PAYLOAD_LEN {
            return Err(Error::validation("recovery code is not valid"));
        }
        if bytes[0] != VERSION {
            return Err(Error::Format("unsupported recovery code version".into()));
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        secret.copy_from_slice(&bytes[1..=SECRET_LEN]);
        let expected = check(&secret);
        if !bool::from(expected.ct_eq(&bytes[SECRET_LEN + 1..])) {
            return Err(Error::validation("recovery code is not valid"));
        }
        Ok(Self(secret))
    }

    pub fn ct_eq(&self, other: &RecoveryCode) -> bool {
        bool::from(self.0.ct_eq(&*other.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::ScriptedRandom;
    use crate::rng::OsRandom;

    #[test]
    fn deterministic_vector() {
        let code = RecoveryCode::generate(&mut ScriptedRandom((0u8..32).collect())).unwrap();
        let text = code.to_text();
        assert_eq!(
            text.as_str(),
            "AEAA-CAQD-AQCQ-MBYI-BEFA-WDAN-BYHR-AEIS-CMKB-KFQX-DAMR-UGY4-DUPB-77OX"
        );
        assert!(RecoveryCode::parse(&text).unwrap().ct_eq(&code));
    }

    #[test]
    fn round_trip_and_lenient_spacing() {
        let code = RecoveryCode::generate(&mut OsRandom).unwrap();
        let text = code.to_text();
        assert_eq!(text.len(), TEXT_LEN + 13);
        let messy = format!("  {}\n", text.to_lowercase().replace('-', " "));
        assert!(RecoveryCode::parse(&messy).unwrap().ct_eq(&code));
        let no_sep = text.replace('-', "");
        assert!(RecoveryCode::parse(&no_sep).unwrap().ct_eq(&code));
    }

    #[test]
    fn typos_versions_and_lengths_are_rejected() {
        let code = RecoveryCode::generate(&mut OsRandom).unwrap();
        let text = code.to_text().replace('-', "");
        // Change one character inside the secret part.
        let mut chars: Vec<char> = text.chars().collect();
        chars[20] = if chars[20] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.iter().collect();
        assert!(matches!(
            RecoveryCode::parse(&typo),
            Err(Error::Validation(_))
        ));
        assert!(RecoveryCode::parse(&text[..55]).is_err());
        assert!(RecoveryCode::parse(&format!("{text}A")).is_err());
        assert!(RecoveryCode::parse("").is_err());
        assert!(RecoveryCode::parse(&"A".repeat(300)).is_err());
        assert!(RecoveryCode::parse(&"!".repeat(56)).is_err());
        // Version 2 with otherwise valid structure.
        let mut payload = vec![2u8];
        payload.extend_from_slice(code.secret());
        payload.extend_from_slice(&[0, 0]);
        let v2 = data_encoding::BASE32_NOPAD.encode(&payload);
        assert!(matches!(RecoveryCode::parse(&v2), Err(Error::Format(_))));
    }

    #[test]
    fn debug_is_redacted() {
        let code = RecoveryCode::generate(&mut OsRandom).unwrap();
        assert_eq!(format!("{code:?}"), "RecoveryCode(<redacted>)");
    }
}
