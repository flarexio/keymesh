//! CSPRNG-backed password and random-secret generation.
//!
//! * Characters are drawn with unbiased rejection sampling
//!   ([`crate::rng::uniform_index`]); no modulo bias, no retry-until-valid
//!   loops. When every character class is required, one character is drawn
//!   from each required class, the remainder from the full alphabet, and the
//!   result is shuffled with an unbiased Fisher–Yates shuffle.
//! * Policies that cannot be satisfied or are too weak are rejected up front.
//! * Passphrases (wordlist-based) are **pending**: no reviewed, versioned
//!   wordlist is vendored in M1, and we do not fabricate one.
//!
//! Random secrets produced here are local random values. They are *not*
//! provider-issued API credentials.

use crate::error::{Error, Result};
use crate::rng::{uniform_index, RandomSource};
use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
pub const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
pub const AMBIGUOUS: &str = "Il1O0o";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 1024;
/// Minimum estimated entropy (length × log2(alphabet)) a policy must reach.
pub const MIN_ENTROPY_BITS: f64 = 64.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordProfile {
    /// 24 characters, all four classes.
    Default,
    /// 32 characters, all four classes.
    Strong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub length: usize,
    /// Character classes; each is a set of allowed characters.
    classes: Vec<Vec<char>>,
    pub require_each_class: bool,
}

impl PasswordPolicy {
    pub fn profile(p: PasswordProfile) -> Self {
        let length = match p {
            PasswordProfile::Default => 24,
            PasswordProfile::Strong => 32,
        };
        Self::classes(length, &[LOWER, UPPER, DIGITS, SYMBOLS], true)
            .expect("built-in profiles are valid")
    }

    /// Policy from explicit character classes.
    pub fn classes(length: usize, classes: &[&str], require_each_class: bool) -> Result<Self> {
        let classes = classes.iter().map(|c| c.chars().collect()).collect();
        let p = Self {
            length,
            classes,
            require_each_class,
        };
        p.normalized()
    }

    /// Policy from a single caller-supplied allowlist of characters.
    pub fn allowlist(length: usize, alphabet: &str) -> Result<Self> {
        Self::classes(length, &[alphabet], false)
    }

    /// Remove ambiguous look-alike characters from every class.
    pub fn exclude_ambiguous(mut self) -> Result<Self> {
        for c in &mut self.classes {
            c.retain(|ch| !AMBIGUOUS.contains(*ch));
        }
        self.normalized()
    }

    fn normalized(mut self) -> Result<Self> {
        let mut seen = BTreeSet::new();
        for class in &mut self.classes {
            let mut uniq = Vec::new();
            for ch in class.iter().copied() {
                if ch.is_control() || ch.is_whitespace() {
                    return Err(Error::Policy(
                        "alphabet must not contain control or whitespace characters".into(),
                    ));
                }
                // A character appearing in two classes would be over-weighted.
                if seen.insert(ch) {
                    uniq.push(ch);
                }
            }
            *class = uniq;
        }
        if self.classes.iter().any(|c| c.is_empty()) {
            return Err(Error::Policy("character class is empty".into()));
        }
        if self.classes.is_empty() {
            return Err(Error::Policy("no character classes".into()));
        }
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(Error::Policy(format!(
                "length must be {MIN_LENGTH}..={MAX_LENGTH}"
            )));
        }
        if self.require_each_class && self.length < self.classes.len() {
            return Err(Error::Policy(
                "length is shorter than the number of required classes".into(),
            ));
        }
        let n = self.alphabet_len();
        if n < 2 {
            return Err(Error::Policy("alphabet needs at least 2 characters".into()));
        }
        if self.entropy_bits() < MIN_ENTROPY_BITS {
            return Err(Error::Policy(format!(
                "policy entropy below {MIN_ENTROPY_BITS} bits"
            )));
        }
        Ok(self)
    }

    pub fn alphabet_len(&self) -> usize {
        self.classes.iter().map(|c| c.len()).sum()
    }

    /// Upper-bound estimate assuming uniform selection from the alphabet.
    pub fn entropy_bits(&self) -> f64 {
        self.length as f64 * (self.alphabet_len() as f64).log2()
    }
}

fn pick(rng: &mut dyn RandomSource, set: &[char]) -> Result<char> {
    Ok(set[uniform_index(rng, set.len() as u32)? as usize])
}

pub fn generate_password(
    policy: &PasswordPolicy,
    rng: &mut dyn RandomSource,
) -> Result<SecretString> {
    let all: Vec<char> = policy.classes.iter().flatten().copied().collect();
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(policy.length));
    if policy.require_each_class {
        for class in &policy.classes {
            chars.push(pick(rng, class)?);
        }
    }
    while chars.len() < policy.length {
        chars.push(pick(rng, &all)?);
    }
    // Fisher–Yates with unbiased indices.
    for i in (1..chars.len()).rev() {
        let j = uniform_index(rng, (i + 1) as u32)? as usize;
        chars.swap(i, j);
    }
    Ok(SecretString::new(chars.iter().collect::<String>()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretEncoding {
    Hex,
    Base64Url,
    Base32,
}

impl SecretEncoding {
    pub fn encode(self, bytes: &[u8]) -> String {
        match self {
            Self::Hex => data_encoding::HEXLOWER.encode(bytes),
            Self::Base64Url => data_encoding::BASE64URL_NOPAD.encode(bytes),
            Self::Base32 => data_encoding::BASE32_NOPAD.encode(bytes),
        }
    }
    pub fn decode(self, s: &str) -> Result<Zeroizing<Vec<u8>>> {
        let r = match self {
            Self::Hex => data_encoding::HEXLOWER_PERMISSIVE.decode(s.as_bytes()),
            Self::Base64Url => data_encoding::BASE64URL_NOPAD.decode(s.as_bytes()),
            Self::Base32 => data_encoding::BASE32_NOPAD.decode(s.as_bytes()),
        };
        r.map(Zeroizing::new)
            .map_err(|_| Error::validation("secret does not match declared encoding"))
    }
}

pub const DEFAULT_SECRET_BYTES: usize = 32;

/// Random secret of `n_bytes` (default 32 = 256 bits) in an explicit encoding.
pub fn generate_secret(
    n_bytes: usize,
    encoding: SecretEncoding,
    rng: &mut dyn RandomSource,
) -> Result<SecretString> {
    if !(16..=1024).contains(&n_bytes) {
        return Err(Error::Policy("secret size must be 16..=1024 bytes".into()));
    }
    let mut buf = Zeroizing::new(vec![0u8; n_bytes]);
    rng.fill(&mut buf)?;
    Ok(SecretString::new(encoding.encode(&buf)))
}

/// Passphrase generation is intentionally not implemented in M1.
pub fn generate_passphrase() -> Result<SecretString> {
    Err(Error::Policy(
        "passphrase generation pending: no reviewed, versioned wordlist is bundled".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::FailingRandom;
    use crate::rng::OsRandom;

    #[test]
    fn profiles_have_expected_length_and_classes() {
        for (p, len) in [
            (PasswordProfile::Default, 24),
            (PasswordProfile::Strong, 32),
        ] {
            let pol = PasswordPolicy::profile(p);
            for _ in 0..200 {
                let pw = generate_password(&pol, &mut OsRandom).unwrap();
                let s = pw.expose();
                assert_eq!(s.chars().count(), len);
                assert!(s.chars().any(|c| LOWER.contains(c)));
                assert!(s.chars().any(|c| UPPER.contains(c)));
                assert!(s.chars().any(|c| DIGITS.contains(c)));
                assert!(s.chars().any(|c| SYMBOLS.contains(c)));
            }
        }
    }

    #[test]
    fn allowlist_is_respected_and_deduplicated() {
        let pol = PasswordPolicy::allowlist(40, "abcabcXYZ789").unwrap();
        assert_eq!(pol.alphabet_len(), 9);
        let pw = generate_password(&pol, &mut OsRandom).unwrap();
        assert!(pw.expose().chars().all(|c| "abcXYZ789".contains(c)));
    }

    #[test]
    fn invalid_policies_error_instead_of_looping() {
        assert!(PasswordPolicy::allowlist(24, "").is_err());
        assert!(PasswordPolicy::allowlist(24, "a").is_err());
        assert!(PasswordPolicy::allowlist(24, "ab c").is_err());
        assert!(PasswordPolicy::allowlist(24, "ab\u{7}").is_err());
        assert!(PasswordPolicy::allowlist(4, LOWER).is_err());
        assert!(PasswordPolicy::allowlist(10, "01").is_err()); // 10 bits
        assert!(PasswordPolicy::allowlist(2000, LOWER).is_err());
        assert!(PasswordPolicy::classes(24, &[LOWER, ""], true).is_err());
        assert!(PasswordPolicy::classes(24, &["0", "0"], true).is_err()); // dup -> empty class
        assert!(PasswordPolicy::classes(24, &["01"], true)
            .unwrap_err()
            .to_string()
            .contains("entropy"));
        assert!(PasswordPolicy::allowlist(30, "Il1O0oab")
            .unwrap()
            .exclude_ambiguous()
            .is_err());
    }

    #[test]
    fn character_distribution_is_roughly_uniform() {
        let pol = PasswordPolicy::allowlist(1000, "abcdefgh").unwrap();
        let pw = generate_password(&pol, &mut OsRandom).unwrap();
        let mut counts = std::collections::HashMap::new();
        for _ in 0..20 {
            let pw2 = generate_password(&pol, &mut OsRandom).unwrap();
            for c in pw2.expose().chars() {
                *counts.entry(c).or_insert(0u32) += 1;
            }
        }
        assert_eq!(pw.expose().len(), 1000);
        for c in "abcdefgh".chars() {
            let n = counts[&c];
            assert!((2200..2800).contains(&n), "{c}: {n}");
        }
    }

    #[test]
    fn secrets_have_explicit_encodings() {
        let hex = generate_secret(32, SecretEncoding::Hex, &mut OsRandom).unwrap();
        assert_eq!(hex.len(), 64);
        assert_eq!(SecretEncoding::Hex.decode(hex.expose()).unwrap().len(), 32);
        let b64 = generate_secret(32, SecretEncoding::Base64Url, &mut OsRandom).unwrap();
        assert_eq!(b64.len(), 43);
        let b32 = generate_secret(32, SecretEncoding::Base32, &mut OsRandom).unwrap();
        assert_eq!(
            SecretEncoding::Base32.decode(b32.expose()).unwrap().len(),
            32
        );
        assert_ne!(
            generate_secret(32, SecretEncoding::Hex, &mut OsRandom).unwrap(),
            hex
        );
        assert!(generate_secret(4, SecretEncoding::Hex, &mut OsRandom).is_err());
    }

    #[test]
    fn rng_failure_propagates() {
        let pol = PasswordPolicy::profile(PasswordProfile::Default);
        assert!(matches!(
            generate_password(&pol, &mut FailingRandom),
            Err(Error::Rng)
        ));
        assert!(matches!(
            generate_secret(32, SecretEncoding::Hex, &mut FailingRandom),
            Err(Error::Rng)
        ));
    }

    #[test]
    fn passphrase_is_explicitly_pending() {
        assert!(generate_passphrase().is_err());
    }
}
