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

/// Largest length accepted through [`PasswordOptions`] (the UI range). It
/// bounds the work a single request can ask for.
pub const OPTIONS_MAX_LENGTH: usize = 128;
/// Longest custom symbol set accepted, counted before de-duplication.
pub const MAX_SYMBOL_SET_CHARS: usize = 64;

/// User-chosen password settings. Every selected class is its own class in
/// the resulting [`PasswordPolicy`], so `require_each_class` keeps its
/// meaning (one character from each selected class).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Symbols to draw from when `symbols` is set: printable ASCII
    /// punctuation only, so letters, digits, spaces or other scripts cannot
    /// slip in through this field. Duplicates are ignored. Unused (and not
    /// validated) when `symbols` is off.
    pub symbol_set: String,
    /// Drop look-alike characters ([`AMBIGUOUS`]).
    pub exclude_ambiguous: bool,
    pub require_each_class: bool,
}

impl PasswordOptions {
    /// The settings equivalent to a built-in profile.
    pub fn preset(p: PasswordProfile) -> Self {
        Self {
            length: match p {
                PasswordProfile::Default => 24,
                PasswordProfile::Strong => 32,
            },
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            symbol_set: SYMBOLS.into(),
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }
}

/// Non-secret description of a policy.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    pub length: usize,
    /// Distinct characters the password is drawn from.
    pub alphabet_size: usize,
    pub classes: usize,
    /// `length × log2(alphabet_size)`: a theoretical upper bound. Forcing one
    /// character per class makes the output slightly non-uniform, so this is
    /// not the exact or guaranteed entropy.
    pub upper_bound_bits: f64,
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

    /// Policy from user settings. Everything is validated here, before any
    /// random number is drawn: length range, at least one class, the custom
    /// symbol set, and the usual entropy floor ([`MIN_ENTROPY_BITS`]), which is
    /// not relaxed for custom settings. Nothing is added or lengthened to make
    /// a policy pass.
    pub fn from_options(o: &PasswordOptions) -> Result<Self> {
        if !(MIN_LENGTH..=OPTIONS_MAX_LENGTH).contains(&o.length) {
            return Err(Error::Policy(format!(
                "length must be {MIN_LENGTH}..={OPTIONS_MAX_LENGTH}"
            )));
        }
        if !(o.lowercase || o.uppercase || o.digits || o.symbols) {
            return Err(Error::Policy("select at least one character class".into()));
        }
        if o.symbols {
            if o.symbol_set.chars().count() > MAX_SYMBOL_SET_CHARS {
                return Err(Error::Policy(format!(
                    "symbol set is too long (at most {MAX_SYMBOL_SET_CHARS} characters)"
                )));
            }
            if o.symbol_set.is_empty() {
                return Err(Error::Policy("symbol set is empty".into()));
            }
            if !o.symbol_set.chars().all(|c| c.is_ascii_punctuation()) {
                return Err(Error::Policy(
                    "symbol set may only contain ASCII punctuation".into(),
                ));
            }
        }
        let mut classes: Vec<String> = [
            (o.lowercase, LOWER),
            (o.uppercase, UPPER),
            (o.digits, DIGITS),
            (o.symbols, o.symbol_set.as_str()),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| set.to_owned())
        .collect();
        if o.exclude_ambiguous {
            for c in &mut classes {
                c.retain(|ch| !AMBIGUOUS.contains(ch));
            }
        }
        let refs: Vec<&str> = classes.iter().map(String::as_str).collect();
        Self::classes(o.length, &refs, o.require_each_class)
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

    pub fn summary(&self) -> PolicySummary {
        PolicySummary {
            length: self.length,
            alphabet_size: self.alphabet_len(),
            classes: self.classes.len(),
            upper_bound_bits: self.entropy_bits(),
        }
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

    fn custom(length: usize) -> PasswordOptions {
        PasswordOptions {
            length,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            symbol_set: SYMBOLS.into(),
            exclude_ambiguous: false,
            require_each_class: true,
        }
    }

    fn policy_err(o: &PasswordOptions) -> String {
        PasswordPolicy::from_options(o).unwrap_err().to_string()
    }

    #[test]
    fn presets_equal_the_built_in_profiles() {
        for p in [PasswordProfile::Default, PasswordProfile::Strong] {
            let o = PasswordOptions::preset(p);
            assert_eq!(
                PasswordPolicy::from_options(&o).unwrap(),
                PasswordPolicy::profile(p)
            );
        }
        assert_eq!(PasswordOptions::preset(PasswordProfile::Default).length, 24);
        assert_eq!(PasswordOptions::preset(PasswordProfile::Strong).length, 32);
    }

    #[test]
    fn options_respect_length_classes_custom_symbols_and_exclusions() {
        let o = PasswordOptions {
            uppercase: true,
            digits: true,
            symbols: true,
            symbol_set: "#@!".into(),
            exclude_ambiguous: true,
            ..custom(40)
        };
        let pol = PasswordPolicy::from_options(&o).unwrap();
        // 26 - {I, O} + 10 - {0, 1} + 3 symbols.
        assert_eq!(pol.alphabet_len(), 24 + 8 + 3);
        for _ in 0..300 {
            let pw = generate_password(&pol, &mut OsRandom).unwrap();
            let s = pw.expose();
            assert_eq!(s.chars().count(), 40);
            assert!(s
                .chars()
                .all(|c| UPPER.contains(c) || DIGITS.contains(c) || "#@!".contains(c)));
            assert!(!s
                .chars()
                .any(|c| AMBIGUOUS.contains(c) || LOWER.contains(c)));
            assert!(s.chars().any(|c| UPPER.contains(c)));
            assert!(s.chars().any(|c| DIGITS.contains(c)));
            assert!(s.chars().any(|c| "#@!".contains(c)));
        }
    }

    #[test]
    fn single_class_policies_need_enough_length_for_the_floor() {
        let digits = |n| PasswordOptions {
            digits: true,
            ..custom(n)
        };
        let lower = |n| PasswordOptions {
            lowercase: true,
            ..custom(n)
        };
        assert!(policy_err(&digits(19)).contains("entropy")); // 63.1 bits
        assert!(policy_err(&lower(13)).contains("entropy")); // 61.1 bits
        for (o, set, n) in [(digits(20), DIGITS, 20), (lower(14), LOWER, 14)] {
            let pol = PasswordPolicy::from_options(&o).unwrap();
            let pw = generate_password(&pol, &mut OsRandom).unwrap();
            assert_eq!(pw.expose().chars().count(), n);
            assert!(pw.expose().chars().all(|c| set.contains(c)));
        }
        // The floor is not lowered for short all-class passwords either.
        let all = PasswordOptions::preset(PasswordProfile::Default);
        assert!(policy_err(&PasswordOptions {
            length: 8,
            ..all.clone()
        })
        .contains("entropy"));
        assert!(PasswordPolicy::from_options(&PasswordOptions { length: 10, ..all }).is_ok());
    }

    #[test]
    fn invalid_options_are_rejected() {
        let all = PasswordOptions::preset(PasswordProfile::Default);
        assert!(policy_err(&PasswordOptions {
            length: 7,
            ..all.clone()
        })
        .contains("8..=128"));
        assert!(policy_err(&PasswordOptions {
            length: 129,
            ..all.clone()
        })
        .contains("8..=128"));
        assert!(policy_err(&custom(24)).contains("at least one character class"));
        let sym = |set: &str| PasswordOptions {
            symbols: true,
            lowercase: true,
            symbol_set: set.into(),
            ..custom(24)
        };
        assert!(policy_err(&sym("")).contains("symbol set is empty"));
        for bad in ["ab", "!1", "! ", "!\u{7}", "!\t", "!€", "!＠"] {
            assert!(
                policy_err(&sym(bad)).contains("ASCII punctuation"),
                "{bad:?}"
            );
        }
        assert!(policy_err(&sym(&"!".repeat(MAX_SYMBOL_SET_CHARS + 1))).contains("too long"));
        assert!(PasswordPolicy::from_options(&sym(&"!".repeat(MAX_SYMBOL_SET_CHARS))).is_ok());
        // With symbols off the symbol set is not part of the policy at all.
        let off = PasswordOptions {
            lowercase: true,
            symbol_set: "abc 1".into(),
            ..custom(24)
        };
        let pol = PasswordPolicy::from_options(&off).unwrap();
        assert_eq!(pol.alphabet_len(), 26);
    }

    #[test]
    fn duplicate_symbols_add_no_weight() {
        let sym = |set: &str| PasswordOptions {
            symbols: true,
            symbol_set: set.into(),
            ..custom(128)
        };
        let dup = PasswordPolicy::from_options(&sym("!!!!!!@@")).unwrap();
        let uniq = PasswordPolicy::from_options(&sym("!@")).unwrap();
        assert_eq!(dup, uniq);
        assert_eq!(dup.summary(), uniq.summary());
        assert_eq!(dup.summary().alphabet_size, 2);
        let mut bang = 0u32;
        for _ in 0..50 {
            let pw = generate_password(&dup, &mut OsRandom).unwrap();
            bang += pw.expose().chars().filter(|&c| c == '!').count() as u32;
        }
        // 6400 draws, p = 1/2: about 3200 ± 40 (1 sd).
        assert!((2950..3450).contains(&bang), "{bang}");
    }

    #[test]
    fn summary_is_an_upper_bound_estimate() {
        let pol = PasswordPolicy::from_options(&PasswordOptions::preset(PasswordProfile::Default))
            .unwrap();
        let s = pol.summary();
        assert_eq!((s.length, s.alphabet_size, s.classes), (24, 90, 4));
        assert!((s.upper_bound_bits - 24.0 * 90f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn invalid_options_fail_before_any_rng_use_and_rng_failure_stays_closed() {
        for bad in [
            custom(24),
            PasswordOptions {
                lowercase: true,
                ..custom(7)
            },
        ] {
            let r = PasswordPolicy::from_options(&bad)
                .and_then(|p| generate_password(&p, &mut FailingRandom));
            assert!(matches!(r, Err(Error::Policy(_))));
        }
        let ok = PasswordPolicy::from_options(&PasswordOptions::preset(PasswordProfile::Strong))
            .unwrap();
        assert!(matches!(
            generate_password(&ok, &mut FailingRandom),
            Err(Error::Rng)
        ));
    }

    #[test]
    fn passphrase_is_explicitly_pending() {
        assert!(generate_passphrase().is_err());
    }
}
