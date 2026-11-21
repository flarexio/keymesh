//! Passphrases from the EFF Long Wordlist (M5 B).
//!
//! * The list is vendored byte-exact (`src/wordlists/`; see its README for
//!   provenance and licence). Its SHA-256 is pinned below and checked at run
//!   time before the first passphrase (generation fails closed on a
//!   mismatch) and by the tests. This is not a compile-time guarantee.
//! * Every word is chosen independently and uniformly with
//!   [`crate::rng::uniform_index`] (rejection sampling over the OS CSPRNG, no
//!   modulo bias). So the entropy is exactly `words × log2(7776)` ≈ 12.925
//!   bits per word, for an attacker who knows the list, the word count and
//!   the separator.
//! * Words are lowercase letters, a few with a hyphen (`drop-down`), so the
//!   separators are a space or a period only. No word is a prefix of another,
//!   and every passphrase splits back into its words in one way only.

use crate::error::{Error, Result};
use crate::rng::{uniform_index, RandomSource};
use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroizing;

const RAW: &str = include_str!("wordlists/eff_large_wordlist.txt");
/// SHA-256 of the vendored file (lowercase hex).
pub const WORDLIST_SHA256: &str =
    "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";
pub const WORDLIST_NAME: &str = "EFF Long Wordlist (7776 words, CC BY 3.0 US)";
pub const WORD_COUNT: usize = 7776;

pub const MIN_WORDS: usize = 4;
pub const MAX_WORDS: usize = 12;
/// Generator default (≈ 77.5 bits).
pub const DEFAULT_WORDS: usize = 6;
/// Suggested master password (≈ 90.5 bits).
pub const MASTER_WORDS: usize = 7;
/// Fewer words than this are flagged as too weak for a master password.
pub const MASTER_MIN_WORDS: usize = 6;

/// The embedded list matches the pinned digest (computed once).
fn list_intact() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        data_encoding::HEXLOWER.encode(&Sha256::digest(RAW.as_bytes())) == WORDLIST_SHA256
    })
}

fn words() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| {
        RAW.lines()
            .filter_map(|l| l.split_once('\t').map(|(_, w)| w))
            .collect()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Separator {
    Space,
    Period,
}

impl Separator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Space => " ",
            Self::Period => ".",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: Separator,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: DEFAULT_WORDS,
            separator: Separator::Space,
        }
    }
}

/// What a passphrase setting gives, for display next to the generator.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct PassphraseSummary {
    pub words: usize,
    pub list_size: usize,
    pub entropy_bits: f64,
    /// Enough words for a master password ([`MASTER_MIN_WORDS`]).
    pub master_ok: bool,
}

pub fn entropy_bits(words: usize) -> f64 {
    words as f64 * (WORD_COUNT as f64).log2()
}

impl PassphraseOptions {
    pub fn validate(&self) -> Result<()> {
        if !(MIN_WORDS..=MAX_WORDS).contains(&self.words) {
            return Err(Error::Policy(format!(
                "a passphrase has {MIN_WORDS} to {MAX_WORDS} words"
            )));
        }
        Ok(())
    }

    pub fn summary(&self) -> Result<PassphraseSummary> {
        self.validate()?;
        Ok(PassphraseSummary {
            words: self.words,
            list_size: WORD_COUNT,
            entropy_bits: entropy_bits(self.words),
            master_ok: self.words >= MASTER_MIN_WORDS,
        })
    }
}

pub fn generate_passphrase(
    options: &PassphraseOptions,
    rng: &mut dyn RandomSource,
) -> Result<SecretString> {
    options.validate()?;
    let list = words();
    if !list_intact() || list.len() != WORD_COUNT {
        return Err(Error::Policy("bundled wordlist is damaged".into()));
    }
    let mut out = Zeroizing::new(String::with_capacity(options.words * 10));
    for i in 0..options.words {
        if i > 0 {
            out.push_str(options.separator.as_str());
        }
        out.push_str(list[uniform_index(rng, WORD_COUNT as u32)? as usize]);
    }
    Ok(SecretString::new(std::mem::take(&mut *out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::testing::FailingRandom;
    use crate::rng::OsRandom;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn vendored_list_is_the_pinned_eff_list() {
        assert_eq!(
            data_encoding::HEXLOWER.encode(&Sha256::digest(RAW.as_bytes())),
            WORDLIST_SHA256
        );
        assert!(list_intact());
        let lines: Vec<&str> = RAW.lines().collect();
        assert_eq!(lines.len(), WORD_COUNT);
        let mut expected = Vec::new();
        for n in 0..WORD_COUNT {
            let mut d = String::new();
            let mut x = n;
            for _ in 0..5 {
                d.insert(0, char::from(b'1' + (x % 6) as u8));
                x /= 6;
            }
            expected.push(d);
        }
        let w = words();
        for (i, l) in lines.iter().enumerate() {
            let (dice, word) = l.split_once('\t').unwrap();
            assert_eq!(dice, expected[i]);
            assert_eq!(w[i], word);
            assert!((3..=9).contains(&word.len()));
            assert!(
                word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{word}"
            );
            assert!(!word.starts_with('-') && !word.ends_with('-'));
            // Neither separator ever appears inside a word.
            assert!(!word.contains(' ') && !word.contains('.'));
        }
        assert_eq!(w.iter().collect::<HashSet<_>>().len(), WORD_COUNT);
        let set: HashSet<&str> = w.iter().copied().collect();
        for word in w {
            for k in 3..word.len() {
                assert!(!set.contains(&word[..k]), "{word} has a word as prefix");
            }
        }
        assert_eq!((w[0], w[WORD_COUNT - 1]), ("abacus", "zoom"));
    }

    #[test]
    fn entropy_and_bounds() {
        assert!((entropy_bits(1) - 12.925).abs() < 0.001);
        assert!((entropy_bits(DEFAULT_WORDS) - 77.55).abs() < 0.01);
        assert!((entropy_bits(MASTER_WORDS) - 90.47).abs() < 0.01);
        for n in [0, 3, 13, 1000] {
            let o = PassphraseOptions {
                words: n,
                separator: Separator::Space,
            };
            assert!(generate_passphrase(&o, &mut OsRandom).is_err());
            assert!(o.summary().is_err());
        }
        let five = PassphraseOptions {
            words: 5,
            separator: Separator::Period,
        };
        assert!(!five.summary().unwrap().master_ok);
        assert!(PassphraseOptions::default().summary().unwrap().master_ok);
        assert!(matches!(
            generate_passphrase(&PassphraseOptions::default(), &mut FailingRandom),
            Err(Error::Rng)
        ));
    }

    #[test]
    fn output_splits_into_list_words() {
        let set: HashSet<&str> = words().iter().copied().collect();
        for sep in [Separator::Space, Separator::Period] {
            for n in [MIN_WORDS, MASTER_WORDS, MAX_WORDS] {
                let p = generate_passphrase(
                    &PassphraseOptions {
                        words: n,
                        separator: sep,
                    },
                    &mut OsRandom,
                )
                .unwrap();
                let parts: Vec<&str> = p.expose().split(sep.as_str()).collect();
                assert_eq!(parts.len(), n);
                assert!(parts.iter().all(|w| set.contains(w)));
            }
        }
        // A master-password suggestion passes the new-password rules.
        let p = generate_passphrase(
            &PassphraseOptions {
                words: MASTER_WORDS,
                separator: Separator::Space,
            },
            &mut OsRandom,
        )
        .unwrap();
        crate::kdf::check_new_password(p.expose()).unwrap();
    }

    /// Scripted 32-bit draws (little-endian), to check rejection exactly.
    struct Script(Vec<u32>);
    impl RandomSource for Script {
        fn fill(&mut self, buf: &mut [u8]) -> crate::Result<()> {
            assert_eq!(buf.len(), 4);
            buf.copy_from_slice(&self.0.remove(0).to_le_bytes());
            Ok(())
        }
    }

    #[test]
    fn rejection_sampling_has_no_modulo_bias() {
        // Values at or above the largest multiple of 7776 are discarded,
        // never folded onto low indices.
        let zone = u32::MAX - (u32::MAX % WORD_COUNT as u32);
        let mut r = Script(vec![zone, u32::MAX, 0, zone - 1, 7776 + 1, 0, 0, 0]);
        let p = generate_passphrase(
            &PassphraseOptions {
                words: 4,
                separator: Separator::Space,
            },
            &mut r,
        )
        .unwrap();
        let w = words();
        assert_eq!(
            p.expose(),
            format!(
                "{} {} {} {}",
                w[0],
                w[(zone - 1) as usize % WORD_COUNT],
                w[1],
                w[0]
            )
        );
    }

    /// Deterministic test-only stream (SHA-256 in counter mode), so the
    /// statistical check is reproducible. Production never uses it.
    struct CounterRng(u64);
    impl RandomSource for CounterRng {
        fn fill(&mut self, buf: &mut [u8]) -> crate::Result<()> {
            for chunk in buf.chunks_mut(32) {
                let d = Sha256::digest(self.0.to_le_bytes());
                self.0 += 1;
                chunk.copy_from_slice(&d[..chunk.len()]);
            }
            Ok(())
        }
    }

    #[test]
    fn word_frequencies_are_uniform_chi_square() {
        let index: HashMap<&str, usize> =
            words().iter().enumerate().map(|(i, w)| (*w, i)).collect();
        let mut counts = vec![0u64; WORD_COUNT];
        let mut rng = CounterRng(1);
        let opts = PassphraseOptions {
            words: MAX_WORDS,
            separator: Separator::Space,
        };
        let draws = 40_000; // 480 000 words, ≈ 61.7 expected per word
        for _ in 0..draws {
            let p = generate_passphrase(&opts, &mut rng).unwrap();
            for w in p.expose().split(' ') {
                counts[index[w]] += 1;
            }
        }
        let n: u64 = counts.iter().sum();
        let e = n as f64 / WORD_COUNT as f64;
        let chi: f64 = counts.iter().map(|&c| (c as f64 - e).powi(2) / e).sum();
        // df = 7775: mean 7775, sd ≈ 124.7. Accept within ±6 sd.
        let (mean, sd) = (7775.0, (2.0f64 * 7775.0).sqrt());
        assert!((chi - mean).abs() < 6.0 * sd, "chi-square {chi}");
        assert!(counts.iter().all(|&c| c > 0));
    }
}
