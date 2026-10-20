//! Randomness port.
//!
//! All entropy in Keymesh flows through [`RandomSource`]. The production
//! implementation is [`OsRandom`] (the operating system CSPRNG via
//! `getrandom`). There is deliberately no fallback: if the OS RNG fails the
//! caller receives [`Error::Rng`] instead of weaker randomness.

use crate::error::{Error, Result};

pub trait RandomSource {
    /// Fill `buf` entirely with cryptographically secure random bytes or fail.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// Operating system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::getrandom(buf).map_err(|_| Error::Rng)
    }
}

/// Returns a uniformly distributed integer in `0..bound` using rejection
/// sampling (no modulo bias). `bound` must be non-zero.
pub fn uniform_index(rng: &mut dyn RandomSource, bound: u32) -> Result<u32> {
    if bound == 0 {
        return Err(Error::Policy("uniform range must be non-empty".into()));
    }
    // Largest multiple of `bound` that fits in u32 range; values at or above
    // it are rejected. Rejection probability is < 1/2, so the expected number
    // of draws is < 2.
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < zone {
            return Ok(v % bound);
        }
    }
}

pub fn random_array<const N: usize>(rng: &mut dyn RandomSource) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// RNG that always fails, to prove errors propagate.
    pub struct FailingRandom;
    impl RandomSource for FailingRandom {
        fn fill(&mut self, _buf: &mut [u8]) -> Result<()> {
            Err(Error::Rng)
        }
    }

    /// Replays a fixed byte script; fails when exhausted.
    pub struct ScriptedRandom(pub Vec<u8>);
    impl RandomSource for ScriptedRandom {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            if self.0.len() < buf.len() {
                return Err(Error::Rng);
            }
            let rest = self.0.split_off(buf.len());
            buf.copy_from_slice(&self.0);
            self.0 = rest;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn rejects_values_in_bias_zone() {
        // bound 3: zone = u32::MAX - (u32::MAX % 3) = u32::MAX (since MAX % 3 == 0)
        // use bound 10: MAX % 10 == 5 -> zone = MAX - 5. Feed MAX first (rejected), then 13.
        let mut script = u32::MAX.to_le_bytes().to_vec();
        script.extend_from_slice(&13u32.to_le_bytes());
        let mut rng = ScriptedRandom(script);
        assert_eq!(uniform_index(&mut rng, 10).unwrap(), 3);
    }

    #[test]
    fn zero_bound_is_error() {
        assert!(uniform_index(&mut OsRandom, 0).is_err());
    }

    #[test]
    fn rng_failure_propagates() {
        assert!(matches!(
            uniform_index(&mut FailingRandom, 10),
            Err(Error::Rng)
        ));
    }

    #[test]
    fn roughly_uniform() {
        let mut counts = [0u32; 7];
        for _ in 0..70_000 {
            counts[uniform_index(&mut OsRandom, 7).unwrap() as usize] += 1;
        }
        for c in counts {
            assert!((9_000..11_000).contains(&c), "count {c}");
        }
    }
}
