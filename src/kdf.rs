//! Password stretching and key derivation for envelope v2 key slots.
//!
//! * Password → Argon2id (RFC 9106, version 0x13), RustCrypto `argon2`
//!   0.5.3, 32-byte output, 16-byte random salt. The output is never used
//!   directly: [`slot_kek`] expands it with HKDF-SHA256 (RFC 5869) bound to
//!   the vault id, slot kind and slot id.
//! * Parameters read from a file are validated against [`KdfParams::check`]
//!   **before** any memory is allocated, so a hostile file cannot demand more
//!   than [`M_KIB_MAX`] KiB or more than [`COST_MAX`] KiB-passes of work.
//! * New passwords follow NIST SP 800-63B-4 §3.1.1.2: NFC normalization, at
//!   least [`MIN_PASSWORD_CHARS`] code points, no composition rules, a
//!   whole-password blocklist, paste allowed (a UI concern).
//!
//! See `docs/adr/0002-envelope-v2.md` for the parameter measurements.

use crate::error::{Error, Result};
use crate::rng::{random_array, RandomSource};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const OUT_LEN: usize = 32;
/// Argon2 version 0x13 (RFC 9106 §3.1).
pub const ARGON2_VERSION: u32 = 0x13;

/// Lower bounds accepted when reading a file. A slot below them is refused,
/// so a weaker slot can never be opened (or written) silently.
pub const M_KIB_MIN: u32 = 19 * 1024;
pub const T_MIN: u32 = 2;
/// Upper bounds accepted when reading a file (memory and total work), so a
/// hostile file is rejected before allocation.
pub const M_KIB_MAX: u32 = 128 * 1024;
pub const T_MAX: u32 = 8;
pub const P_MAX: u32 = 4;
/// m × t limit in KiB-passes (4 × the default's work).
pub const COST_MAX: u64 = 4 * 64 * 1024 * 3;

pub const MIN_PASSWORD_CHARS: usize = 15;
/// Longest accepted password, in UTF-8 bytes after normalization.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Stored default for new password slots: RFC 9106's second recommended
    /// option (64 MiB, t=3) with p=1, because both the native core and the
    /// browser WASM build run Argon2 single-threaded. Chosen from the
    /// measurements in ADR 0002.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };

    /// Bounds check without allocating; every read and write path calls it.
    pub fn check(&self) -> Result<()> {
        let ok = (M_KIB_MIN..=M_KIB_MAX).contains(&self.m_kib)
            && (T_MIN..=T_MAX).contains(&self.t)
            && (1..=P_MAX).contains(&self.p)
            // Argon2 needs at least 8 KiB per lane.
            && self.m_kib >= 8 * self.p
            && u64::from(self.m_kib) * u64::from(self.t) <= COST_MAX;
        if ok {
            Ok(())
        } else {
            Err(Error::Format(
                "key derivation parameters out of bounds".into(),
            ))
        }
    }
}

/// NFC-normalized password bytes, bounded. Used for both new and existing
/// passwords so the same typed text always derives the same key.
pub fn normalize_password(password: &str) -> Result<Zeroizing<String>> {
    if password.len() > MAX_PASSWORD_BYTES * 4 {
        return Err(Error::validation("password is too long"));
    }
    let n = Zeroizing::new(password.nfc().collect::<String>());
    if n.is_empty() {
        return Err(Error::validation("password is empty"));
    }
    if n.len() > MAX_PASSWORD_BYTES {
        return Err(Error::validation("password is too long"));
    }
    Ok(n)
}

/// Small, non-exhaustive whole-password blocklist (lower-cased, NFC).
/// Real breach corpora are not bundled; length does most of the work.
const BLOCKLIST: &[&str] = &[
    "keymeshkeymesh",
    "keymeshpassword",
    "keymesh password",
    "mykeymeshpassword",
    "passwordpassword",
    "password1234567",
    "password12345678",
    "password123456789",
    "123456789012345",
    "1234567890123456",
    "qwertyuiopasdfgh",
    "qwertyuiopasdfghjkl",
    "1q2w3e4r5t6y7u8i",
    "iloveyouiloveyou",
    "correcthorsebatterystaple",
    "correct horse battery staple",
];

/// Checks a NEW master password (NIST SP 800-63B-4 §3.1.1.2).
pub fn check_new_password(password: &str) -> Result<()> {
    let n = normalize_password(password)?;
    if n.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::validation("password is too short"));
    }
    let lower = Zeroizing::new(n.to_lowercase());
    let mut chars = lower.chars();
    let first = chars.next();
    if chars.all(|c| Some(c) == first) || BLOCKLIST.contains(&lower.as_str()) {
        return Err(Error::validation("password is too common"));
    }
    Ok(())
}

/// Argon2id(normalized password, salt, params) → 32 bytes.
pub fn argon2id(
    password: &str,
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; OUT_LEN]>> {
    params.check()?;
    if salt.len() != SALT_LEN {
        return Err(Error::Format("invalid salt length".into()));
    }
    let pw = normalize_password(password)?;
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(OUT_LEN))
        .map_err(|_| Error::Format("key derivation parameters out of bounds".into()))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; OUT_LEN]);
    a.hash_password_into(pw.as_bytes(), salt, &mut *out)
        .map_err(|_| Error::KeyProvider("key derivation failed".into()))?;
    Ok(out)
}

pub fn random_salt(rng: &mut dyn RandomSource) -> Result<[u8; SALT_LEN]> {
    random_array::<SALT_LEN>(rng)
}

/// Length-prefixed concatenation (u32 big-endian length before each field):
/// unambiguous context strings for HKDF info and AEAD associated data.
pub fn fields(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(parts.iter().map(|p| p.len() + 4).sum());
    for p in parts {
        v.extend_from_slice(&(p.len() as u32).to_be_bytes());
        v.extend_from_slice(p);
    }
    v
}

/// KEK for one slot: HKDF-SHA256(salt, ikm, info = fields(context…)).
pub fn slot_kek(
    ikm: &[u8],
    salt: Option<&[u8]>,
    kind: &str,
    vault_id: &str,
    slot_id: &str,
) -> Result<crate::crypto::Key256> {
    let info = fields(&[
        b"keymesh.vault",
        b"2",
        b"kek",
        kind.as_bytes(),
        vault_id.as_bytes(),
        slot_id.as_bytes(),
    ]);
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(salt, ikm)
        .expand(&info, &mut *okm)
        .map_err(|_| Error::KeyProvider("key derivation failed".into()))?;
    Ok(crate::crypto::Key256::from_bytes(*okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_reject_hostile_parameters_without_running() {
        assert!(KdfParams::DEFAULT.check().is_ok());
        for bad in [
            KdfParams {
                m_kib: M_KIB_MAX + 1,
                t: 3,
                p: 1,
            },
            KdfParams {
                m_kib: u32::MAX,
                t: 3,
                p: 1,
            },
            KdfParams {
                m_kib: M_KIB_MIN - 1,
                t: 3,
                p: 1,
            },
            KdfParams {
                m_kib: 65536,
                t: 1,
                p: 1,
            },
            KdfParams {
                m_kib: 65536,
                t: T_MAX + 1,
                p: 1,
            },
            KdfParams {
                m_kib: 65536,
                t: u32::MAX,
                p: 1,
            },
            KdfParams {
                m_kib: 65536,
                t: 3,
                p: 0,
            },
            KdfParams {
                m_kib: 65536,
                t: 3,
                p: 5,
            },
            // Inside each range, but too much total work.
            KdfParams {
                m_kib: M_KIB_MAX,
                t: T_MAX,
                p: 1,
            },
        ] {
            assert!(matches!(bad.check(), Err(Error::Format(_))), "{bad:?}");
            assert!(argon2id("synthetic password", &[0; 16], bad).is_err());
        }
        assert!(argon2id("synthetic password", &[0; 15], KdfParams::DEFAULT).is_err());
    }

    #[test]
    fn rfc9106_reference_vector_for_the_library() {
        // RFC 9106 §5.3 (Argon2id, v=19, m=32 KiB, t=3, p=4, secret and
        // associated data). Slots use neither, but this pins the library's
        // core against the standard's own vector.
        let p = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
            .build()
            .unwrap();
        let a = argon2::Argon2::new_with_secret(
            &[3; 8],
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            p,
        )
        .unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[1; 32], &[2; 16], &mut out).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    #[test]
    fn normalization_makes_equivalent_input_equal() {
        // "é" precomposed vs "e" + combining acute.
        let a = normalize_password("caf\u{e9} synthetic").unwrap();
        let b = normalize_password("cafe\u{301} synthetic").unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn new_password_rules() {
        assert!(check_new_password("short pass").is_err());
        assert!(check_new_password(&"a".repeat(20)).is_err());
        assert!(check_new_password("PasswordPassword").is_err());
        assert!(check_new_password("Correct Horse Battery Staple").is_err());
        assert!(check_new_password("synthetic river lamp ferry").is_ok());
        // 15 code points of CJK pass even though they are 45 bytes.
        assert!(check_new_password("合成密碼測試用的十五個字元長度").is_ok());
        assert!(check_new_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        assert!(normalize_password("").is_err());
    }

    #[test]
    fn hkdf_context_separates_slots() {
        let ikm = [7u8; 32];
        let a = slot_kek(&ikm, None, "password", "v1", "s1").unwrap();
        let b = slot_kek(&ikm, None, "password", "v1", "s2").unwrap();
        let c = slot_kek(&ikm, None, "recovery", "v1", "s1").unwrap();
        let d = slot_kek(&ikm, None, "password", "v2", "s1").unwrap();
        let all = [a.as_bytes(), b.as_bytes(), c.as_bytes(), d.as_bytes()];
        for i in 0..all.len() {
            for j in i + 1..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
        // Length prefixes keep ("ab","c") and ("a","bc") apart.
        assert_ne!(fields(&[b"ab", b"c"]), fields(&[b"a", b"bc"]));
    }
}
