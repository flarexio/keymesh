//! RFC 6238 TOTP for codes used by *external* services.
//!
//! This is not Keymesh's own authentication. HOTP (counter-based) and
//! vendor-specific variants (e.g. `encoder=steam`) are rejected explicitly
//! rather than being silently treated as TOTP.

use crate::error::{Error, Result};
use crate::secret::SecretBytes;
use hmac::{Hmac, Mac};
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const DEFAULT_PERIOD: u32 = 30;
pub const MIN_PERIOD: u32 = 15;
pub const MAX_PERIOD: u32 = 300;
/// 80 bits: the length most deployed providers issue. RFC 4226 recommends
/// 160 bits; we accept shorter provider-issued secrets for interoperability.
pub const MIN_SECRET_LEN: usize = 10;
pub const MAX_SECRET_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            _ => Err(Error::Totp("unsupported algorithm".into())),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpConfig {
    pub secret: SecretBytes,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u32,
}

impl TotpConfig {
    pub fn new(
        secret: SecretBytes,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u32,
    ) -> Result<Self> {
        let c = Self {
            secret,
            algorithm,
            digits,
            period,
        };
        c.validate()?;
        Ok(c)
    }

    /// Defaults: SHA1, 6 digits, 30 s.
    pub fn with_defaults(secret: SecretBytes) -> Result<Self> {
        Self::new(secret, TotpAlgorithm::Sha1, 6, DEFAULT_PERIOD)
    }

    pub fn validate(&self) -> Result<()> {
        if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&self.secret.len()) {
            return Err(Error::Totp(format!(
                "secret must be {MIN_SECRET_LEN}..={MAX_SECRET_LEN} bytes"
            )));
        }
        if self.digits != 6 && self.digits != 8 {
            return Err(Error::Totp("digits must be 6 or 8".into()));
        }
        if !(MIN_PERIOD..=MAX_PERIOD).contains(&self.period) {
            return Err(Error::Totp(format!(
                "period must be {MIN_PERIOD}..={MAX_PERIOD} seconds"
            )));
        }
        Ok(())
    }
}

/// Injectable clock (seconds since Unix epoch).
pub trait Clock {
    fn now_unix(&self) -> Result<u64>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> Result<u64> {
        match crate::model::unix_now() {
            0 => Err(Error::Totp(
                "system clock unavailable or before Unix epoch".into(),
            )),
            t => Ok(t),
        }
    }
}

pub struct FixedClock(pub u64);
impl Clock for FixedClock {
    fn now_unix(&self) -> Result<u64> {
        Ok(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub seconds_remaining: u32,
}

fn hmac_digest(alg: TotpAlgorithm, key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    macro_rules! mac {
        ($h:ty) => {{
            let mut m =
                <Hmac<$h> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(msg);
            Zeroizing::new(m.finalize().into_bytes().to_vec())
        }};
    }
    match alg {
        TotpAlgorithm::Sha1 => mac!(sha1::Sha1),
        TotpAlgorithm::Sha256 => mac!(sha2::Sha256),
        TotpAlgorithm::Sha512 => mac!(sha2::Sha512),
    }
}

/// Code for the time step containing `unix_time`.
pub fn code_at(cfg: &TotpConfig, unix_time: u64) -> Result<String> {
    cfg.validate()?;
    let counter = unix_time / u64::from(cfg.period);
    let digest = hmac_digest(cfg.algorithm, cfg.secret.expose(), &counter.to_be_bytes());
    // RFC 4226 §5.3 dynamic truncation.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10u32.pow(u32::from(cfg.digits));
    Ok(format!(
        "{:0width$}",
        bin % modulus,
        width = cfg.digits as usize
    ))
}

pub fn code_now(cfg: &TotpConfig, clock: &dyn Clock) -> Result<TotpCode> {
    let now = clock.now_unix()?;
    let code = code_at(cfg, now)?;
    let period = u64::from(cfg.period);
    Ok(TotpCode {
        code,
        seconds_remaining: (period - now % period) as u32,
    })
}

/// Parse a manually entered Base32 secret. Case-insensitive; spaces, hyphens
/// and trailing `=` padding are ignored.
pub fn parse_base32_secret(input: &str) -> Result<SecretBytes> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .trim_end_matches('=')
            .to_ascii_uppercase(),
    );
    if cleaned.is_empty() {
        return Err(Error::Totp("empty Base32 secret".into()));
    }
    let bytes = data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| Error::Totp("invalid Base32 secret".into()))?;
    let s = SecretBytes::new(bytes);
    if !(MIN_SECRET_LEN..=MAX_SECRET_LEN).contains(&s.len()) {
        return Err(Error::Totp(format!(
            "secret must be {MIN_SECRET_LEN}..={MAX_SECRET_LEN} bytes"
        )));
    }
    Ok(s)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuth {
    pub config: TotpConfig,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

fn decode_component(s: &str) -> Result<String> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| Error::Totp("invalid percent-encoding in URI".into()))
}

/// Parse an `otpauth://totp/...` Key URI.
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpAuth> {
    let uri = uri.trim();
    let rest = uri
        .get(..10)
        .filter(|p| p.eq_ignore_ascii_case("otpauth://"))
        .map(|_| &uri[10..])
        .ok_or_else(|| Error::Totp("not an otpauth:// URI".into()))?;
    let (otp_type, rest) = rest
        .split_once('/')
        .ok_or_else(|| Error::Totp("missing OTP type".into()))?;
    match otp_type.to_ascii_lowercase().as_str() {
        "totp" => {}
        "hotp" => return Err(Error::Totp("HOTP is not supported".into())),
        _ => return Err(Error::Totp("unsupported OTP type".into())),
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    if query.contains('#') {
        return Err(Error::Totp("fragment not allowed in otpauth URI".into()));
    }
    let label = decode_component(label)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
        None => (None, label.trim().to_owned()),
    };

    let mut params: HashMap<String, Zeroizing<String>> = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = k.to_ascii_lowercase();
        if !matches!(
            k.as_str(),
            "secret" | "issuer" | "algorithm" | "digits" | "period" | "image"
        ) {
            return Err(Error::Totp("unsupported otpauth parameter".into()));
        }
        if params
            .insert(k, Zeroizing::new(decode_component(v)?))
            .is_some()
        {
            return Err(Error::Totp("duplicate otpauth parameter".into()));
        }
    }

    let secret = parse_base32_secret(
        params
            .get("secret")
            .ok_or_else(|| Error::Totp("missing secret".into()))?,
    )?;
    let algorithm = match params.get("algorithm") {
        Some(a) => TotpAlgorithm::parse(a)?,
        None => TotpAlgorithm::Sha1,
    };
    let digits = match params.get("digits") {
        Some(d) => d
            .parse::<u8>()
            .map_err(|_| Error::Totp("invalid digits".into()))?,
        None => 6,
    };
    let period = match params.get("period") {
        Some(p) => p
            .parse::<u32>()
            .map_err(|_| Error::Totp("invalid period".into()))?,
        None => DEFAULT_PERIOD,
    };
    let param_issuer = params.get("issuer").map(|s| s.trim().to_owned());
    let issuer = match (label_issuer, param_issuer) {
        (Some(a), Some(b)) if a != b => {
            return Err(Error::Totp("issuer in label and parameter differ".into()))
        }
        (a, b) => b.or(a).filter(|s| !s.is_empty()),
    };
    Ok(OtpAuth {
        config: TotpConfig::new(secret, algorithm, digits, period)?,
        issuer,
        account_name: Some(account).filter(|s| !s.is_empty()),
    })
}

/// Render a Key URI (contains the secret: treat the result as secret).
pub fn to_otpauth_uri(auth: &OtpAuth) -> Zeroizing<String> {
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let account = auth.account_name.as_deref().unwrap_or("");
    let label = match &auth.issuer {
        Some(i) => format!("{}:{}", enc(i), enc(account)),
        None => enc(account),
    };
    let secret = Zeroizing::new(data_encoding::BASE32_NOPAD.encode(auth.config.secret.expose()));
    let mut uri = format!(
        "otpauth://totp/{label}?secret={}&algorithm={}&digits={}&period={}",
        secret.as_str(),
        auth.config.algorithm.as_str(),
        auth.config.digits,
        auth.config.period
    );
    if let Some(i) = &auth.issuer {
        uri.push_str("&issuer=");
        uri.push_str(&enc(i));
    }
    Zeroizing::new(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(seed: &[u8], alg: TotpAlgorithm, digits: u8) -> TotpConfig {
        TotpConfig::new(SecretBytes::new(seed.to_vec()), alg, digits, 30).unwrap()
    }

    // RFC 6238 Appendix B. Seeds are the ASCII strings from the reference
    // implementation (20/32/64 bytes for SHA1/SHA256/SHA512).
    const SEED1: &[u8] = b"12345678901234567890";
    const SEED256: &[u8] = b"12345678901234567890123456789012";
    const SEED512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc6238_appendix_b_vectors() {
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        let c1 = cfg(SEED1, TotpAlgorithm::Sha1, 8);
        let c256 = cfg(SEED256, TotpAlgorithm::Sha256, 8);
        let c512 = cfg(SEED512, TotpAlgorithm::Sha512, 8);
        for (t, s1, s256, s512) in cases {
            assert_eq!(code_at(&c1, *t).unwrap(), *s1, "sha1 t={t}");
            assert_eq!(code_at(&c256, *t).unwrap(), *s256, "sha256 t={t}");
            assert_eq!(code_at(&c512, *t).unwrap(), *s512, "sha512 t={t}");
        }
    }

    #[test]
    fn six_digits_and_leading_zero_preserved() {
        let c = cfg(SEED1, TotpAlgorithm::Sha1, 6);
        // 8-digit vector 07081804 -> 6-digit is last six digits: 081804.
        assert_eq!(code_at(&c, 1111111109).unwrap(), "081804");
        let c8 = cfg(SEED1, TotpAlgorithm::Sha1, 8);
        assert_eq!(code_at(&c8, 1111111109).unwrap(), "07081804");
    }

    #[test]
    fn rollover_at_period_boundary() {
        let c = cfg(SEED1, TotpAlgorithm::Sha1, 8);
        let a = code_now(&c, &FixedClock(1111111109)).unwrap();
        let b = code_now(&c, &FixedClock(1111111110)).unwrap(); // 1111111110 % 30 == 0
        assert_eq!(a.seconds_remaining, 1);
        assert_eq!(b.seconds_remaining, 30);
        assert_ne!(a.code, b.code);
        assert_eq!(b.code, code_at(&c, 1111111139).unwrap());
    }

    #[test]
    fn invalid_configs_rejected() {
        let s = || SecretBytes::new(SEED1.to_vec());
        assert!(TotpConfig::new(s(), TotpAlgorithm::Sha1, 7, 30).is_err());
        assert!(TotpConfig::new(s(), TotpAlgorithm::Sha1, 6, 0).is_err());
        assert!(TotpConfig::new(s(), TotpAlgorithm::Sha1, 6, 10_000).is_err());
        assert!(TotpConfig::new(SecretBytes::new(vec![1; 4]), TotpAlgorithm::Sha1, 6, 30).is_err());
    }

    #[test]
    fn base32_manual_entry() {
        // "12345678901234567890" in Base32.
        let b = parse_base32_secret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(b.expose(), SEED1);
        let b = parse_base32_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====").unwrap();
        assert_eq!(b.expose(), SEED1);
        assert!(parse_base32_secret("not base32 !!").is_err());
        assert!(parse_base32_secret("").is_err());
        assert!(parse_base32_secret("GEZA").is_err()); // too short
    }

    #[test]
    fn otpauth_uri_parse_and_round_trip() {
        let uri = "otpauth://totp/Example%20Co:alice%40example.test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example%20Co&algorithm=SHA256&digits=8&period=60";
        let p = parse_otpauth_uri(uri).unwrap();
        assert_eq!(p.issuer.as_deref(), Some("Example Co"));
        assert_eq!(p.account_name.as_deref(), Some("alice@example.test"));
        assert_eq!(p.config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(p.config.digits, 8);
        assert_eq!(p.config.period, 60);
        let again = parse_otpauth_uri(&to_otpauth_uri(&p)).unwrap();
        assert_eq!(again, p);
    }

    #[test]
    fn otpauth_defaults() {
        let p = parse_otpauth_uri("otpauth://totp/acct?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
            .unwrap();
        assert_eq!(p.config.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(p.config.digits, 6);
        assert_eq!(p.config.period, 30);
        assert_eq!(p.issuer, None);
    }

    #[test]
    fn otpauth_rejects_unsupported_modes() {
        let s = "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for bad in [
            format!("otpauth://hotp/a?{s}&counter=1"),
            format!("otpauth://totp/a?{s}&encoder=steam"),
            format!("otpauth://totp/a?{s}&algorithm=MD5"),
            format!("otpauth://totp/a?{s}&digits=7"),
            format!("otpauth://totp/a?{s}&period=1"),
            format!("otpauth://totp/a?{s}&{s}"),
            format!("otpauth://totp/X:a?{s}&issuer=Y"),
            "otpauth://totp/a?issuer=X".to_string(),
            format!("https://totp/a?{s}"),
        ] {
            assert!(parse_otpauth_uri(&bad).is_err(), "{bad}");
        }
    }
}
