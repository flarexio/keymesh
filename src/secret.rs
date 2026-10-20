//! Secret value wrappers: zeroized on drop and redacted in `Debug`.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A secret UTF-8 string. Never printed by `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        SecretString(s.into())
    }
    /// Explicit, greppable access to the plaintext.
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        SecretString(s)
    }
}

impl From<Zeroizing<String>> for SecretString {
    fn from(s: Zeroizing<String>) -> Self {
        SecretString(s.as_str().to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Secret binary material, serialized as unpadded base64url.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(b: Vec<u8>) -> Self {
        SecretBytes(b)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.0.len())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let enc = Zeroizing::new(data_encoding::BASE64URL_NOPAD.encode(&self.0));
        s.serialize_str(&enc)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = Zeroizing::new(String::deserialize(d)?);
        data_encoding::BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map(SecretBytes)
            .map_err(|_| serde::de::Error::custom("invalid base64url secret bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretString::new("hunter2-synthetic");
        assert!(!format!("{s:?}").contains("hunter2"));
        let b = SecretBytes::new(vec![0xAB; 4]);
        assert!(!format!("{b:?}").contains("ab"));
    }

    #[test]
    fn bytes_serde_round_trip() {
        let b = SecretBytes::new((0u8..40).collect());
        let j = serde_json::to_string(&b).unwrap();
        let back: SecretBytes = serde_json::from_str(&j).unwrap();
        assert_eq!(back, b);
    }
}
