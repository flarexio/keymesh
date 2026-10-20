//! Typed vault items and validation.
//!
//! Every field of an [`Item`] — including title, URLs and notes — lives inside
//! the encrypted item payload. Only the item id and revision are visible in
//! the vault file (see [`crate::vault`]).

use crate::ed25519::Ed25519KeyPair;
use crate::error::{Error, Result};
use crate::generate::SecretEncoding;
use crate::rng::{random_array, RandomSource};
use crate::secret::SecretString;
use crate::totp::TotpConfig;
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_TITLE: usize = 256;
pub const MAX_LABEL: usize = 128;
pub const MAX_SHORT: usize = 2048;
pub const MAX_VALUE: usize = 64 * 1024;
pub const MAX_LIST: usize = 256;

/// 128-bit random identifier, lowercase hex.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ItemId(String);

impl ItemId {
    pub fn generate(rng: &mut dyn RandomSource) -> Result<Self> {
        Ok(ItemId(
            data_encoding::HEXLOWER.encode(&random_array::<16>(rng)?),
        ))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ItemId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        if s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(ItemId(s))
        } else {
            Err(Error::validation("invalid item id"))
        }
    }
}

impl std::str::FromStr for ItemId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        ItemId::try_from(s.to_owned())
    }
}

impl From<ItemId> for String {
    fn from(i: ItemId) -> String {
        i.0
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ItemId({})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    Secret,
    Contact,
    CryptoWallet,
    Ed25519Key,
    Totp,
    SecureNote,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Secret => "secret",
            Self::Contact => "contact",
            Self::CryptoWallet => "crypto_wallet",
            Self::Ed25519Key => "ed25519_key",
            Self::Totp => "totp",
            Self::SecureNote => "secure_note",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabeledValue {
    pub label: Option<String>,
    pub value: String,
}

impl LabeledValue {
    pub fn new(label: Option<&str>, value: impl Into<String>) -> Self {
        Self {
            label: label.map(str::to_owned),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Concealed,
    Url,
    Email,
    Phone,
    Date,
    Otp,
    /// Imported field whose source type has no first-class mapping; the value
    /// is preserved verbatim (encrypted).
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomField {
    pub section: Option<String>,
    pub label: String,
    pub kind: FieldKind,
    /// Source field type name when imported (e.g. 1Password `SSHKEY`).
    pub source_type: Option<String>,
    pub value: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<SecretString>,
    pub urls: Vec<String>,
    /// Reference to a [`ItemKind::Totp`] item in the same vault.
    pub totp_item: Option<ItemId>,
    pub recovery_codes: Vec<SecretString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretOrigin {
    /// Random value generated locally by Keymesh. Not provider-issued.
    Generated,
    /// Entered or pasted by the user.
    Manual,
    /// Imported from another password manager.
    Imported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretFormat {
    Text,
    Encoded(SecretEncoding),
    /// Opaque private-key material in an unverified format (e.g. imported PEM).
    OpaquePrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCredential {
    pub secret: SecretString,
    pub format: SecretFormat,
    pub origin: SecretOrigin,
    pub username: Option<String>,
    pub service: Option<String>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub full_name: Option<String>,
    pub organization: Option<String>,
    pub emails: Vec<LabeledValue>,
    pub phones: Vec<LabeledValue>,
    pub addresses: Vec<LabeledValue>,
    pub websites: Vec<LabeledValue>,
}

/// Passive encrypted storage of another wallet's data. Keymesh does not
/// sign transactions, talk to chains or validate recovery phrases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CryptoWalletRecord {
    pub wallet_software: Option<String>,
    pub network: Option<String>,
    pub addresses: Vec<LabeledValue>,
    pub recovery_phrase: Option<SecretString>,
    pub wallet_password: Option<SecretString>,
    pub private_key: Option<SecretString>,
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpRecord {
    pub config: TotpConfig,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519KeyRecord {
    pub key: Ed25519KeyPair,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureNote {
    pub body: SecretString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ItemData {
    Login(Login),
    Secret(SecretCredential),
    Contact(Contact),
    CryptoWallet(CryptoWalletRecord),
    Ed25519Key(Ed25519KeyRecord),
    Totp(TotpRecord),
    SecureNote(SecureNote),
}

impl ItemData {
    pub fn kind(&self) -> ItemKind {
        match self {
            Self::Login(_) => ItemKind::Login,
            Self::Secret(_) => ItemKind::Secret,
            Self::Contact(_) => ItemKind::Contact,
            Self::CryptoWallet(_) => ItemKind::CryptoWallet,
            Self::Ed25519Key(_) => ItemKind::Ed25519Key,
            Self::Totp(_) => ItemKind::Totp,
            Self::SecureNote(_) => ItemKind::SecureNote,
        }
    }
}

/// Provenance of an imported item, used for de-duplication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportSource {
    pub provider: String,
    /// Stable source identifier (e.g. `1password:<vault-id>/<item-id>`).
    pub source_id: String,
    /// SHA-256 over the mapped content, detects source changes.
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Item {
    pub id: ItemId,
    pub rev: u64,
    pub title: String,
    pub tags: Vec<String>,
    pub notes: Option<SecretString>,
    pub custom_fields: Vec<CustomField>,
    pub created_at: u64,
    pub updated_at: u64,
    pub source: Option<ImportSource>,
    pub data: ItemData,
}

/// Current Unix time in seconds (0 if the clock is before the epoch).
///
/// `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`, so the
/// browser build reads the JavaScript clock instead.
pub fn unix_now() -> u64 {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        let ms = js_sys::Date::now();
        if ms.is_finite() && ms > 0.0 {
            (ms / 1000.0) as u64
        } else {
            0
        }
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl Item {
    /// New item with a random id, revision 1 and current timestamps. Validated.
    pub fn new(
        title: impl Into<String>,
        data: ItemData,
        rng: &mut dyn RandomSource,
    ) -> Result<Self> {
        let now = unix_now();
        let item = Self {
            id: ItemId::generate(rng)?,
            rev: 1,
            title: title.into(),
            tags: vec![],
            notes: None,
            custom_fields: vec![],
            created_at: now,
            updated_at: now,
            source: None,
            data,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn kind(&self) -> ItemKind {
        self.data.kind()
    }

    /// Item-local validation. Cross-item references are checked by the vault.
    pub fn validate(&self) -> Result<()> {
        text("title", &self.title, 1, MAX_TITLE)?;
        list("tags", &self.tags)?;
        for t in &self.tags {
            text("tag", t, 1, MAX_LABEL)?;
        }
        if let Some(n) = &self.notes {
            secret_len("notes", n, MAX_VALUE)?;
        }
        list("custom_fields", &self.custom_fields)?;
        for f in &self.custom_fields {
            text("custom field label", &f.label, 1, MAX_LABEL)?;
            opt_text("custom field section", &f.section, MAX_LABEL)?;
            opt_text("custom field source type", &f.source_type, MAX_LABEL)?;
            secret_len("custom field value", &f.value, MAX_VALUE)?;
        }
        if let Some(s) = &self.source {
            text("source provider", &s.provider, 1, MAX_LABEL)?;
            text("source id", &s.source_id, 1, MAX_SHORT)?;
            text("source fingerprint", &s.fingerprint, 1, MAX_LABEL)?;
        }
        if self.rev == 0 {
            return Err(Error::validation("revision must start at 1"));
        }
        match &self.data {
            ItemData::Login(l) => {
                opt_text("username", &l.username, MAX_SHORT)?;
                if let Some(p) = &l.password {
                    secret_len("password", p, MAX_SHORT)?;
                }
                list("urls", &l.urls)?;
                for u in &l.urls {
                    url(u)?;
                }
                list("recovery_codes", &l.recovery_codes)?;
                for c in &l.recovery_codes {
                    if c.is_empty() {
                        return Err(Error::validation("recovery code is empty"));
                    }
                    secret_len("recovery code", c, MAX_LABEL)?;
                }
            }
            ItemData::Secret(s) => {
                if s.secret.is_empty() {
                    return Err(Error::validation("secret is empty"));
                }
                secret_len("secret", &s.secret, MAX_VALUE)?;
                if let SecretFormat::Encoded(enc) = s.format {
                    enc.decode(s.secret.expose())?;
                }
                opt_text("username", &s.username, MAX_SHORT)?;
                opt_text("service", &s.service, MAX_SHORT)?;
            }
            ItemData::Contact(c) => {
                opt_text("full_name", &c.full_name, MAX_SHORT)?;
                opt_text("organization", &c.organization, MAX_SHORT)?;
                for (name, vals) in [
                    ("emails", &c.emails),
                    ("phones", &c.phones),
                    ("addresses", &c.addresses),
                    ("websites", &c.websites),
                ] {
                    labeled(name, vals)?;
                }
                for e in &c.emails {
                    email(&e.value)?;
                }
                for w in &c.websites {
                    url(&w.value)?;
                }
                if c.full_name.is_none()
                    && c.organization.is_none()
                    && c.emails.is_empty()
                    && c.phones.is_empty()
                    && c.addresses.is_empty()
                    && c.websites.is_empty()
                {
                    return Err(Error::validation("contact has no name or contact details"));
                }
            }
            ItemData::CryptoWallet(w) => {
                opt_text("wallet_software", &w.wallet_software, MAX_SHORT)?;
                opt_text("network", &w.network, MAX_SHORT)?;
                opt_text("derivation_path", &w.derivation_path, MAX_SHORT)?;
                labeled("addresses", &w.addresses)?;
                for s in [&w.recovery_phrase, &w.wallet_password, &w.private_key]
                    .into_iter()
                    .flatten()
                {
                    secret_len("wallet secret", s, MAX_VALUE)?;
                }
            }
            ItemData::Ed25519Key(k) => {
                k.key.validate()?;
                opt_text("comment", &k.comment, MAX_LABEL)?;
            }
            ItemData::Totp(t) => {
                t.config.validate()?;
                opt_text("issuer", &t.issuer, MAX_SHORT)?;
                opt_text("account_name", &t.account_name, MAX_SHORT)?;
            }
            ItemData::SecureNote(n) => secret_len("note body", &n.body, MAX_VALUE)?,
        }
        Ok(())
    }
}

fn text(name: &str, s: &str, min: usize, max: usize) -> Result<()> {
    let n = s.chars().count();
    if n < min || n > max {
        return Err(Error::validation(format!(
            "{name} length must be {min}..={max}"
        )));
    }
    if s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
        return Err(Error::validation(format!(
            "{name} contains control characters"
        )));
    }
    Ok(())
}

fn opt_text(name: &str, s: &Option<String>, max: usize) -> Result<()> {
    match s {
        Some(v) => text(name, v, 1, max),
        None => Ok(()),
    }
}

fn secret_len(name: &str, s: &SecretString, max: usize) -> Result<()> {
    if s.len() > max {
        return Err(Error::validation(format!("{name} exceeds {max} bytes")));
    }
    Ok(())
}

fn list<T>(name: &str, v: &[T]) -> Result<()> {
    if v.len() > MAX_LIST {
        return Err(Error::validation(format!(
            "{name} has more than {MAX_LIST} entries"
        )));
    }
    Ok(())
}

fn labeled(name: &str, v: &[LabeledValue]) -> Result<()> {
    list(name, v)?;
    for lv in v {
        opt_text("label", &lv.label, MAX_LABEL)?;
        text(name, &lv.value, 1, MAX_SHORT)?;
    }
    Ok(())
}

fn url(u: &str) -> Result<()> {
    text("url", u, 1, MAX_SHORT)?;
    if u.chars().any(char::is_whitespace) {
        return Err(Error::validation("url contains whitespace"));
    }
    Ok(())
}

fn email(e: &str) -> Result<()> {
    match e.split_once('@') {
        Some((local, domain))
            if !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && !e.chars().any(char::is_whitespace) =>
        {
            Ok(())
        }
        _ => Err(Error::validation("invalid email address")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::OsRandom;
    use crate::secret::SecretBytes;
    use crate::totp::TotpAlgorithm;

    fn login() -> ItemData {
        ItemData::Login(Login {
            username: Some("synthetic-user".into()),
            password: Some(SecretString::new("synthetic-pass")),
            urls: vec!["https://example.test/login".into()],
            totp_item: None,
            recovery_codes: vec![SecretString::new("RC-0001")],
        })
    }

    #[test]
    fn every_kind_validates_and_round_trips() {
        let mut r = OsRandom;
        let datas = vec![
            login(),
            ItemData::Secret(SecretCredential {
                secret: SecretString::new("00ff"),
                format: SecretFormat::Encoded(SecretEncoding::Hex),
                origin: SecretOrigin::Generated,
                username: None,
                service: Some("example api".into()),
                expires_at: None,
            }),
            ItemData::Contact(Contact {
                full_name: Some("Synthetic Person".into()),
                emails: vec![
                    LabeledValue::new(Some("work"), "a@example.test"),
                    LabeledValue::new(Some("home"), "b@example.test"),
                ],
                phones: vec![LabeledValue::new(None, "+1 555 0100")],
                ..Default::default()
            }),
            ItemData::CryptoWallet(CryptoWalletRecord {
                network: Some("testnet".into()),
                addresses: vec![LabeledValue::new(None, "synthetic-address-1")],
                recovery_phrase: Some(SecretString::new("synthetic words only")),
                ..Default::default()
            }),
            ItemData::Ed25519Key(Ed25519KeyRecord {
                key: Ed25519KeyPair::generate(&mut r).unwrap(),
                comment: Some("test".into()),
            }),
            ItemData::Totp(TotpRecord {
                config: TotpConfig::with_defaults(SecretBytes::new(vec![7; 20])).unwrap(),
                issuer: Some("Example".into()),
                account_name: None,
            }),
            ItemData::SecureNote(SecureNote {
                body: SecretString::new("synthetic note"),
            }),
        ];
        for d in datas {
            let mut item = Item::new("Synthetic", d, &mut r).unwrap();
            item.custom_fields.push(CustomField {
                section: Some("extra".into()),
                label: "pin".into(),
                kind: FieldKind::Concealed,
                source_type: None,
                value: SecretString::new("1234"),
            });
            item.validate().unwrap();
            let j = serde_json::to_vec(&item).unwrap();
            let back: Item = serde_json::from_slice(&j).unwrap();
            assert_eq!(back, item);
        }
    }

    #[test]
    fn validation_rejects_bad_input() {
        let mut r = OsRandom;
        assert!(Item::new("", login(), &mut r).is_err());
        assert!(Item::new("x".repeat(MAX_TITLE + 1), login(), &mut r).is_err());
        assert!(Item::new("bad\u{0}title", login(), &mut r).is_err());
        assert!(Item::new("c", ItemData::Contact(Contact::default()), &mut r).is_err());
        let bad_email = ItemData::Contact(Contact {
            emails: vec![LabeledValue::new(None, "not-an-email")],
            ..Default::default()
        });
        assert!(Item::new("c", bad_email, &mut r).is_err());
        let bad_hex = ItemData::Secret(SecretCredential {
            secret: SecretString::new("zz"),
            format: SecretFormat::Encoded(SecretEncoding::Hex),
            origin: SecretOrigin::Manual,
            username: None,
            service: None,
            expires_at: None,
        });
        assert!(Item::new("s", bad_hex, &mut r).is_err());
        let bad_url = ItemData::Login(Login {
            username: None,
            password: None,
            urls: vec!["https://exa mple.test".into()],
            totp_item: None,
            recovery_codes: vec![],
        });
        assert!(Item::new("l", bad_url, &mut r).is_err());
        let bad_totp = ItemData::Totp(TotpRecord {
            config: TotpConfig {
                secret: SecretBytes::new(vec![1; 20]),
                algorithm: TotpAlgorithm::Sha1,
                digits: 9,
                period: 30,
            },
            issuer: None,
            account_name: None,
        });
        assert!(Item::new("t", bad_totp, &mut r).is_err());
    }

    #[test]
    fn item_ids_are_validated() {
        assert!("0123456789abcdef0123456789abcdef".parse::<ItemId>().is_ok());
        assert!("0123".parse::<ItemId>().is_err());
        assert!("../../etc/passwd0123456789abcdef"
            .parse::<ItemId>()
            .is_err());
        assert!(serde_json::from_str::<ItemId>("\"XYZ\"").is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let j = r#"{"body":"x","extra":1}"#;
        assert!(serde_json::from_str::<SecureNote>(j).is_err());
    }
}
