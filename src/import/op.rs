//! Import FROM 1Password via the `op` CLI.
//!
//! Supported targets (no implicit account or vault enumeration):
//! * an explicit item: `op item get <item> --vault=<vault> [--account=<acct>] --format=json --reveal`
//! * a single field reference: `op read --no-newline [--account=<acct>] op://vault/item/[section/]field`
//!
//! Flow: [`plan`] fetches and maps every target into in-memory drafts (secrets
//! stay in this process, zeroized on drop), [`ImportPlan::preview`] reports
//! what would happen, and [`ImportPlan::apply`] writes into a [`Vault`]. The
//! caller persists the vault (encrypted) afterwards.
//!
//! Reports contain stable source identifiers, statuses, counts and stable
//! warning codes. They never contain secret values, raw `op` output, stderr,
//! item titles or command arguments.
//!
//! One-time passwords: the OTP field's provisioning value (`otpauth://` URI or
//! Base32 secret) is imported. The ephemeral current code (`totp` key / `--otp`)
//! is ignored.

use crate::error::{Error, Result};
use crate::model::{
    Contact, CryptoWalletRecord, CustomField, FieldKind, ImportSource, Item, ItemData, ItemId,
    LabeledValue, Login, SecretCredential, SecretFormat, SecretOrigin, SecureNote, TotpRecord,
    MAX_LABEL, MAX_TITLE,
};
use crate::rng::RandomSource;
use crate::secret::SecretString;
use crate::totp::{parse_base32_secret, parse_otpauth_uri, TotpConfig};
use crate::vault::Vault;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use zeroize::Zeroizing;

pub const PROVIDER: &str = "1password";
/// Custom-field section holding source URLs that have no typed mapping.
pub const URL_SECTION: &str = "urls";

// ---------------------------------------------------------------------------
// Runner port
// ---------------------------------------------------------------------------

pub struct RunOutput {
    pub status: Option<i32>,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    MissingOp,
    Timeout,
    OutputTooLarge,
    Io,
}

/// Executes `op` with an argument vector (never through a shell).
pub trait OpRunner {
    fn run(&self, args: &[String]) -> std::result::Result<RunOutput, RunError>;
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpTarget {
    Item {
        account: Option<String>,
        vault: String,
        item: String,
    },
    Reference {
        account: Option<String>,
        reference: String,
    },
}

fn check_arg(name: &str, v: &str, positional: bool) -> Result<()> {
    if v.is_empty() || v.len() > 512 {
        return Err(Error::Import(format!("{name} must be 1..=512 bytes")));
    }
    if v.chars().any(char::is_control) {
        return Err(Error::Import(format!("{name} contains control characters")));
    }
    if positional && v.starts_with('-') {
        // Prevents option injection and `-` (read specifiers from stdin).
        return Err(Error::Import(format!("{name} must not start with '-'")));
    }
    Ok(())
}

impl OpTarget {
    pub fn validate(&self) -> Result<()> {
        match self {
            OpTarget::Item {
                account,
                vault,
                item,
            } => {
                if let Some(a) = account {
                    check_arg("account", a, false)?;
                }
                check_arg("vault", vault, false)?;
                check_arg("item", item, true)?;
            }
            OpTarget::Reference { account, reference } => {
                // Secret references are paths (vault/item/field names), which
                // are only unique within an account. Without `--account`, `op`
                // resolves OP_ACCOUNT or its default account, which can change
                // between runs, so provenance would be ambiguous: require it.
                let Some(a) = account else {
                    return Err(Error::Import(
                        "reference targets require an explicit account".into(),
                    ));
                };
                check_arg("account", a, false)?;
                check_arg("reference", reference, true)?;
                let path = reference
                    .strip_prefix("op://")
                    .ok_or_else(|| Error::Import("reference must start with op://".into()))?;
                if path.contains('?') {
                    // e.g. ?attribute=otp would return an ephemeral code.
                    return Err(Error::Import(
                        "reference query parameters are not supported".into(),
                    ));
                }
                let segs: Vec<&str> = path.split('/').collect();
                if !(3..=4).contains(&segs.len()) || segs.iter().any(|s| s.is_empty()) {
                    return Err(Error::Import(
                        "reference must be op://vault/item/[section/]field".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The exact argument vector passed to `op` (no shell).
    pub fn args(&self) -> Result<Vec<String>> {
        self.validate()?;
        let mut a: Vec<String> = Vec::new();
        match self {
            OpTarget::Item {
                account,
                vault,
                item,
            } => {
                a.extend(["item".into(), "get".into(), item.clone()]);
                a.push(format!("--vault={vault}"));
                a.push("--format=json".into());
                a.push("--reveal".into());
                if let Some(acc) = account {
                    a.push(format!("--account={acc}"));
                }
            }
            OpTarget::Reference { account, reference } => {
                a.extend(["read".into(), "--no-newline".into()]);
                if let Some(acc) = account {
                    a.push(format!("--account={acc}"));
                }
                a.push(reference.clone());
            }
        }
        Ok(a)
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportErrorCode {
    InvalidTarget,
    MissingOp,
    Unauthenticated,
    NotFound,
    NonZeroExit,
    Timeout,
    OutputTooLarge,
    MalformedOutput,
    InvalidData,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    WouldCreate,
    Created,
    /// Same source id already imported with identical content.
    UnchangedDuplicate,
    /// Same source id already imported but content changed; not applied
    /// unless [`ConflictPolicy::Update`].
    Conflict,
    WouldUpdate,
    Updated,
    /// Source repeated within the same import run.
    DuplicateInRun,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportEntry {
    /// Stable id: `1password:item:<vault-id>/<item-id>`, `1password:ref:<sha256-prefix>`,
    /// or `target:<n>` when the fetch failed before an id was known.
    pub source_id: String,
    pub category: Option<String>,
    pub status: ImportStatus,
    pub error: Option<ImportErrorCode>,
    pub records: Vec<RecordOutcome>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordOutcome {
    pub source_id: String,
    pub kind: crate::model::ItemKind,
    pub status: ImportStatus,
    pub item_id: Option<String>,
    pub mapped_fields: usize,
    pub custom_fields: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportCounts {
    pub targets: usize,
    pub records: usize,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub conflicts: usize,
    pub duplicates_in_run: usize,
    pub unsupported: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportReport {
    pub provider: String,
    pub applied: bool,
    pub counts: ImportCounts,
    pub entries: Vec<ImportEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictPolicy {
    #[default]
    Skip,
    Update,
}

// ---------------------------------------------------------------------------
// 1Password JSON (lenient: unknown keys ignored, they may be added upstream)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OpItem {
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    category: Option<String>,
    vault: OpVault,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    urls: Vec<OpUrl>,
    #[serde(default)]
    fields: Vec<OpField>,
    #[serde(default)]
    files: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct OpVault {
    id: String,
}

#[derive(Deserialize)]
struct OpUrl {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    href: Option<String>,
}

#[derive(Deserialize)]
struct OpSection {
    #[serde(default)]
    label: Option<String>,
}

#[derive(Deserialize)]
struct OpField {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "type", default)]
    ftype: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    value: Option<serde_json::Value>,
    #[serde(default)]
    section: Option<OpSection>,
    // NOTE: the `totp` key (current ephemeral code) is intentionally not
    // deserialized.
}

impl Drop for OpField {
    fn drop(&mut self) {
        if let Some(serde_json::Value::String(s)) = &mut self.value {
            zeroize::Zeroize::zeroize(s);
        }
    }
}

// ---------------------------------------------------------------------------
// Drafts
// ---------------------------------------------------------------------------

struct Draft {
    source_id: String,
    title: String,
    tags: Vec<String>,
    notes: Option<SecretString>,
    custom_fields: Vec<CustomField>,
    data: ItemData,
    /// For logins: link to the first TOTP draft of the same source item.
    link_totp: bool,
    mapped_fields: usize,
}

impl Draft {
    /// SHA-256 over the mapped content (the login→TOTP link is excluded: it is
    /// a local id, and TOTP changes show up in the TOTP record's own
    /// fingerprint). Stored only inside the encrypted item.
    fn fingerprint(&self) -> String {
        #[derive(Serialize)]
        struct Fp<'a> {
            title: &'a str,
            tags: &'a [String],
            notes: &'a Option<SecretString>,
            custom: &'a [CustomField],
            data: &'a ItemData,
        }
        let j = Zeroizing::new(
            serde_json::to_vec(&Fp {
                title: &self.title,
                tags: &self.tags,
                notes: &self.notes,
                custom: &self.custom_fields,
                data: &self.data,
            })
            .expect("draft serializes"),
        );
        data_encoding::HEXLOWER.encode(&Sha256::digest(&j[..]))
    }

    fn to_item(&self, id: ItemId, totp_link: Option<ItemId>) -> Item {
        let now = crate::model::unix_now();
        let mut data = self.data.clone();
        if let ItemData::Login(l) = &mut data {
            l.totp_item = totp_link;
        }
        Item {
            id,
            rev: 1,
            title: self.title.clone(),
            tags: self.tags.clone(),
            notes: self.notes.clone(),
            custom_fields: self.custom_fields.clone(),
            created_at: now,
            updated_at: now,
            source: Some(ImportSource {
                provider: PROVIDER.into(),
                source_id: self.source_id.clone(),
                fingerprint: self.fingerprint(),
            }),
            data,
        }
    }
}

enum Fetched {
    Ok {
        source_id: String,
        category: Option<String>,
        drafts: Vec<Draft>,
        warnings: Vec<String>,
    },
    Unsupported {
        source_id: String,
        category: Option<String>,
        warnings: Vec<String>,
    },
    Failed {
        source_id: String,
        code: ImportErrorCode,
    },
}

pub struct ImportPlan {
    fetched: Vec<Fetched>,
}

/// Fetch and map every target. Each target is independent: failures are
/// recorded per target and do not abort the others.
pub fn plan(runner: &dyn OpRunner, targets: &[OpTarget]) -> ImportPlan {
    let fetched = targets
        .iter()
        .enumerate()
        .map(|(n, t)| fetch_one(runner, t, n))
        .collect();
    ImportPlan { fetched }
}

fn classify_failure(out: &RunOutput) -> ImportErrorCode {
    // stderr is inspected for classification only; it is never surfaced.
    let s = Zeroizing::new(String::from_utf8_lossy(&out.stderr).to_ascii_lowercase());
    if s.contains("not currently signed in")
        || s.contains("sign in")
        || s.contains("signin")
        || s.contains("session expired")
        || s.contains("unauthorized")
        || s.contains("authorization")
    {
        ImportErrorCode::Unauthenticated
    } else if s.contains("isn't an item")
        || s.contains("isn't a vault")
        || s.contains("not found")
        || s.contains("no item")
    {
        ImportErrorCode::NotFound
    } else {
        ImportErrorCode::NonZeroExit
    }
}

fn run_checked(
    runner: &dyn OpRunner,
    args: &[String],
) -> std::result::Result<RunOutput, ImportErrorCode> {
    let out = runner.run(args).map_err(|e| match e {
        RunError::MissingOp => ImportErrorCode::MissingOp,
        RunError::Timeout => ImportErrorCode::Timeout,
        RunError::OutputTooLarge => ImportErrorCode::OutputTooLarge,
        RunError::Io => ImportErrorCode::Io,
    })?;
    if out.status != Some(0) {
        return Err(classify_failure(&out));
    }
    Ok(out)
}

/// Stable, account-scoped id for a secret reference. The account selector and
/// path are hashed so the report does not reveal them. Different selectors for
/// the same account (shorthand vs. sign-in address vs. ID) give different ids:
/// that can produce a duplicate record, never an overwrite of another
/// account's record.
fn ref_source_id(account: &str, reference: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"keymesh.op-ref.v2\0");
    h.update(account.as_bytes());
    h.update(b"\0");
    h.update(reference.as_bytes());
    format!(
        "{PROVIDER}:acct-ref:{}",
        data_encoding::HEXLOWER.encode(&h.finalize()[..16])
    )
}

fn fetch_one(runner: &dyn OpRunner, target: &OpTarget, n: usize) -> Fetched {
    let fallback_id = match target {
        OpTarget::Reference {
            account: Some(account),
            reference,
        } if target.validate().is_ok() => ref_source_id(account, reference),
        _ => format!("target:{n}"),
    };
    let fail = |code| Fetched::Failed {
        source_id: fallback_id.clone(),
        code,
    };
    let args = match target.args() {
        Ok(a) => a,
        Err(_) => return fail(ImportErrorCode::InvalidTarget),
    };
    let out = match run_checked(runner, &args) {
        Ok(o) => o,
        Err(code) => return fail(code),
    };
    match target {
        OpTarget::Reference { reference, .. } => {
            match map_reference(fallback_id.clone(), reference, &out.stdout) {
                Ok(d) => Fetched::Ok {
                    source_id: fallback_id.clone(),
                    category: None,
                    drafts: vec![d],
                    warnings: vec![],
                },
                Err(code) => fail(code),
            }
        }
        OpTarget::Item { .. } => {
            let item: OpItem = match serde_json::from_slice(&out.stdout) {
                Ok(i) => i,
                Err(_) => return fail(ImportErrorCode::MalformedOutput),
            };
            if item.id.is_empty() || item.vault.id.is_empty() {
                return fail(ImportErrorCode::MalformedOutput);
            }
            let source_id = format!("{PROVIDER}:item:{}/{}", item.vault.id, item.id);
            if check_arg("id", &source_id, false).is_err() {
                return fail(ImportErrorCode::MalformedOutput);
            }
            map_item(source_id, item)
        }
    }
}

fn map_reference(
    source_id: String,
    reference: &str,
    stdout: &[u8],
) -> std::result::Result<Draft, ImportErrorCode> {
    let value = Zeroizing::new(
        std::str::from_utf8(stdout)
            .map_err(|_| ImportErrorCode::MalformedOutput)?
            .to_owned(),
    );
    if value.is_empty() {
        return Err(ImportErrorCode::MalformedOutput);
    }
    let segs: Vec<&str> = reference["op://".len()..].split('/').collect();
    let title = format!("1Password {}/{}", segs[1], segs[segs.len() - 1]);
    let title = if title.chars().count() > MAX_TITLE {
        "1Password reference".to_owned()
    } else {
        title
    };
    let data = if value
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("otpauth://")
    {
        let p = parse_otpauth_uri(&value).map_err(|_| ImportErrorCode::InvalidData)?;
        ItemData::Totp(TotpRecord {
            config: p.config,
            issuer: p.issuer,
            account_name: p.account_name,
        })
    } else {
        ItemData::Secret(SecretCredential {
            secret: SecretString::new(value.as_str()),
            format: SecretFormat::Text,
            origin: SecretOrigin::Imported,
            username: None,
            service: None,
            expires_at: None,
        })
    };
    Ok(Draft {
        source_id,
        title,
        tags: vec![],
        notes: None,
        custom_fields: vec![],
        data,
        link_totp: false,
        mapped_fields: 1,
    })
}

fn value_string(v: &serde_json::Value) -> Option<Zeroizing<String>> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) if s.is_empty() => None,
        serde_json::Value::String(s) => Some(Zeroizing::new(s.clone())),
        // Structured values (e.g. ADDRESS objects) are preserved as JSON text.
        other => Some(Zeroizing::new(other.to_string())),
    }
}

fn field_kind(t: &str) -> FieldKind {
    match t {
        "STRING" | "MENU" => FieldKind::Text,
        "CONCEALED" => FieldKind::Concealed,
        "URL" => FieldKind::Url,
        "EMAIL" => FieldKind::Email,
        "PHONE" => FieldKind::Phone,
        "DATE" | "MONTH_YEAR" => FieldKind::Date,
        "OTP" => FieldKind::Otp,
        _ => FieldKind::Unsupported,
    }
}

fn is_email(s: &str) -> bool {
    matches!(s.split_once('@'), Some((l, d)) if !l.is_empty() && !d.is_empty() && !d.contains('@'))
        && !s.chars().any(char::is_whitespace)
}

fn is_url(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Working view over one field while mapping.
struct F<'a> {
    id: &'a str,
    ftype: &'a str,
    purpose: &'a str,
    label: String,
    label_lc: String,
    section: Option<String>,
    value: Zeroizing<String>,
}

fn otp_config(value: &str) -> Option<(TotpConfig, Option<String>, Option<String>)> {
    if value
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("otpauth://")
    {
        parse_otpauth_uri(value)
            .ok()
            .map(|p| (p.config, p.issuer, p.account_name))
    } else {
        parse_base32_secret(value)
            .ok()
            .and_then(|s| TotpConfig::with_defaults(s).ok())
            .map(|c| (c, None, None))
    }
}

/// Field picker: tracks which fields have been consumed by a typed mapping.
struct Picker<'a> {
    fields: Vec<F<'a>>,
    used: Vec<bool>,
    mapped: usize,
}

impl<'a> Picker<'a> {
    fn take(&mut self, pred: impl Fn(&F) -> bool) -> Option<usize> {
        let i = (0..self.fields.len()).find(|&i| !self.used[i] && pred(&self.fields[i]))?;
        self.used[i] = true;
        self.mapped += 1;
        Some(i)
    }
    fn text(&mut self, pred: impl Fn(&F) -> bool) -> Option<String> {
        self.take(pred).map(|i| self.fields[i].value.to_string())
    }
    fn secret(&mut self, pred: impl Fn(&F) -> bool) -> Option<SecretString> {
        self.take(pred)
            .map(|i| SecretString::new(self.fields[i].value.as_str()))
    }
    fn labeled(&mut self, pred: impl Fn(&F) -> bool) -> Vec<LabeledValue> {
        let mut out = Vec::new();
        while let Some(i) = self.take(&pred) {
            let f = &self.fields[i];
            out.push(LabeledValue::new(Some(&f.label), f.value.as_str()));
        }
        out
    }
}

fn imported_secret(secret: SecretString, format: SecretFormat) -> SecretCredential {
    SecretCredential {
        secret,
        format,
        origin: SecretOrigin::Imported,
        username: None,
        service: None,
        expires_at: None,
    }
}

fn empty_note(notes: &Option<SecretString>) -> ItemData {
    ItemData::SecureNote(SecureNote {
        body: notes.clone().unwrap_or_else(|| SecretString::new("")),
    })
}

fn map_item(source_id: String, item: OpItem) -> Fetched {
    let category = item.category.as_deref().map(str::to_ascii_uppercase);
    let cat = category.clone().unwrap_or_default();
    let failed = |code| Fetched::Failed {
        source_id: source_id.clone(),
        code,
    };
    let mut warnings: Vec<String> = Vec::new();

    if cat == "DOCUMENT" {
        return Fetched::Unsupported {
            source_id: source_id.clone(),
            category,
            warnings: vec!["document_content_not_imported".into()],
        };
    }
    if !item.files.is_empty() {
        warnings.push(format!("attachments_not_imported:{}", item.files.len()));
    }

    let title = item
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or("Untitled 1Password item")
        .to_owned();
    if title.chars().count() > MAX_TITLE {
        return failed(ImportErrorCode::InvalidData);
    }

    let mut fields = Vec::new();
    let mut empty = 0usize;
    for f in &item.fields {
        let Some(value) = f.value.as_ref().and_then(value_string) else {
            empty += 1;
            continue;
        };
        let id = f.id.as_deref().unwrap_or("");
        let label = f
            .label
            .clone()
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| {
                if id.is_empty() {
                    "field".into()
                } else {
                    id.into()
                }
            });
        let section = f
            .section
            .as_ref()
            .and_then(|s| s.label.clone())
            .filter(|s| !s.is_empty());
        // Never truncate: over-long labels fail the item explicitly.
        if label.chars().count() > MAX_LABEL
            || section
                .as_ref()
                .is_some_and(|s| s.chars().count() > MAX_LABEL)
        {
            return failed(ImportErrorCode::InvalidData);
        }
        fields.push(F {
            id,
            ftype: f.ftype.as_deref().unwrap_or(""),
            purpose: f.purpose.as_deref().unwrap_or(""),
            label_lc: label.to_ascii_lowercase(),
            label,
            section,
            value,
        });
    }
    if empty > 0 {
        warnings.push(format!("empty_fields_skipped:{empty}"));
    }
    let used = vec![false; fields.len()];
    let mut p = Picker {
        fields,
        used,
        mapped: 0,
    };

    let notes = p.secret(|f| f.purpose == "NOTES");

    // OTP fields become TOTP items holding the provisioning secret.
    let mut drafts: Vec<Draft> = Vec::new();
    for i in 0..p.fields.len() {
        if p.fields[i].ftype != "OTP" {
            continue;
        }
        match otp_config(&p.fields[i].value) {
            Some((config, issuer, account_name)) => {
                p.used[i] = true;
                p.mapped += 1;
                let fid = if p.fields[i].id.is_empty() {
                    drafts.len().to_string()
                } else {
                    p.fields[i].id.to_owned()
                };
                drafts.push(Draft {
                    source_id: format!("{source_id}#otp:{fid}"),
                    title: format!("{title} (TOTP)").chars().take(MAX_TITLE).collect(),
                    tags: vec![],
                    notes: None,
                    custom_fields: vec![],
                    data: ItemData::Totp(TotpRecord {
                        config,
                        issuer,
                        account_name,
                    }),
                    link_totp: false,
                    mapped_fields: 1,
                });
            }
            // Unparseable OTP value: preserved as an encrypted custom field.
            None => warnings.push("otp_unparsed_preserved".into()),
        }
    }
    let has_totp = !drafts.is_empty();

    // URLs not consumed by a typed mapping are preserved as custom fields.
    let mut url_used = vec![false; item.urls.len()];
    let primary: Option<ItemData> = match cat.as_str() {
        "LOGIN" => {
            let username = p.text(|f| f.purpose == "USERNAME");
            let password = p.secret(|f| f.purpose == "PASSWORD");
            let mut urls = Vec::new();
            for (i, u) in item.urls.iter().enumerate() {
                match u.href.as_deref() {
                    Some(h) if is_url(h) && h.chars().count() <= crate::model::MAX_SHORT => {
                        urls.push(h.to_owned());
                        url_used[i] = true;
                    }
                    // Kept below as an encrypted custom field.
                    Some(h) if !h.is_empty() => warnings.push("invalid_url_preserved".into()),
                    _ => {}
                }
            }
            Some(ItemData::Login(Login {
                username,
                password,
                urls,
                totp_item: None,
                recovery_codes: vec![],
            }))
        }
        "PASSWORD" => p
            .secret(|f| f.purpose == "PASSWORD" || f.ftype == "CONCEALED")
            .map(|s| ItemData::Secret(imported_secret(s, SecretFormat::Text))),
        "API_CREDENTIAL" => {
            let secret = p
                .secret(|f| f.id == "credential")
                .or_else(|| p.secret(|f| f.ftype == "CONCEALED"));
            secret.map(|s| {
                let mut c = imported_secret(s, SecretFormat::Text);
                c.username = p.text(|f| f.id == "username");
                c.service = p.text(|f| f.id == "hostname");
                ItemData::Secret(c)
            })
        }
        "SSH_KEY" => {
            // Format not verified: opaque secret, never a validated Ed25519 key.
            let k = p.secret(|f| f.ftype == "SSHKEY" || f.id == "private_key");
            if k.is_some() {
                warnings.push("ssh_key_stored_opaque".into());
            }
            k.map(|s| ItemData::Secret(imported_secret(s, SecretFormat::OpaquePrivateKey)))
        }
        "SECURE_NOTE" => Some(empty_note(&notes)),
        "IDENTITY" => {
            let first = p.text(|f| f.id == "firstname");
            let last = p.text(|f| f.id == "lastname");
            let full_name = match (first, last) {
                (Some(a), Some(b)) => Some(format!("{a} {b}")),
                (a, b) => a.or(b),
            };
            let organization = p.text(|f| f.id == "company");
            let c = Contact {
                full_name,
                organization,
                emails: p.labeled(|f| f.ftype == "EMAIL" && is_email(&f.value)),
                phones: p.labeled(|f| f.ftype == "PHONE"),
                addresses: p.labeled(|f| f.ftype == "ADDRESS" || f.id == "address"),
                websites: p.labeled(|f| f.ftype == "URL" && is_url(&f.value)),
            };
            let empty_contact = c == Contact::default();
            (!empty_contact).then_some(ItemData::Contact(c))
        }
        "CRYPTO_WALLET" => {
            let has = |f: &F, keys: &[&str]| {
                keys.iter()
                    .any(|k| f.label_lc.contains(k) || f.id.to_ascii_lowercase().contains(k))
            };
            Some(ItemData::CryptoWallet(CryptoWalletRecord {
                recovery_phrase: p.secret(|f| has(f, &["recovery", "seed", "mnemonic"])),
                private_key: p.secret(|f| has(f, &["private"])),
                wallet_password: p.secret(|f| has(f, &["password"])),
                network: p.text(|f| has(f, &["network", "chain"])),
                addresses: p.labeled(|f| has(f, &["address"])),
                wallet_software: None,
                derivation_path: None,
            }))
        }
        _ => None,
    };

    let data = match primary {
        Some(d) => d,
        None => {
            // Unknown category, or known category missing its primary field:
            // preserve every field as encrypted custom data on a note.
            warnings.push(
                if matches!(
                    cat.as_str(),
                    "PASSWORD" | "API_CREDENTIAL" | "SSH_KEY" | "IDENTITY"
                ) {
                    "primary_field_missing_preserved_as_note".into()
                } else {
                    "category_preserved_as_generic_note".into()
                },
            );
            empty_note(&notes)
        }
    };

    let mut custom_fields: Vec<CustomField> = p
        .fields
        .iter()
        .zip(&p.used)
        .filter(|(_, used)| !**used)
        .map(|(f, _)| CustomField {
            section: f.section.clone(),
            label: f.label.clone(),
            kind: field_kind(f.ftype),
            source_type: Some(f.ftype.to_owned())
                .filter(|s| !s.is_empty() && s.chars().count() <= MAX_LABEL),
            value: SecretString::new(f.value.as_str()),
        })
        .collect();
    let mut empty_urls = 0usize;
    for (u, _) in item.urls.iter().zip(&url_used).filter(|(_, used)| !**used) {
        let Some(href) = u.href.as_deref().filter(|h| !h.is_empty()) else {
            empty_urls += 1;
            continue;
        };
        let label = u
            .label
            .as_deref()
            .filter(|l| !l.is_empty())
            .unwrap_or("url")
            .to_owned();
        // Never truncate: an over-long label fails the item explicitly.
        if label.chars().count() > MAX_LABEL {
            return failed(ImportErrorCode::InvalidData);
        }
        custom_fields.push(CustomField {
            section: Some(URL_SECTION.into()),
            label,
            kind: FieldKind::Url,
            source_type: Some("URL".into()),
            value: SecretString::new(href),
        });
    }
    if empty_urls > 0 {
        warnings.push(format!("empty_urls_skipped:{empty_urls}"));
    }

    let is_login = matches!(data, ItemData::Login(_));
    let notes = match data {
        // The note body already holds the notes.
        ItemData::SecureNote(_) => None,
        _ => notes,
    };
    drafts.push(Draft {
        source_id: source_id.clone(),
        title,
        tags: item
            .tags
            .iter()
            .filter(|t| !t.is_empty())
            .cloned()
            .collect(),
        notes,
        custom_fields,
        data,
        link_totp: is_login && has_totp,
        mapped_fields: p.mapped,
    });

    // Pre-validate every record so apply cannot fail half-way on bad data.
    if drafts
        .iter()
        .any(|d| d.to_item(placeholder_id(), None).validate().is_err())
    {
        return failed(ImportErrorCode::InvalidData);
    }
    Fetched::Ok {
        source_id,
        category,
        drafts,
        warnings,
    }
}

fn placeholder_id() -> ItemId {
    "00000000000000000000000000000000"
        .parse()
        .expect("valid id")
}

// ---------------------------------------------------------------------------
// Preview / apply
// ---------------------------------------------------------------------------

/// What the plan intends for one draft, relative to the current vault.
enum Decision {
    Create,
    Unchanged(ItemId),
    Conflict(ItemId),
    Update(ItemId),
}

fn decide(vault: &Vault, d: &Draft, policy: ConflictPolicy) -> Decision {
    match vault.find_by_source(PROVIDER, &d.source_id) {
        None => Decision::Create,
        Some(e)
            if e.source
                .as_ref()
                .is_some_and(|s| s.fingerprint == d.fingerprint()) =>
        {
            Decision::Unchanged(e.id.clone())
        }
        Some(e) if policy == ConflictPolicy::Update => Decision::Update(e.id.clone()),
        Some(e) => Decision::Conflict(e.id.clone()),
    }
}

impl ImportPlan {
    /// Report what `apply` would do, without modifying the vault.
    pub fn preview(&self, vault: &Vault, policy: ConflictPolicy) -> ImportReport {
        let mut seen = HashSet::new();
        let entries = self
            .fetched
            .iter()
            .map(|f| {
                entry_for(f, &mut seen, |drafts| {
                    Ok(drafts
                        .iter()
                        .map(|d| {
                            let (status, id) = match decide(vault, d, policy) {
                                Decision::Create => (ImportStatus::WouldCreate, None),
                                Decision::Unchanged(i) => {
                                    (ImportStatus::UnchangedDuplicate, Some(i))
                                }
                                Decision::Conflict(i) => (ImportStatus::Conflict, Some(i)),
                                Decision::Update(i) => (ImportStatus::WouldUpdate, Some(i)),
                            };
                            outcome(d, status, id)
                        })
                        .collect())
                })
            })
            .collect();
        finish(entries, false)
    }

    /// Apply into `vault` in memory. Each source entry is applied all-or-
    /// nothing. The caller must persist the vault; if that fails, nothing was
    /// written.
    pub fn apply(
        &self,
        vault: &mut Vault,
        policy: ConflictPolicy,
        rng: &mut dyn RandomSource,
    ) -> ImportReport {
        let mut seen = HashSet::new();
        let entries = self
            .fetched
            .iter()
            .map(|f| {
                entry_for(f, &mut seen, |drafts| {
                    apply_entry(vault, drafts, policy, rng)
                })
            })
            .collect();
        finish(entries, true)
    }
}

fn outcome(d: &Draft, status: ImportStatus, id: Option<ItemId>) -> RecordOutcome {
    RecordOutcome {
        source_id: d.source_id.clone(),
        kind: d.data.kind(),
        status,
        item_id: id.map(|i| i.to_string()),
        mapped_fields: d.mapped_fields,
        custom_fields: d.custom_fields.len(),
    }
}

fn apply_entry(
    vault: &mut Vault,
    drafts: &[Draft],
    policy: ConflictPolicy,
    rng: &mut dyn RandomSource,
) -> std::result::Result<Vec<RecordOutcome>, ImportErrorCode> {
    let mut created: Vec<ItemId> = Vec::new();
    let mut updated: Vec<Item> = Vec::new();
    let mut out = Vec::new();
    // Item id of the first TOTP record, for the login link.
    let mut totp_id: Option<ItemId> = None;
    let mut result = Ok(());
    for d in drafts {
        let link = if d.link_totp { totp_id.clone() } else { None };
        let step = match decide(vault, d, policy) {
            Decision::Create => ItemId::generate(rng)
                .map_err(|_| ImportErrorCode::Io)
                .and_then(|id| {
                    vault
                        .insert(d.to_item(id, link))
                        .map_err(|_| ImportErrorCode::InvalidData)
                })
                .map(|id| {
                    created.push(id.clone());
                    (ImportStatus::Created, id)
                }),
            Decision::Unchanged(id) => Ok((ImportStatus::UnchangedDuplicate, id)),
            Decision::Conflict(id) => Ok((ImportStatus::Conflict, id)),
            Decision::Update(id) => {
                let before = vault.get(&id).cloned().map_err(|_| ImportErrorCode::Io);
                before.and_then(|before| {
                    let fresh = d.to_item(id.clone(), link);
                    vault
                        .update(&id, |it| {
                            it.title = fresh.title;
                            it.tags = fresh.tags;
                            it.notes = fresh.notes;
                            it.custom_fields = fresh.custom_fields;
                            it.data = fresh.data;
                            it.source = fresh.source;
                        })
                        .map_err(|_| ImportErrorCode::InvalidData)?;
                    updated.push(before);
                    Ok((ImportStatus::Updated, id))
                })
            }
        };
        match step {
            Ok((status, id)) => {
                if matches!(d.data, ItemData::Totp(_)) && totp_id.is_none() {
                    totp_id = Some(id.clone());
                }
                out.push(outcome(d, status, Some(id)));
            }
            Err(code) => {
                result = Err(code);
                break;
            }
        }
    }
    if let Err(code) = result {
        // Roll back this entry (logins first: they may reference TOTP items).
        for id in created.iter().rev() {
            let _ = vault.remove(id);
        }
        for before in updated {
            vault.restore_item(before);
        }
        return Err(code);
    }
    Ok(out)
}

fn entry_for(
    f: &Fetched,
    seen: &mut HashSet<String>,
    act: impl FnOnce(&[Draft]) -> std::result::Result<Vec<RecordOutcome>, ImportErrorCode>,
) -> ImportEntry {
    let base = |source_id: &str, category: &Option<String>, status| ImportEntry {
        source_id: source_id.to_owned(),
        category: category.clone(),
        status,
        error: None,
        records: vec![],
        warnings: vec![],
    };
    match f {
        Fetched::Failed { source_id, code } => ImportEntry {
            error: Some(*code),
            ..base(source_id, &None, ImportStatus::Failed)
        },
        Fetched::Unsupported {
            source_id,
            category,
            warnings,
        } => ImportEntry {
            warnings: warnings.clone(),
            ..base(source_id, category, ImportStatus::Unsupported)
        },
        Fetched::Ok {
            source_id,
            category,
            ..
        } if !seen.insert(source_id.clone()) => {
            base(source_id, category, ImportStatus::DuplicateInRun)
        }
        Fetched::Ok {
            source_id,
            category,
            drafts,
            warnings,
        } => match act(drafts) {
            Ok(records) => ImportEntry {
                status: aggregate(&records),
                records,
                warnings: warnings.clone(),
                ..base(source_id, category, ImportStatus::Failed)
            },
            Err(code) => ImportEntry {
                error: Some(code),
                warnings: warnings.clone(),
                ..base(source_id, category, ImportStatus::Failed)
            },
        },
    }
}

fn aggregate(records: &[RecordOutcome]) -> ImportStatus {
    use ImportStatus::*;
    [Conflict, Updated, WouldUpdate, Created, WouldCreate]
        .into_iter()
        .find(|s| records.iter().any(|r| r.status == *s))
        .unwrap_or(UnchangedDuplicate)
}

fn finish(entries: Vec<ImportEntry>, applied: bool) -> ImportReport {
    let mut c = ImportCounts {
        targets: entries.len(),
        ..Default::default()
    };
    for e in &entries {
        match e.status {
            ImportStatus::Failed => c.failed += 1,
            ImportStatus::Unsupported => c.unsupported += 1,
            ImportStatus::DuplicateInRun => c.duplicates_in_run += 1,
            _ => {}
        }
        for r in &e.records {
            c.records += 1;
            match r.status {
                ImportStatus::Created | ImportStatus::WouldCreate => c.created += 1,
                ImportStatus::Updated | ImportStatus::WouldUpdate => c.updated += 1,
                ImportStatus::UnchangedDuplicate => c.unchanged += 1,
                ImportStatus::Conflict => c.conflicts += 1,
                _ => {}
            }
        }
    }
    ImportReport {
        provider: PROVIDER.into(),
        applied,
        counts: c,
        entries,
    }
}
