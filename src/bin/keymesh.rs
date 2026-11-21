//! Keymesh CLI — **EXPERIMENTAL, NOT INDEPENDENTLY REVIEWED: synthetic data
//! only until acceptance.**
//!
//! * `init` creates a password-protected vault (envelope v2): a master
//!   password plus a recovery code that is shown once and must be typed back.
//!   Every command opens the vault with the password (Argon2id each time; no
//!   agent or cached key).
//! * `init --demo` creates a v1 demo vault keyed by `KEYMESH_DEMO_KEY` (64 hex
//!   chars, synthetic demo key provider). The file's version decides which
//!   unlock applies; a demo vault is never converted into a protected one.
//!
//! Exit status: 0 success; 1 failure (a failed save never replaces the vault
//! file; `import-op apply` may still have saved before reporting failed
//! targets); 3 the change was
//! written and is in effect but the directory sync failed, so durability is
//! unconfirmed (see `Error::DurabilityUncertain`).
//!
//! Secrets are never taken from command-line arguments: the password and
//! recovery code are read from the terminal without echo, or with
//! `--password-stdin` one line each from stdin (the first lines), followed by
//! any other stdin input the command reads.

use clap::{Args, Parser, Subcommand, ValueEnum};
use keymesh::crypto::SyntheticDemoKeyProvider;
use keymesh::ed25519::Ed25519KeyPair;
use keymesh::generate::{
    generate_passphrase, generate_password, generate_secret, PasswordPolicy, PasswordProfile,
    SecretEncoding,
};
use keymesh::import::op::{plan, ConflictPolicy, OpTarget};
use keymesh::import::process::ProcessOpRunner;
use keymesh::kdf::check_new_password;
use keymesh::keyslot::{Authority, PasswordSetup};
use keymesh::model::{
    Contact, CryptoWalletRecord, Ed25519KeyRecord, Item, ItemData, ItemId, LabeledValue, Login,
    SecretCredential, SecretFormat, SecretOrigin, SecureNote, TotpRecord,
};
use keymesh::recovery::RecoveryCode;
use keymesh::rng::OsRandom;
use keymesh::secret::SecretString;
use keymesh::totp::{
    code_now, parse_base32_secret, parse_otpauth_uri, FixedClock, SystemClock, TotpConfig,
};
use keymesh::vault::{password_request, read_header, Vault};
use keymesh::{storage, Error};
use std::cell::RefCell;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use zeroize::Zeroizing;

const BANNER: &str =
    "keymesh: SYNTHETIC DEMO KEY PROVIDER — not production unlock; use synthetic data only";
const EXPERIMENTAL: &str =
    "keymesh: password vault (experimental, not independently reviewed) — use synthetic data only";

#[derive(Parser)]
#[command(
    name = "keymesh",
    version,
    about = "Keymesh vault CLI (experimental; synthetic data only)"
)]
struct Cli {
    /// Vault file path.
    #[arg(long, env = "KEYMESH_VAULT", global = true)]
    vault: Option<PathBuf>,
    /// Read the password / recovery code from stdin (one line each) instead
    /// of the terminal.
    #[arg(long, global = true)]
    password_stdin: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new empty vault (refuses to overwrite). Asks for a master
    /// password, shows a recovery code once and asks you to type it back.
    Init {
        /// Demo vault keyed by KEYMESH_DEMO_KEY instead (synthetic data only).
        #[arg(long)]
        demo: bool,
    },
    /// Change the master password (needs the current password, or the
    /// recovery code with --recovery). Older backups keep the old password.
    Passwd {
        #[arg(long)]
        recovery: bool,
    },
    /// Replace the recovery code (needs the current password). Older backups
    /// keep the old code.
    NewRecoveryCode,
    /// Open a backup with its recovery code, set a new password and write it
    /// to --vault (refuses to overwrite without --force).
    Recover {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// List items: id, kind, title.
    List,
    /// Show one item as JSON; secrets redacted unless --reveal.
    Show {
        id: ItemId,
        #[arg(long)]
        reveal: bool,
    },
    /// Add an item.
    #[command(subcommand)]
    Add(AddCmd),
    /// Edit item metadata.
    Edit {
        id: ItemId,
        #[arg(long)]
        title: Option<String>,
        #[arg(long = "add-tag")]
        add_tags: Vec<String>,
        /// Replace notes with stdin.
        #[arg(long)]
        notes_stdin: bool,
    },
    /// Delete an item from the Keymesh vault.
    Delete { id: ItemId },
    /// Current TOTP code for a TOTP item.
    Totp {
        id: ItemId,
        /// Unix time to evaluate at (default: now).
        #[arg(long)]
        at: Option<u64>,
    },
    /// Print an Ed25519 item's public key.
    Ed25519Public {
        id: ItemId,
        #[arg(long)]
        openssh: bool,
    },
    /// Generators (no vault needed).
    #[command(subcommand)]
    Gen(GenCmd),
    /// Copy the encrypted vault to a new file after verifying it opens.
    Backup {
        #[arg(long)]
        to: PathBuf,
    },
    /// Restore an encrypted backup to --vault after verifying it opens (with
    /// the backup's own password for a password vault).
    Restore {
        #[arg(long)]
        from: PathBuf,
        /// Replace an existing vault file.
        #[arg(long)]
        force: bool,
    },
    /// Import from 1Password via the local `op` CLI (explicit targets only).
    ImportOp(ImportArgs),
}

#[derive(Subcommand)]
enum AddCmd {
    Login {
        #[arg(long)]
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long = "url")]
        urls: Vec<String>,
        /// Generate the password instead of reading it from stdin.
        #[arg(long)]
        generate: bool,
        #[arg(long, value_enum, default_value_t = Profile::Default)]
        profile: Profile,
        /// Read password from stdin.
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        totp_item: Option<ItemId>,
    },
    Secret {
        #[arg(long)]
        title: String,
        /// Generate a random secret (local random value, not provider-issued).
        #[arg(long)]
        generate: bool,
        #[arg(long, default_value_t = 32)]
        bytes: usize,
        #[arg(long, value_enum, default_value_t = Enc::Hex)]
        encoding: Enc,
        #[arg(long)]
        service: Option<String>,
    },
    /// Body from stdin.
    Note {
        #[arg(long)]
        title: String,
    },
    Contact {
        #[arg(long)]
        title: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        organization: Option<String>,
        #[arg(long = "email")]
        emails: Vec<String>,
        #[arg(long = "phone")]
        phones: Vec<String>,
        #[arg(long = "address")]
        addresses: Vec<String>,
    },
    /// Passive wallet record; recovery phrase from stdin if --phrase-stdin.
    Wallet {
        #[arg(long)]
        title: String,
        #[arg(long)]
        network: Option<String>,
        #[arg(long = "address")]
        addresses: Vec<String>,
        #[arg(long)]
        phrase_stdin: bool,
    },
    /// TOTP from stdin: an otpauth://totp URI, or a Base32 secret with --base32.
    Totp {
        #[arg(long)]
        title: String,
        #[arg(long)]
        base32: bool,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        account: Option<String>,
    },
    /// Generate a new Ed25519 key pair.
    Ed25519 {
        #[arg(long)]
        title: String,
        #[arg(long)]
        comment: Option<String>,
    },
}

#[derive(Subcommand)]
enum GenCmd {
    Password {
        #[arg(long, value_enum, default_value_t = Profile::Default)]
        profile: Profile,
        /// Custom length (requires --alphabet).
        #[arg(long, requires = "alphabet")]
        length: Option<usize>,
        /// Custom character allowlist.
        #[arg(long, requires = "length")]
        alphabet: Option<String>,
    },
    Secret {
        #[arg(long, default_value_t = 32)]
        bytes: usize,
        #[arg(long, value_enum, default_value_t = Enc::Hex)]
        encoding: Enc,
    },
    /// Pending: no reviewed wordlist bundled.
    Passphrase,
}

#[derive(Args)]
struct ImportArgs {
    /// `preview` (default, no writes) or `apply`.
    #[arg(value_enum, default_value_t = Mode::Preview)]
    mode: Mode,
    #[arg(long)]
    account: Option<String>,
    /// 1Password vault containing the --item targets.
    #[arg(long, requires = "items")]
    op_vault: Option<String>,
    /// Item name or ID (repeatable). Requires --op-vault.
    #[arg(long = "item", requires = "op_vault")]
    items: Vec<String>,
    /// Single field reference op://vault/item/[section/]field (repeatable).
    /// Requires --account.
    #[arg(long = "ref")]
    refs: Vec<String>,
    /// Update previously imported items whose source changed.
    #[arg(long)]
    update: bool,
    /// Path to the `op` executable (default: `op` on PATH).
    #[arg(long, env = "KEYMESH_OP_BIN")]
    op_path: Option<PathBuf>,
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Preview,
    Apply,
}

#[derive(Clone, Copy, ValueEnum)]
enum Profile {
    Default,
    Strong,
}

#[derive(Clone, Copy, ValueEnum)]
enum Enc {
    Hex,
    Base64url,
    Base32,
}

impl From<Enc> for SecretEncoding {
    fn from(e: Enc) -> Self {
        match e {
            Enc::Hex => SecretEncoding::Hex,
            Enc::Base64url => SecretEncoding::Base64Url,
            Enc::Base32 => SecretEncoding::Base32,
        }
    }
}

impl From<Profile> for PasswordProfile {
    fn from(p: Profile) -> Self {
        match p {
            Profile::Default => PasswordProfile::Default,
            Profile::Strong => PasswordProfile::Strong,
        }
    }
}

type R<T> = Result<T, Error>;

fn usage(msg: &str) -> Error {
    Error::Validation(msg.into())
}

fn provider() -> R<SyntheticDemoKeyProvider> {
    let hex = Zeroizing::new(std::env::var("KEYMESH_DEMO_KEY").map_err(|_| {
        Error::KeyProvider("set KEYMESH_DEMO_KEY to 64 hex chars (synthetic demo key)".into())
    })?);
    eprintln!("{BANNER}");
    SyntheticDemoKeyProvider::from_hex(&hex)
}

fn vault_path(cli: &Cli) -> R<PathBuf> {
    cli.vault
        .clone()
        .ok_or_else(|| usage("--vault (or KEYMESH_VAULT) is required"))
}

thread_local! {
    /// One buffered stdin for the whole run: credential lines first, then
    /// whatever else the command reads.
    static STDIN: RefCell<std::io::BufReader<std::io::Stdin>> =
        RefCell::new(std::io::BufReader::new(std::io::stdin()));
}

fn strip_eol(s: &str) -> &str {
    let s = s.strip_suffix('\n').unwrap_or(s);
    s.strip_suffix('\r').unwrap_or(s)
}

/// A password or recovery code: from the terminal without echo, or one line
/// of stdin with `--password-stdin`. Never from arguments or the environment.
fn read_credential(cli: &Cli, prompt: &str) -> R<Zeroizing<String>> {
    let value = if cli.password_stdin {
        let mut line = Zeroizing::new(String::new());
        STDIN.with(|s| s.borrow_mut().read_line(&mut line))?;
        Zeroizing::new(strip_eol(&line).to_owned())
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(usage(
                "no terminal for the password prompt; use --password-stdin",
            ));
        }
        Zeroizing::new(rpassword::prompt_password(prompt)?)
    };
    if value.is_empty() {
        return Err(usage("expected a password or recovery code"));
    }
    Ok(value)
}

/// A new master password, checked against the password rules (typed twice
/// on a terminal).
fn read_new_password(cli: &Cli) -> R<Zeroizing<String>> {
    let pw = read_credential(cli, "New master password: ")?;
    check_new_password(&pw)?;
    if !cli.password_stdin {
        let again = read_credential(cli, "Repeat new master password: ")?;
        if *again != *pw {
            return Err(usage("the passwords do not match"));
        }
    }
    Ok(pw)
}

fn read_recovery_code(cli: &Cli, prompt: &str) -> R<RecoveryCode> {
    RecoveryCode::parse(&read_credential(cli, prompt)?)
}

/// Show a new recovery code once, then require it to be typed back.
fn show_and_confirm_code(cli: &Cli, code: &RecoveryCode) -> R<RecoveryCode> {
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "Recovery code (shown once; store it offline, separate from this device):"
    )?;
    writeln!(out, "{}", code.to_text().as_str())?;
    out.flush()?;
    drop(out);
    let back = read_recovery_code(cli, "Type the recovery code to confirm: ")?;
    if !back.ct_eq(code) {
        return Err(usage(
            "the recovery code does not match; nothing was written",
        ));
    }
    Ok(back)
}

fn read_stdin_secret() -> R<SecretString> {
    let mut s = Zeroizing::new(String::new());
    STDIN.with(|i| i.borrow_mut().read_to_string(&mut s))?;
    let trimmed = strip_eol(&s);
    if trimmed.is_empty() {
        return Err(usage("expected a value on stdin"));
    }
    Ok(SecretString::new(trimmed))
}

/// An opened vault and how to save it again.
enum Opened {
    Demo(SyntheticDemoKeyProvider),
    Protected,
}

/// Open --vault with the unlock its file version needs.
fn open_vault(cli: &Cli, path: &std::path::Path) -> R<(Vault, Opened, Zeroizing<[u8; 32]>)> {
    let bytes = storage::read_envelope(path)?;
    if read_header(&bytes)?.version == 1 {
        let p = provider()?;
        let v = Vault::decrypt(&bytes, &p)?;
        return Ok((v, Opened::Demo(p), Zeroizing::new([0; 32])));
    }
    eprintln!("{EXPERIMENTAL}");
    let req = password_request(&bytes)?;
    let pw = read_credential(cli, "Master password: ")?;
    let key = req.setup.derive(&pw)?;
    let v = Vault::open_with_password_key(&bytes, &key)?;
    Ok((v, Opened::Protected, key))
}

fn save_vault(path: &std::path::Path, v: &mut Vault, how: &Opened) -> R<()> {
    match how {
        Opened::Demo(p) => storage::save(path, v, p, &mut OsRandom),
        Opened::Protected => storage::save_protected(path, v, &mut OsRandom),
    }
}

fn with_vault(cli: &Cli, f: impl FnOnce(&mut Vault) -> R<bool>) -> R<()> {
    let path = vault_path(cli)?;
    let (mut v, how, _key) = open_vault(cli, &path)?;
    if f(&mut v)? {
        save_vault(&path, &mut v, &how)?;
    }
    Ok(())
}

/// Opens the vault (reading the password first), then reads item input.
fn add_item(cli: &Cli, a: &AddCmd) -> R<()> {
    with_vault(cli, |v| {
        let (title, data) = build_item(a)?;
        let item = Item::new(title, data, &mut OsRandom)?;
        let id = v.insert(item)?;
        println!("{id}");
        Ok(true)
    })
}

const SECRET_KEYS: &[&str] = &[
    "password",
    "recovery_codes",
    "secret",
    "recovery_phrase",
    "wallet_password",
    "private_key",
    "seed",
    "body",
    "notes",
    "fingerprint",
];

fn redact(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if SECRET_KEYS.contains(&k.as_str()) && !val.is_null() {
                    *val = Value::String("<redacted>".into());
                } else if k == "custom_fields" {
                    if let Value::Array(a) = val {
                        for f in a {
                            if let Some(x) = f.get_mut("value") {
                                *x = Value::String("<redacted>".into());
                            }
                        }
                    }
                } else {
                    redact(val);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact),
        _ => {}
    }
}

fn run(cli: Cli) -> R<()> {
    match &cli.cmd {
        Cmd::Init { demo: true } => {
            let p = provider()?;
            let path = vault_path(&cli)?;
            let mut v = Vault::create(&p, &mut OsRandom)?;
            storage::create(&path, &mut v, &p, &mut OsRandom)?;
            println!("created vault {}", v.vault_id());
        }
        Cmd::Init { demo: false } => {
            let path = vault_path(&cli)?;
            if path.exists() {
                return Err(usage("vault file already exists"));
            }
            eprintln!("{EXPERIMENTAL}");
            let pw = read_new_password(&cli)?;
            let (mut v, code) = Vault::create_with_password(&pw, &mut OsRandom)?;
            let back = show_and_confirm_code(&cli, &code)?;
            v.confirm_recovery(&back)?;
            storage::create_protected(&path, &mut v, &mut OsRandom)?;
            println!("created vault {}", v.vault_id());
            println!("Without the password or the recovery code this vault cannot be opened.");
        }
        Cmd::Passwd { recovery } => {
            let path = vault_path(&cli)?;
            let bytes = storage::read_envelope(&path)?;
            eprintln!("{EXPERIMENTAL}");
            let (mut v, code, key) = if *recovery {
                let code = read_recovery_code(&cli, "Recovery code: ")?;
                (Vault::open_with_recovery(&bytes, &code)?, Some(code), None)
            } else {
                let req = password_request(&bytes)?;
                let pw = read_credential(&cli, "Current master password: ")?;
                let key = req.setup.derive(&pw)?;
                (
                    Vault::open_with_password_key(&bytes, &key)?,
                    None,
                    Some(key),
                )
            };
            let new_pw = read_new_password(&cli)?;
            let setup = PasswordSetup::generate(&mut OsRandom)?;
            let new_key = setup.derive(&new_pw)?;
            let authority = match (&code, &key) {
                (Some(c), _) => Authority::Recovery(c),
                (None, Some(k)) => Authority::PasswordKey(k),
                _ => unreachable!(),
            };
            v.change_password(authority, &setup, &new_key, &mut OsRandom)?;
            storage::save_protected(&path, &mut v, &mut OsRandom)?;
            println!("password changed");
            println!("Backups made before this change still open with the old password.");
        }
        Cmd::NewRecoveryCode => {
            let path = vault_path(&cli)?;
            let (mut v, how, key) = open_vault(&cli, &path)?;
            if !matches!(how, Opened::Protected) {
                return Err(usage("demo vaults have no recovery code"));
            }
            let pending = v.begin_recovery_change(Authority::PasswordKey(&key), &mut OsRandom)?;
            let code = RecoveryCode::parse(&pending.code().to_text())?;
            let back = show_and_confirm_code(&cli, &code)?;
            v.finish_recovery_change(pending, &back)?;
            storage::save_protected(&path, &mut v, &mut OsRandom)?;
            println!("recovery code replaced");
            println!("Backups made before this change still open with the old recovery code.");
        }
        Cmd::Recover { from, force } => {
            let dest = vault_path(&cli)?;
            if dest.exists() && !force {
                return Err(usage("--vault exists; pass --force to replace it"));
            }
            let bytes = storage::read_envelope(from)?;
            eprintln!("{EXPERIMENTAL}");
            let code = read_recovery_code(&cli, "Recovery code: ")?;
            let mut v = Vault::open_with_recovery(&bytes, &code)?;
            let new_pw = read_new_password(&cli)?;
            let setup = PasswordSetup::generate(&mut OsRandom)?;
            let new_key = setup.derive(&new_pw)?;
            v.change_password(Authority::Recovery(&code), &setup, &new_key, &mut OsRandom)?;
            storage::write_protected_to(&dest, &mut v, &mut OsRandom, *force)?;
            println!("recovered vault {} with a new password", v.vault_id());
        }
        Cmd::List => with_vault(&cli, |v| {
            for i in v.items() {
                println!("{}\t{}\t{}", i.id, i.kind().as_str(), i.title);
            }
            Ok(false)
        })?,
        Cmd::Show { id, reveal } => with_vault(&cli, |v| {
            let mut j = serde_json::to_value(v.get(id)?).map_err(|_| usage("serialize"))?;
            if !reveal {
                redact(&mut j);
            }
            let out =
                Zeroizing::new(serde_json::to_string_pretty(&j).map_err(|_| usage("serialize"))?);
            println!("{}", out.as_str());
            Ok(false)
        })?,
        Cmd::Add(a) => add_item(&cli, a)?,
        Cmd::Edit {
            id,
            title,
            add_tags,
            notes_stdin,
        } => with_vault(&cli, |v| {
            let notes = if *notes_stdin {
                Some(read_stdin_secret()?)
            } else {
                None
            };
            v.update(id, |it| {
                if let Some(t) = title {
                    it.title = t.clone();
                }
                it.tags.extend(add_tags.iter().cloned());
                if notes.is_some() {
                    it.notes = notes.clone();
                }
            })?;
            println!("updated {id}");
            Ok(true)
        })?,
        Cmd::Delete { id } => with_vault(&cli, |v| {
            v.remove(id)?;
            println!("deleted {id}");
            Ok(true)
        })?,
        Cmd::Totp { id, at } => with_vault(&cli, |v| {
            let ItemData::Totp(t) = &v.get(id)?.data else {
                return Err(usage("item is not a TOTP item"));
            };
            let c = match at {
                Some(ts) => code_now(&t.config, &FixedClock(*ts))?,
                None => code_now(&t.config, &SystemClock)?,
            };
            println!("{}\t{}s", c.code, c.seconds_remaining);
            Ok(false)
        })?,
        Cmd::Ed25519Public { id, openssh } => with_vault(&cli, |v| {
            let item = v.get(id)?;
            let ItemData::Ed25519Key(k) = &item.data else {
                return Err(usage("item is not an Ed25519 key"));
            };
            if *openssh {
                println!("{}", k.key.openssh_public_key(k.comment.as_deref())?);
            } else {
                println!("{}", k.key.public_key_hex);
            }
            Ok(false)
        })?,
        Cmd::Gen(g) => {
            let s = match g {
                GenCmd::Password {
                    profile,
                    length,
                    alphabet,
                } => {
                    let pol = match (length, alphabet) {
                        (Some(l), Some(a)) => PasswordPolicy::allowlist(*l, a)?,
                        _ => PasswordPolicy::profile((*profile).into()),
                    };
                    generate_password(&pol, &mut OsRandom)?
                }
                GenCmd::Secret { bytes, encoding } => {
                    generate_secret(*bytes, (*encoding).into(), &mut OsRandom)?
                }
                GenCmd::Passphrase => generate_passphrase()?,
            };
            println!("{}", s.expose());
        }
        Cmd::Backup { to } => {
            let path = vault_path(&cli)?;
            let bytes = storage::read_envelope(&path)?;
            if read_header(&bytes)?.version == 1 {
                storage::backup(&path, to, &provider()?)?;
            } else {
                // Verify the exact bytes open before copying them.
                let (_v, _, _) = open_vault(&cli, &path)?;
                if storage::read_envelope(&path)? != bytes {
                    return Err(usage("vault changed while the backup was verified"));
                }
                storage::write_backup(to, &bytes)?;
            }
            println!("backup written");
        }
        Cmd::Restore { from, force } => {
            let dest = vault_path(&cli)?;
            let bytes = storage::read_envelope(from)?;
            if read_header(&bytes)?.version == 1 {
                storage::restore(from, &dest, &provider()?, *force)?;
            } else {
                eprintln!("{EXPERIMENTAL}");
                let req = password_request(&bytes)?;
                let pw = read_credential(&cli, "Backup's master password: ")?;
                let key = req.setup.derive(&pw)?;
                Vault::open_with_password_key(&bytes, &key)?;
                storage::restore_verified(&bytes, &dest, *force)?;
            }
            println!("restored");
        }
        Cmd::ImportOp(a) => import_op(&cli, a)?,
    }
    Ok(())
}

fn build_item(a: &AddCmd) -> R<(String, ItemData)> {
    Ok(match a {
        AddCmd::Login {
            title,
            username,
            urls,
            generate,
            profile,
            password_stdin,
            totp_item,
        } => {
            let password = match (generate, password_stdin) {
                (true, true) => return Err(usage("use either --generate or --password-stdin")),
                (true, false) => Some(generate_password(
                    &PasswordPolicy::profile((*profile).into()),
                    &mut OsRandom,
                )?),
                (false, true) => Some(read_stdin_secret()?),
                (false, false) => None,
            };
            (
                title.clone(),
                ItemData::Login(Login {
                    username: username.clone(),
                    password,
                    urls: urls.clone(),
                    totp_item: totp_item.clone(),
                    recovery_codes: vec![],
                }),
            )
        }
        AddCmd::Secret {
            title,
            generate,
            bytes,
            encoding,
            service,
        } => {
            let (secret, format, origin) = if *generate {
                (
                    generate_secret(*bytes, (*encoding).into(), &mut OsRandom)?,
                    SecretFormat::Encoded((*encoding).into()),
                    SecretOrigin::Generated,
                )
            } else {
                (
                    read_stdin_secret()?,
                    SecretFormat::Text,
                    SecretOrigin::Manual,
                )
            };
            (
                title.clone(),
                ItemData::Secret(SecretCredential {
                    secret,
                    format,
                    origin,
                    username: None,
                    service: service.clone(),
                    expires_at: None,
                }),
            )
        }
        AddCmd::Note { title } => (
            title.clone(),
            ItemData::SecureNote(SecureNote {
                body: read_stdin_secret()?,
            }),
        ),
        AddCmd::Contact {
            title,
            name,
            organization,
            emails,
            phones,
            addresses,
        } => {
            let lv = |v: &Vec<String>| {
                v.iter()
                    .map(|s| LabeledValue::new(None, s.as_str()))
                    .collect()
            };
            (
                title.clone(),
                ItemData::Contact(Contact {
                    full_name: name.clone(),
                    organization: organization.clone(),
                    emails: lv(emails),
                    phones: lv(phones),
                    addresses: lv(addresses),
                    websites: vec![],
                }),
            )
        }
        AddCmd::Wallet {
            title,
            network,
            addresses,
            phrase_stdin,
        } => (
            title.clone(),
            ItemData::CryptoWallet(CryptoWalletRecord {
                network: network.clone(),
                addresses: addresses
                    .iter()
                    .map(|s| LabeledValue::new(None, s.as_str()))
                    .collect(),
                recovery_phrase: if *phrase_stdin {
                    Some(read_stdin_secret()?)
                } else {
                    None
                },
                ..Default::default()
            }),
        ),
        AddCmd::Totp {
            title,
            base32,
            issuer,
            account,
        } => {
            let input = read_stdin_secret()?;
            let rec = if *base32 {
                TotpRecord {
                    config: TotpConfig::with_defaults(parse_base32_secret(input.expose())?)?,
                    issuer: issuer.clone(),
                    account_name: account.clone(),
                }
            } else {
                let p = parse_otpauth_uri(input.expose())?;
                TotpRecord {
                    config: p.config,
                    issuer: issuer.clone().or(p.issuer),
                    account_name: account.clone().or(p.account_name),
                }
            };
            (title.clone(), ItemData::Totp(rec))
        }
        AddCmd::Ed25519 { title, comment } => (
            title.clone(),
            ItemData::Ed25519Key(Ed25519KeyRecord {
                key: Ed25519KeyPair::generate(&mut OsRandom)?,
                comment: comment.clone(),
            }),
        ),
    })
}

fn import_op(cli: &Cli, a: &ImportArgs) -> R<()> {
    let mut targets: Vec<OpTarget> = a
        .items
        .iter()
        .map(|i| OpTarget::Item {
            account: a.account.clone(),
            vault: a.op_vault.clone().unwrap_or_default(),
            item: i.clone(),
        })
        .collect();
    targets.extend(a.refs.iter().map(|r| OpTarget::Reference {
        account: a.account.clone(),
        reference: r.clone(),
    }));
    if !a.refs.is_empty() && a.account.is_none() {
        return Err(usage(
            "--ref requires --account (references are only unique within an account)",
        ));
    }
    if targets.is_empty() {
        return Err(usage(
            "specify --op-vault with --item, or --ref (no implicit enumeration)",
        ));
    }
    let path = vault_path(cli)?;
    // Open first: never fetch provider data if the vault cannot be opened.
    let (mut v, how, _key) = open_vault(cli, &path)?;
    let runner = ProcessOpRunner::with_program(
        a.op_path.clone().unwrap_or_else(|| PathBuf::from("op")),
        Duration::from_secs(a.timeout_secs),
    );
    let policy = if a.update {
        ConflictPolicy::Update
    } else {
        ConflictPolicy::Skip
    };
    let pl = plan(&runner, &targets);
    let report = match a.mode {
        Mode::Preview => pl.preview(&v, policy),
        Mode::Apply => {
            let r = pl.apply(&mut v, policy, &mut OsRandom);
            save_vault(&path, &mut v, &how)?;
            r
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|_| usage("serialize report"))?
    );
    if report.counts.failed > 0 {
        return Err(Error::Import(format!(
            "{} target(s) failed",
            report.counts.failed
        )));
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        // Exit 3: the file WAS replaced (the change is in effect) but its
        // durability is unconfirmed; distinct from ordinary failures (exit 1),
        // where a failed save left the vault file untouched.
        Err(e @ Error::DurabilityUncertain(_)) => {
            eprintln!("warning: {e}");
            ExitCode::from(3)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
