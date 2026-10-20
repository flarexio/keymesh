//! 1Password importer tests. SYNTHETIC FIXTURES ONLY: a fake in-process runner
//! and a fake `op` executable stand in for the real CLI. Nothing here contacts
//! 1Password or reads real data.

use keymesh::crypto::EphemeralKeyProvider;
use keymesh::import::op::{
    plan, ConflictPolicy, ImportErrorCode, ImportReport, ImportStatus, OpRunner, OpTarget,
    RunError, RunOutput,
};
use keymesh::model::{FieldKind, ItemData, ItemKind, SecretFormat};
use keymesh::rng::OsRandom;
use keymesh::storage;
use keymesh::totp::{code_at, parse_otpauth_uri};
use keymesh::vault::Vault;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/op")
            .join(name),
    )
    .unwrap()
}

/// Every synthetic secret value appearing in fixtures. None may leak into
/// reports.
const SECRETS: &[&str] = &[
    "SYNTH-PASSWORD",
    "SYNTH-NOTE",
    "SYNTH-PIN",
    "GEZDGNBVGY3TQOJQ",
    "999999",
    "SYNTH-WORDS",
    "SYNTH-WALLET-PASS",
    "SYNTH-API-TOKEN",
    "SYNTH-NOT-A-REAL-KEY",
    "SYNTH-STANDALONE-PW",
    "SYNTH-WIFI-PASS",
    "SYNTH-FUTURE",
    "SYNTH-STDERR-SECRET",
    "SYNTH-REF-VALUE",
    "Synthetic Example Login",
    "synthetic-user@example.test",
];

fn assert_no_leak(report: &ImportReport) {
    let j = serde_json::to_string(report).unwrap();
    for s in SECRETS {
        assert!(!j.contains(s), "report leaked {s}: {j}");
    }
    let d = format!("{report:?}");
    for s in SECRETS {
        assert!(!d.contains(s), "report Debug leaked {s}");
    }
}

type Responder = Box<dyn Fn(&[String]) -> Result<RunOutput, RunError>>;

/// In-process fake runner: records argv, answers via a closure.
struct FakeRunner {
    respond: Responder,
    calls: RefCell<Vec<Vec<String>>>,
}

impl FakeRunner {
    fn new(f: impl Fn(&[String]) -> Result<RunOutput, RunError> + 'static) -> Self {
        Self {
            respond: Box::new(f),
            calls: RefCell::new(vec![]),
        }
    }
    /// Serves `fixtures[item name]` for `op item get <name>`.
    fn items(map: &'static [(&'static str, &'static str)]) -> Self {
        Self::new(move |args| {
            let name = &args[2];
            match map.iter().find(|(n, _)| n == name) {
                Some((_, file)) => Ok(ok(fixture(file))),
                None => Ok(err(1, b"[ERROR] \"x\" isn't an item. SYNTH-STDERR-SECRET")),
            }
        })
    }
}

impl OpRunner for FakeRunner {
    fn run(&self, args: &[String]) -> Result<RunOutput, RunError> {
        self.calls.borrow_mut().push(args.to_vec());
        (self.respond)(args)
    }
}

fn ok(stdout: Vec<u8>) -> RunOutput {
    RunOutput {
        status: Some(0),
        stdout: Zeroizing::new(stdout),
        stderr: Zeroizing::new(vec![]),
    }
}

fn err(code: i32, stderr: &[u8]) -> RunOutput {
    RunOutput {
        status: Some(code),
        stdout: Zeroizing::new(vec![]),
        stderr: Zeroizing::new(stderr.to_vec()),
    }
}

fn item(name: &str) -> OpTarget {
    OpTarget::Item {
        account: None,
        vault: "Synthetic Vault".into(),
        item: name.into(),
    }
}

fn new_vault() -> (EphemeralKeyProvider, Vault) {
    let p = EphemeralKeyProvider::generate("test-ephemeral", &mut OsRandom).unwrap();
    let v = Vault::create(&p, &mut OsRandom).unwrap();
    (p, v)
}

const ALL: &[(&str, &str)] = &[
    ("login", "login.json"),
    ("identity", "identity.json"),
    ("wallet", "wallet.json"),
    ("api", "api.json"),
    ("ssh", "sshkey.json"),
    ("note", "note.json"),
    ("password", "password.json"),
    ("router", "router.json"),
    ("document", "document.json"),
    ("malformed", "malformed.json"),
    ("missing-id", "missing-id.json"),
];

#[test]
fn exact_argument_vectors_and_no_enumeration() {
    let t = OpTarget::Item {
        account: Some("synthetic.example.test".into()),
        vault: "Synthetic Vault".into(),
        item: "login".into(),
    };
    assert_eq!(
        t.args().unwrap(),
        [
            "item",
            "get",
            "login",
            "--vault=Synthetic Vault",
            "--format=json",
            "--reveal",
            "--account=synthetic.example.test"
        ]
    );
    let r = OpTarget::Reference {
        account: None,
        reference: "op://Synthetic Vault/Item/credential".into(),
    };
    assert_eq!(
        r.args().unwrap(),
        [
            "read",
            "--no-newline",
            "op://Synthetic Vault/Item/credential"
        ]
    );
    let runner = FakeRunner::items(ALL);
    let _ = plan(&runner, &[item("login"), r.clone()]);
    let calls = runner.calls.borrow();
    assert_eq!(calls.len(), 2, "one call per explicit target, nothing else");
    for c in calls.iter() {
        assert!(!c
            .iter()
            .any(|a| a == "list" || a == "whoami" || a == "--otp"));
    }
}

#[test]
fn rejects_option_injection_and_unsafe_references() {
    for bad in [
        item("-"),
        item("--help"),
        item(""),
        item("bad\nname"),
        OpTarget::Item {
            account: None,
            vault: "v\0".into(),
            item: "x".into(),
        },
        OpTarget::Reference {
            account: None,
            reference: "op://v/i/one-time password?attribute=otp".into(),
        },
        OpTarget::Reference {
            account: None,
            reference: "op://v/i".into(),
        },
        OpTarget::Reference {
            account: None,
            reference: "https://v/i/f".into(),
        },
        OpTarget::Reference {
            account: None,
            reference: "op://v//f".into(),
        },
    ] {
        let runner = FakeRunner::items(ALL);
        let (_p, v) = new_vault();
        let rep = plan(&runner, std::slice::from_ref(&bad)).preview(&v, ConflictPolicy::Skip);
        assert_eq!(rep.entries[0].status, ImportStatus::Failed, "{bad:?}");
        assert_eq!(rep.entries[0].error, Some(ImportErrorCode::InvalidTarget));
        assert!(
            runner.calls.borrow().is_empty(),
            "runner must not be invoked"
        );
    }
}

#[test]
fn maps_every_category_and_round_trips_through_encrypted_store() {
    let runner = FakeRunner::items(ALL);
    let targets: Vec<_> = [
        "login", "identity", "wallet", "api", "ssh", "note", "password", "router", "document",
    ]
    .into_iter()
    .map(item)
    .collect();
    let (p, mut v) = new_vault();
    let pl = plan(&runner, &targets);

    let preview = pl.preview(&v, ConflictPolicy::Skip);
    assert!(!preview.applied);
    assert_eq!(preview.counts.created, 9); // 8 items + 1 TOTP
    assert!(v.is_empty(), "preview must not modify the vault");
    assert_no_leak(&preview);

    let rep = pl.apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
    assert_no_leak(&rep);
    assert!(rep.applied);
    assert_eq!(rep.counts.targets, 9);
    assert_eq!(rep.counts.created, 9);
    assert_eq!(rep.counts.unsupported, 1);
    assert_eq!(rep.counts.failed, 0);
    let doc = rep
        .entries
        .iter()
        .find(|e| e.source_id.ends_with("synthdocitem000000000000a9"))
        .unwrap();
    assert_eq!(doc.status, ImportStatus::Unsupported);
    let login_entry = &rep.entries[0];
    assert_eq!(
        login_entry.source_id,
        "1password:item:synthvault000000000000000v1/synthloginitem0000000000a1"
    );
    assert!(login_entry
        .warnings
        .contains(&"attachments_not_imported:1".to_string()));
    assert!(login_entry
        .warnings
        .contains(&"empty_fields_skipped:1".to_string()));
    assert!(login_entry
        .warnings
        .contains(&"invalid_url_skipped".to_string()));

    // Persist encrypted, reload, verify content.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("import.keymesh");
    storage::create(&path, &mut v, &p, &mut OsRandom).unwrap();
    let raw = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
    for s in SECRETS {
        assert!(!raw.contains(s), "vault file leaked {s}");
    }
    let v = storage::load(&path, &p).unwrap();
    assert_eq!(v.len(), 9);

    let by_kind = |k: ItemKind| v.items().filter(move |i| i.kind() == k).collect::<Vec<_>>();
    // Login + linked TOTP with provisioning secret, not the ephemeral code.
    let login = by_kind(ItemKind::Login)[0];
    let totp = by_kind(ItemKind::Totp)[0];
    let ItemData::Login(l) = &login.data else {
        panic!()
    };
    assert_eq!(l.username.as_deref(), Some("synthetic-user@example.test"));
    assert_eq!(l.password.as_ref().unwrap().expose(), "SYNTH-PASSWORD-Zq9!");
    assert_eq!(l.urls, ["https://login.example.test/"]);
    assert_eq!(l.totp_item.as_ref(), Some(&totp.id));
    assert_eq!(
        login.notes.as_ref().unwrap().expose(),
        "SYNTH-NOTE-login notes"
    );
    assert_eq!(login.tags, ["synthetic", "fixture"]);
    let pin = login
        .custom_fields
        .iter()
        .find(|f| f.label == "backup pin")
        .unwrap();
    assert_eq!(pin.kind, FieldKind::Concealed);
    assert_eq!(pin.section.as_deref(), Some("Security"));
    assert_eq!(pin.value.expose(), "SYNTH-PIN-4321");
    assert!(login
        .custom_fields
        .iter()
        .any(|f| f.label == "plan" && f.kind == FieldKind::Text));
    let ItemData::Totp(t) = &totp.data else {
        panic!()
    };
    let expected = parse_otpauth_uri(
        "otpauth://totp/Example:x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example",
    )
    .unwrap();
    assert_eq!(t.config, expected.config);
    assert_eq!(t.issuer.as_deref(), Some("Example"));
    assert_eq!(code_at(&t.config, 59).unwrap(), "287082"); // RFC 6238 SHA1 vector, 6 digits

    // Contact with multi-value fields; invalid email preserved as custom.
    let ItemData::Contact(c) = &by_kind(ItemKind::Contact)[0].data else {
        panic!()
    };
    assert_eq!(c.full_name.as_deref(), Some("Ada Synthetic"));
    assert_eq!(c.organization.as_deref(), Some("Example Org"));
    assert_eq!(c.emails.len(), 2);
    assert_eq!(c.phones.len(), 2);
    assert_eq!(c.addresses.len(), 1);
    assert!(c.addresses[0].value.contains("1 Synthetic Way"));
    assert_eq!(c.websites.len(), 1);
    let contact = by_kind(ItemKind::Contact)[0];
    assert!(contact
        .custom_fields
        .iter()
        .any(|f| f.value.expose() == "not-an-email"));
    assert!(contact
        .custom_fields
        .iter()
        .any(|f| f.kind == FieldKind::Date));

    let ItemData::CryptoWallet(w) = &by_kind(ItemKind::CryptoWallet)[0].data else {
        panic!()
    };
    assert!(w
        .recovery_phrase
        .as_ref()
        .unwrap()
        .expose()
        .starts_with("SYNTH-WORDS"));
    assert_eq!(
        w.wallet_password.as_ref().unwrap().expose(),
        "SYNTH-WALLET-PASS"
    );
    assert_eq!(w.addresses[0].value, "synthetic-address-0001");
    assert_eq!(w.network.as_deref(), Some("synthetic-testnet"));

    let secrets = by_kind(ItemKind::Secret);
    assert_eq!(secrets.len(), 3); // api, ssh (opaque), password
    let ssh = secrets
        .iter()
        .find(|s| matches!(&s.data, ItemData::Secret(c) if c.format == SecretFormat::OpaquePrivateKey))
        .unwrap();
    assert!(ssh.custom_fields.iter().any(|f| f.label == "public key"));
    assert!(
        by_kind(ItemKind::Ed25519Key).is_empty(),
        "SSH keys are never claimed as Ed25519"
    );
    let api = secrets
        .iter()
        .find(|s| matches!(&s.data, ItemData::Secret(c) if c.username.as_deref() == Some("svc-synthetic")))
        .unwrap();
    let ItemData::Secret(ac) = &api.data else {
        panic!()
    };
    assert_eq!(ac.secret.expose(), "SYNTH-API-TOKEN-0000");
    assert_eq!(ac.service.as_deref(), Some("api.example.test"));

    // Unknown category preserved field-by-field as an encrypted generic note.
    let notes = by_kind(ItemKind::SecureNote);
    assert_eq!(notes.len(), 2);
    let router = notes
        .iter()
        .find(|n| n.title == "Synthetic Router")
        .unwrap();
    assert_eq!(router.custom_fields.len(), 3);
    let fut = router
        .custom_fields
        .iter()
        .find(|f| f.label == "future")
        .unwrap();
    assert_eq!(fut.kind, FieldKind::Unsupported);
    assert_eq!(fut.source_type.as_deref(), Some("SOME_FUTURE_TYPE"));
    assert_eq!(fut.value.expose(), "SYNTH-FUTURE");
}

#[test]
fn partial_failure_and_error_classification() {
    let runner = FakeRunner::new(|args| {
        Ok(match args[2].as_str() {
            "login" => ok(fixture("login.json")),
            "unauth" => err(
                1,
                b"[ERROR] You are not currently signed in. SYNTH-STDERR-SECRET",
            ),
            "missing" => err(1, b"[ERROR] \"missing\" isn't an item. SYNTH-STDERR-SECRET"),
            "weird" => err(2, b"SYNTH-STDERR-SECRET boom"),
            "malformed" => ok(fixture("malformed.json")),
            "missing-id" => ok(fixture("missing-id.json")),
            "binary" => ok(vec![0xff, 0xfe, 0x00]),
            "timeout" => return Err(RunError::Timeout),
            "toolarge" => return Err(RunError::OutputTooLarge),
            "noop" => return Err(RunError::MissingOp),
            _ => unreachable!(),
        })
    });
    let names = [
        "login",
        "unauth",
        "missing",
        "weird",
        "malformed",
        "missing-id",
        "binary",
        "timeout",
        "toolarge",
        "noop",
    ];
    let (_p, mut v) = new_vault();
    let rep = plan(&runner, &names.map(item)).apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
    assert_no_leak(&rep);
    let codes: Vec<_> = rep.entries.iter().map(|e| e.error).collect();
    use ImportErrorCode::*;
    assert_eq!(
        codes,
        [
            None,
            Some(Unauthenticated),
            Some(NotFound),
            Some(NonZeroExit),
            Some(MalformedOutput),
            Some(MalformedOutput),
            Some(MalformedOutput),
            Some(Timeout),
            Some(OutputTooLarge),
            Some(MissingOp)
        ]
    );
    assert_eq!(rep.counts.failed, 9);
    assert_eq!(rep.counts.created, 2);
    assert_eq!(v.len(), 2, "successful entries still applied");
    assert_eq!(rep.entries[1].source_id, "target:1");
}

#[test]
fn idempotent_reimport_conflicts_and_updates() {
    let (_p, mut v) = new_vault();
    let r1 = FakeRunner::items(ALL);
    let rep = plan(&r1, &[item("login"), item("login")]).apply(
        &mut v,
        ConflictPolicy::Skip,
        &mut OsRandom,
    );
    assert_eq!(rep.entries[1].status, ImportStatus::DuplicateInRun);
    assert_eq!(rep.counts.duplicates_in_run, 1);
    assert_eq!(v.len(), 2);

    // Same content again: unchanged, nothing new.
    let rep = plan(&r1, &[item("login")]).apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
    assert_eq!(rep.entries[0].status, ImportStatus::UnchangedDuplicate);
    assert_eq!(rep.counts.unchanged, 2);
    assert_eq!(v.len(), 2);

    // Source changed: conflict by default, nothing overwritten.
    let changed = FakeRunner::new(|_| {
        let s = String::from_utf8(fixture("login.json")).unwrap();
        Ok(ok(s
            .replace("SYNTH-PASSWORD-Zq9!", "SYNTH-PASSWORD-rotated")
            .into_bytes()))
    });
    let pl = plan(&changed, &[item("login")]);
    let pre = pl.preview(&v, ConflictPolicy::Skip);
    assert_eq!(pre.entries[0].status, ImportStatus::Conflict);
    let rep = pl.apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
    assert_eq!(rep.entries[0].status, ImportStatus::Conflict);
    let pw = |v: &Vault| {
        v.items()
            .find_map(|i| match &i.data {
                ItemData::Login(l) => Some(l.password.as_ref().unwrap().expose().to_owned()),
                _ => None,
            })
            .unwrap()
    };
    assert_eq!(pw(&v), "SYNTH-PASSWORD-Zq9!");

    // Explicit update policy applies it; login stays linked to its TOTP.
    assert_eq!(
        pl.preview(&v, ConflictPolicy::Update).entries[0].status,
        ImportStatus::WouldUpdate
    );
    let rep = pl.apply(&mut v, ConflictPolicy::Update, &mut OsRandom);
    assert_no_leak(&rep);
    assert_eq!(rep.entries[0].status, ImportStatus::Updated);
    assert_eq!(pw(&v), "SYNTH-PASSWORD-rotated");
    assert_eq!(v.len(), 2);
    let login = v.items().find(|i| i.kind() == ItemKind::Login).unwrap();
    assert_eq!(login.rev, 2);
    let ItemData::Login(l) = &login.data else {
        panic!()
    };
    assert!(l.totp_item.is_some());
}

#[test]
fn reference_import_uses_op_read() {
    let runner = FakeRunner::new(|args| {
        assert_eq!(args[0], "read");
        Ok(ok(b"SYNTH-REF-VALUE".to_vec()))
    });
    let t = OpTarget::Reference {
        account: None,
        reference: "op://Synthetic Vault/Item/credential".into(),
    };
    let (_p, mut v) = new_vault();
    let rep =
        plan(&runner, std::slice::from_ref(&t)).apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
    assert_no_leak(&rep);
    assert!(rep.entries[0].source_id.starts_with("1password:ref:"));
    assert_eq!(rep.counts.created, 1);
    let it = v.items().next().unwrap();
    let ItemData::Secret(s) = &it.data else {
        panic!()
    };
    assert_eq!(s.secret.expose(), "SYNTH-REF-VALUE");
    // Idempotent on the same reference.
    let rep = plan(&runner, &[t]).apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
    assert_eq!(rep.entries[0].status, ImportStatus::UnchangedDuplicate);
}

// --- Fake executable through the real process runner ----------------------

#[cfg(unix)]
mod process {
    use super::*;
    use keymesh::import::process::ProcessOpRunner;
    use std::time::{Duration, Instant};

    struct Env {
        dir: tempfile::TempDir,
        args_file: PathBuf,
    }

    /// Creates a wrapper that sets the fake mode and execs the fake `op`.
    fn fake_op(mode: &str, extra: &[(&str, &str)]) -> (Env, ProcessOpRunner) {
        let dir = tempfile::tempdir().unwrap();
        let args_file = dir.path().join("args.txt");
        let fake = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-op");
        let mut script = format!(
            "#!/bin/sh\nFAKE_OP_MODE='{mode}' FAKE_OP_ARGS_FILE='{}' ",
            args_file.display()
        );
        for (k, v) in extra {
            script.push_str(&format!("{k}='{v}' "));
        }
        script.push_str(&format!("exec '{}' \"$@\"\n", fake.display()));
        let wrapper = dir.path().join("op");
        std::fs::write(&wrapper, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runner = ProcessOpRunner::with_program(&wrapper, Duration::from_secs(10));
        (Env { dir, args_file }, runner)
    }

    #[test]
    fn success_through_fake_executable() {
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/op/login.json");
        let (env, runner) = fake_op("ok", &[("FAKE_OP_FIXTURE", fx.to_str().unwrap())]);
        let (_p, mut v) = new_vault();
        let rep =
            plan(&runner, &[item("login")]).apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
        assert_no_leak(&rep);
        assert_eq!(rep.counts.created, 2);
        let args = std::fs::read_to_string(&env.args_file).unwrap();
        assert_eq!(
            args,
            "item\nget\nlogin\n--vault=Synthetic Vault\n--format=json\n--reveal\n"
        );
    }

    #[test]
    fn shell_metacharacters_are_passed_verbatim() {
        let (env, runner) = fake_op("notfound", &[]);
        let marker = env.dir.path().join("PWNED");
        let evil = format!(
            "$(touch {m}); `touch PWNED2` | touch PWNED3 && echo $HOME > x; '\"*",
            m = marker.display()
        );
        assert!(evil.len() <= 512);
        let t = OpTarget::Item {
            account: Some("acct;touch x".into()),
            vault: "v$(id)|&".into(),
            item: evil.clone(),
        };
        let (_p, v) = new_vault();
        let rep = plan(&runner, &[t]).preview(&v, ConflictPolicy::Skip);
        assert_no_leak(&rep);
        assert_eq!(rep.entries[0].error, Some(ImportErrorCode::NotFound));
        assert!(!marker.exists(), "metacharacters must not be interpreted");
        let args: Vec<String> = std::fs::read_to_string(&env.args_file)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(args[2], evil);
        assert_eq!(args[3], "--vault=v$(id)|&");
        assert_eq!(args[6], "--account=acct;touch x");
        // Report must not echo provider/command data either.
        let j = serde_json::to_string(&rep).unwrap();
        assert!(!j.contains("PWNED") && !j.contains("touch"));
    }

    #[test]
    fn unauthenticated_and_nonzero_exit() {
        for (mode, code) in [
            ("unauth", ImportErrorCode::Unauthenticated),
            ("nonzero", ImportErrorCode::NonZeroExit),
        ] {
            let (_env, runner) = fake_op(mode, &[]);
            let (_p, v) = new_vault();
            let rep = plan(&runner, &[item("x")]).preview(&v, ConflictPolicy::Skip);
            assert_no_leak(&rep);
            assert_eq!(rep.entries[0].error, Some(code));
        }
    }

    #[test]
    fn missing_op_executable() {
        let dir = tempfile::tempdir().unwrap();
        let runner =
            ProcessOpRunner::with_program(dir.path().join("no-such-op"), Duration::from_secs(5));
        let (_p, v) = new_vault();
        let rep = plan(&runner, &[item("x")]).preview(&v, ConflictPolicy::Skip);
        assert_eq!(rep.entries[0].error, Some(ImportErrorCode::MissingOp));
    }

    #[test]
    fn timeout_kills_child() {
        let (_env, mut runner) = fake_op("sleep", &[]);
        runner.timeout = Duration::from_millis(300);
        let (_p, v) = new_vault();
        let start = Instant::now();
        let rep = plan(&runner, &[item("x")]).preview(&v, ConflictPolicy::Skip);
        assert_eq!(rep.entries[0].error, Some(ImportErrorCode::Timeout));
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn reference_value_through_fake_executable() {
        let (env, runner) = fake_op("value", &[("FAKE_OP_VALUE", "SYNTH-REF-VALUE")]);
        let (_p, mut v) = new_vault();
        let t = OpTarget::Reference {
            account: None,
            reference: "op://Synthetic Vault/Item/credential".into(),
        };
        let rep = plan(&runner, &[t]).apply(&mut v, ConflictPolicy::Skip, &mut OsRandom);
        assert_no_leak(&rep);
        assert_eq!(rep.counts.created, 1);
        assert_eq!(
            std::fs::read_to_string(&env.args_file).unwrap(),
            "read\n--no-newline\nop://Synthetic Vault/Item/credential\n"
        );
    }
}
