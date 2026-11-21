//! CLI smoke tests against the real `keymesh` binary. SYNTHETIC DATA ONLY:
//! the demo key is random per test and `op` is a fake executable.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Ctx {
    dir: tempfile::TempDir,
    key: String,
}

impl Ctx {
    fn new() -> Self {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).unwrap();
        Self {
            dir: tempfile::tempdir().unwrap(),
            key: data_encoding::HEXLOWER.encode(&k),
        }
    }
    fn vault(&self) -> PathBuf {
        self.dir.path().join("demo.keymesh")
    }
    fn cmd_with_key(&self, key: Option<&str>, args: &[&str], stdin: Option<&str>) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_keymesh"));
        c.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .arg("--vault")
            .arg(self.vault())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(k) = key {
            c.env("KEYMESH_DEMO_KEY", k);
        }
        let mut child = c.spawn().unwrap();
        {
            let mut si = child.stdin.take().unwrap();
            if let Some(s) = stdin {
                si.write_all(s.as_bytes()).unwrap();
            }
        }
        child.wait_with_output().unwrap()
    }
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.cmd_with_key(Some(&self.key), args, stdin)
    }
    fn ok(&self, args: &[&str], stdin: Option<&str>) -> String {
        let o = self.run(args, stdin);
        assert!(
            o.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }
}

#[test]
fn generators() {
    let c = Ctx::new();
    assert_eq!(
        c.ok(&["gen", "password"], None).trim_end().chars().count(),
        24
    );
    assert_eq!(
        c.ok(&["gen", "password", "--profile", "strong"], None)
            .trim_end()
            .chars()
            .count(),
        32
    );
    let custom = c.ok(
        &[
            "gen",
            "password",
            "--length",
            "40",
            "--alphabet",
            "abcdef0123",
        ],
        None,
    );
    assert!(custom
        .trim_end()
        .chars()
        .all(|ch| "abcdef0123".contains(ch)));
    assert!(!c
        .run(
            &["gen", "password", "--length", "4", "--alphabet", "ab"],
            None
        )
        .status
        .success());
    let hex = c.ok(&["gen", "secret"], None);
    assert_eq!(hex.trim_end().len(), 64);
    let b32 = c.ok(&["gen", "secret", "--encoding", "base32"], None);
    assert!(b32
        .trim_end()
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ('2'..='7').contains(&ch)));
    let p = c.ok(&["gen", "passphrase"], None);
    assert_eq!(p.trim_end().split(' ').count(), 6);
    let p = c.ok(
        &["gen", "passphrase", "--words", "8", "--separator", "period"],
        None,
    );
    assert_eq!(p.trim_end().split('.').count(), 8);
    let o = c.run(&["gen", "passphrase", "--words", "3"], None);
    assert!(!o.status.success());
    let o = c.run(&["gen", "passphrase", "--words", "5"], None);
    assert!(String::from_utf8_lossy(&o.stderr).contains("too few words"));
}

#[test]
fn vault_lifecycle_end_to_end() {
    let c = Ctx::new();
    // No key: refuses.
    assert!(!c
        .cmd_with_key(None, &["init", "--demo"], None)
        .status
        .success());
    let o = c.run(&["init", "--demo"], None);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("SYNTHETIC DEMO"));
    assert!(
        !c.run(&["init", "--demo"], None).status.success(),
        "init must not overwrite"
    );
    assert_eq!(c.ok(&["list"], None), "");

    let login = c.ok(
        &[
            "add",
            "login",
            "--title",
            "Synthetic Login",
            "--username",
            "synthetic-user",
            "--url",
            "https://example.test",
            "--generate",
            "--profile",
            "strong",
        ],
        None,
    );
    let login = login.trim();
    let totp = c.ok(
        &["add", "totp", "--title", "Synthetic TOTP"],
        Some("otpauth://totp/Example:synthetic?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=8\n"),
    );
    let totp = totp.trim();
    assert_eq!(c.ok(&["totp", totp, "--at", "59"], None), "94287082\t1s\n");
    assert_eq!(
        c.ok(&["totp", totp, "--at", "1111111109"], None),
        "07081804\t1s\n"
    );
    let b32 = c.ok(
        &["add", "totp", "--title", "Manual", "--base32"],
        Some("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"),
    );
    assert_eq!(
        c.ok(&["totp", b32.trim(), "--at", "59"], None),
        "287082\t1s\n"
    );
    assert!(!c
        .run(
            &["add", "totp", "--title", "H"],
            Some("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1")
        )
        .status
        .success());

    let key = c.ok(
        &[
            "add",
            "ed25519",
            "--title",
            "Synthetic Key",
            "--comment",
            "synthetic@test",
        ],
        None,
    );
    let pubhex = c.ok(&["ed25519-public", key.trim()], None);
    assert_eq!(pubhex.trim().len(), 64);
    let ssh = c.ok(&["ed25519-public", key.trim(), "--openssh"], None);
    assert!(
        ssh.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
            && ssh.trim_end().ends_with("synthetic@test")
    );

    let note = c.ok(
        &["add", "note", "--title", "SYNTH-TITLE-NOTE"],
        Some("SYNTH-NOTE-BODY-123\n"),
    );
    c.ok(
        &[
            "add",
            "contact",
            "--title",
            "Synthetic Contact",
            "--name",
            "Ada",
            "--email",
            "a@example.test",
            "--email",
            "b@example.test",
            "--phone",
            "+1 555 0100",
        ],
        None,
    );
    assert!(!c
        .run(
            &["add", "contact", "--title", "Bad", "--email", "nope"],
            None
        )
        .status
        .success());
    c.ok(
        &[
            "add",
            "wallet",
            "--title",
            "Synthetic Wallet",
            "--network",
            "testnet",
            "--address",
            "synthetic-addr",
            "--phrase-stdin",
        ],
        Some("SYNTH-WORDS one two three"),
    );
    c.ok(
        &[
            "add",
            "secret",
            "--title",
            "Synthetic API",
            "--generate",
            "--encoding",
            "base64url",
        ],
        None,
    );

    // Link login -> TOTP is validated.
    c.ok(
        &[
            "add",
            "login",
            "--title",
            "Linked",
            "--totp-item",
            totp,
            "--password-stdin",
        ],
        Some("SYNTH-PW-LINKED"),
    );
    assert!(!c
        .run(
            &[
                "add",
                "login",
                "--title",
                "BadLink",
                "--totp-item",
                note.trim()
            ],
            None
        )
        .status
        .success());

    let list = c.ok(&["list"], None);
    assert_eq!(list.lines().count(), 9);
    for kind in [
        "login",
        "totp",
        "ed25519_key",
        "secure_note",
        "contact",
        "crypto_wallet",
        "secret",
    ] {
        assert!(list.contains(&format!("\t{kind}\t")), "{kind}");
    }

    // Redacted by default; reveal on request.
    let shown = c.ok(&["show", note.trim()], None);
    assert!(!shown.contains("SYNTH-NOTE-BODY-123") && shown.contains("<redacted>"));
    assert!(c
        .ok(&["show", note.trim(), "--reveal"], None)
        .contains("SYNTH-NOTE-BODY-123"));
    let shown = c.ok(&["show", login], None);
    assert!(shown.contains("synthetic-user") && shown.contains("<redacted>"));

    // Ciphertext at rest: no titles, bodies or secrets in the file.
    let raw = std::fs::read_to_string(c.vault()).unwrap();
    for s in [
        "SYNTH-NOTE-BODY",
        "SYNTH-TITLE-NOTE",
        "SYNTH-WORDS",
        "SYNTH-PW-LINKED",
        "GEZDGNBV",
        "synthetic-user",
        "example.test",
    ] {
        assert!(!raw.contains(s), "plaintext {s} in vault file");
    }

    // Edit.
    c.ok(
        &[
            "edit",
            note.trim(),
            "--title",
            "Renamed Note",
            "--add-tag",
            "t1",
        ],
        None,
    );
    assert!(c.ok(&["list"], None).contains("Renamed Note"));
    // Deleting a TOTP referenced by a login is refused.
    assert!(!c.run(&["delete", totp], None).status.success());

    // Backup / restore round-trip.
    let bak = c.dir.path().join("demo.bak");
    c.ok(&["backup", "--to", bak.to_str().unwrap()], None);
    let restored = c.dir.path().join("restored.keymesh");
    let o = Command::new(env!("CARGO_BIN_EXE_keymesh"))
        .env_clear()
        .env("KEYMESH_DEMO_KEY", &c.key)
        .args([
            "--vault",
            restored.to_str().unwrap(),
            "restore",
            "--from",
            bak.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(
        std::fs::read(&restored).unwrap(),
        std::fs::read(&bak).unwrap()
    );

    // Wrong key fails closed and never rewrites the vault.
    let before = std::fs::read(c.vault()).unwrap();
    let wrong = "11".repeat(32);
    let o = c.cmd_with_key(Some(&wrong), &["list"], None);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("decryption failed"));
    assert!(!c
        .cmd_with_key(Some(&wrong), &["add", "note", "--title", "x"], Some("y"))
        .status
        .success());
    assert!(!c
        .cmd_with_key(Some(&wrong), &["init", "--demo"], None)
        .status
        .success());
    assert_eq!(std::fs::read(c.vault()).unwrap(), before);

    // Corrupted / truncated vault fails closed and is left untouched.
    std::fs::write(c.vault(), &before[..before.len() / 2]).unwrap();
    assert!(!c.run(&["list"], None).status.success());
    assert!(!c
        .run(&["add", "note", "--title", "x"], Some("y"))
        .status
        .success());
    assert_eq!(std::fs::read(c.vault()).unwrap().len(), before.len() / 2);
    // Restore refuses to clobber without --force, then recovers.
    assert!(!c
        .run(&["restore", "--from", bak.to_str().unwrap()], None)
        .status
        .success());
    c.ok(
        &["restore", "--from", bak.to_str().unwrap(), "--force"],
        None,
    );
    assert_eq!(c.ok(&["list"], None).lines().count(), 9);
}

#[cfg(unix)]
fn fake_op_wrapper(dir: &Path, fixture: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = format!(
        "#!/bin/sh\nFAKE_OP_MODE=ok FAKE_OP_FIXTURE='{}' exec '{}' \"$@\"\n",
        root.join("tests/fixtures/op").join(fixture).display(),
        root.join("tests/fixtures/fake-op").display()
    );
    let p = dir.join("op");
    std::fs::write(&p, script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}

#[cfg(unix)]
#[test]
fn import_op_preview_apply_idempotent() {
    let c = Ctx::new();
    c.ok(&["init", "--demo"], None);
    let op = fake_op_wrapper(c.dir.path(), "login.json");
    let op = op.to_str().unwrap();
    let before = std::fs::read(c.vault()).unwrap();
    // Missing targets: refuses rather than enumerating.
    assert!(!c
        .run(&["import-op", "--op-path", op], None)
        .status
        .success());

    let args = [
        "import-op",
        "preview",
        "--op-path",
        op,
        "--op-vault",
        "Synthetic Vault",
        "--item",
        "login",
    ];
    let preview = c.ok(&args, None);
    assert!(preview.contains("\"would_create\""));
    assert_eq!(
        std::fs::read(c.vault()).unwrap(),
        before,
        "preview must not write"
    );

    let mut apply = args;
    apply[1] = "apply";
    let rep = c.ok(&apply, None);
    assert!(rep.contains("\"created\": 2"));
    for s in [
        "SYNTH-PASSWORD",
        "SYNTH-NOTE",
        "GEZDGNBV",
        "999999",
        "Synthetic Example Login",
    ] {
        assert!(!rep.contains(s), "report leaked {s}");
    }
    assert_eq!(c.ok(&["list"], None).lines().count(), 2);
    let again = c.ok(&apply, None);
    assert!(again.contains("\"unchanged\": 2"));
    assert_eq!(c.ok(&["list"], None).lines().count(), 2);

    // Missing op executable: per-target failure, nonzero exit, vault intact.
    let o = c.run(
        &[
            "import-op",
            "apply",
            "--op-path",
            "/nonexistent/op",
            "--op-vault",
            "v",
            "--item",
            "x",
        ],
        None,
    );
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("missing_op"));
    assert_eq!(c.ok(&["list"], None).lines().count(), 2);
}
