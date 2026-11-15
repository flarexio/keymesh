//! Password-vault (envelope v2) flows against the real `keymesh` binary,
//! one process per command (so every step is a restart). SYNTHETIC DATA
//! ONLY. Credentials go through stdin (`--password-stdin`), never argv, and
//! the tests never print them.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const PW: &str = "synthetic cli passphrase one";
const PW2: &str = "synthetic cli passphrase two";
const PW3: &str = "synthetic cli passphrase three";

struct Ctx {
    dir: tempfile::TempDir,
}

fn cmd(vault: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_keymesh"));
    c.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .arg("--password-stdin")
        .arg("--vault")
        .arg(vault)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

impl Ctx {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run_at(&self, vault: &Path, args: &[&str], stdin: &str) -> Output {
        let mut child = cmd(vault).args(args).spawn().unwrap();
        // A command that refuses early (e.g. a demo vault given to a
        // password command) may exit before reading stdin; the closed pipe
        // is then expected. Callers assert on the exit status and output.
        match child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            Err(e) => panic!("writing stdin: {e}"),
        }
        child.wait_with_output().unwrap()
    }

    fn ok_at(&self, vault: &Path, args: &[&str], stdin: &str) -> String {
        let o = self.run_at(vault, args, stdin);
        assert!(
            o.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }

    /// Run a command that shows a new recovery code: send `before` lines,
    /// read the code from stdout, then send it back (or `confirm` instead).
    /// Returns (output, code shown).
    fn with_code(
        &self,
        vault: &Path,
        args: &[&str],
        before: &str,
        confirm: Option<&str>,
    ) -> (Output, String) {
        let mut child = cmd(vault).args(args).spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(before.as_bytes()).unwrap();
        stdin.flush().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let mut code = String::new();
        loop {
            line.clear();
            if out.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.starts_with("Recovery code") {
                out.read_line(&mut code).unwrap();
                break;
            }
        }
        let code = code.trim().to_owned();
        let back = confirm.map(str::to_owned).unwrap_or_else(|| code.clone());
        // The process may already have failed (e.g. a rejected password).
        let _ = stdin.write_all(format!("{back}\n").as_bytes());
        drop(stdin);
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut out, &mut rest).unwrap();
        let o = child.wait_with_output().unwrap();
        (
            Output {
                status: o.status,
                stdout: rest.into_bytes(),
                stderr: o.stderr,
            },
            code,
        )
    }

    fn init(&self, vault: &Path, pw: &str) -> String {
        let (o, code) = self.with_code(vault, &["init"], &format!("{pw}\n"), None);
        assert!(
            o.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert_eq!(code.len(), 56 + 13, "code shown in groups");
        code
    }
}

fn assert_no_secrets(bytes: &[u8], secrets: &[&str]) {
    let text = String::from_utf8_lossy(bytes).to_lowercase();
    for s in secrets {
        assert!(!text.contains(&s.to_lowercase()), "a secret leaked");
        let compact = s.replace('-', "").to_lowercase();
        assert!(!text.contains(&compact), "a secret leaked");
    }
}

fn list(c: &Ctx, vault: &Path, pw: &str) -> String {
    c.ok_at(vault, &["list"], &format!("{pw}\n"))
}

#[test]
fn create_write_restart_unlock_backup_change_and_recover() {
    let c = Ctx::new();
    let v = c.path("vault.keymesh");
    let code = c.init(&v, PW);
    assert!(v.exists());

    // Write items in separate processes (each one a restart + Argon2id unlock).
    c.ok_at(
        &v,
        &["add", "note", "--title", "Synthetic note"],
        &format!("{PW}\nSYNTHETIC-NOTE-BODY\n"),
    );
    c.ok_at(
        &v,
        &["add", "ed25519", "--title", "Synthetic key"],
        &format!("{PW}\n"),
    );
    c.ok_at(
        &v,
        &["add", "totp", "--title", "Synthetic otp", "--base32"],
        &format!("{PW}\nJBSWY3DPEHPK3PXP\n"),
    );
    let l = list(&c, &v, PW);
    for t in ["Synthetic note", "Synthetic key", "Synthetic otp"] {
        assert!(l.contains(t), "{t} listed");
    }
    let file = std::fs::read(&v).unwrap();
    assert_no_secrets(&file, &[PW, &code, "SYNTHETIC-NOTE-BODY", "Synthetic note"]);

    // Wrong password: refused, file untouched.
    let o = c.run_at(&v, &["list"], "synthetic wrong passphrase\n");
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&v).unwrap(), file);
    // Recovery code is not a password.
    assert!(!c
        .run_at(&v, &["list"], &format!("{code}\n"))
        .status
        .success());

    // Backup verifies with the password.
    let bak = c.path("backup.keymesh");
    c.ok_at(
        &v,
        &["backup", "--to", bak.to_str().unwrap()],
        &format!("{PW}\n"),
    );
    assert_eq!(std::fs::read(&bak).unwrap(), file);

    // Password change needs the current password.
    let o = c.run_at(
        &v,
        &["passwd"],
        &format!("synthetic wrong passphrase\n{PW2}\n"),
    );
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&v).unwrap(), file);
    // A weak new password is refused.
    let o = c.run_at(&v, &["passwd"], &format!("{PW}\nshort\n"));
    assert!(!o.status.success());
    let out = c.ok_at(&v, &["passwd"], &format!("{PW}\n{PW2}\n"));
    assert!(out.contains("old password"), "rewrap semantics stated");
    assert!(!c.run_at(&v, &["list"], &format!("{PW}\n")).status.success());
    assert!(list(&c, &v, PW2).contains("Synthetic note"));
    // The backup made before the change still opens with the OLD password.
    assert!(list(&c, &bak, PW).contains("Synthetic note"));
    assert!(!c
        .run_at(&bak, &["list"], &format!("{PW2}\n"))
        .status
        .success());

    // Forgot the password: recover from the backup with the recovery code.
    let restored = c.path("restored.keymesh");
    let o = c.run_at(
        &restored,
        &["recover", "--from", bak.to_str().unwrap()],
        &format!("{}\n{PW3}\n", "A".repeat(56)),
    );
    assert!(!o.status.success(), "invalid code refused");
    assert!(!restored.exists());
    c.ok_at(
        &restored,
        &["recover", "--from", bak.to_str().unwrap()],
        &format!("{code}\n{PW3}\n"),
    );
    assert!(list(&c, &restored, PW3).contains("Synthetic otp"));
    assert!(!c
        .run_at(&restored, &["list"], &format!("{PW}\n"))
        .status
        .success());
    // recover never clobbers without --force.
    let before = std::fs::read(&restored).unwrap();
    let o = c.run_at(
        &restored,
        &["recover", "--from", bak.to_str().unwrap()],
        &format!("{code}\n{PW}\n"),
    );
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&restored).unwrap(), before);

    // Password reset with the recovery code on the live vault.
    c.ok_at(&v, &["passwd", "--recovery"], &format!("{code}\n{PW3}\n"));
    assert!(list(&c, &v, PW3).contains("Synthetic key"));

    // Replace the recovery code: the old one stops working for this file only.
    let (o, new_code) = c.with_code(&v, &["new-recovery-code"], &format!("{PW3}\n"), None);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_ne!(new_code, code);
    let r2 = c.path("r2.keymesh");
    assert!(!c
        .run_at(
            &r2,
            &["recover", "--from", v.to_str().unwrap()],
            &format!("{code}\n{PW}\n")
        )
        .status
        .success());
    c.ok_at(
        &r2,
        &["recover", "--from", v.to_str().unwrap()],
        &format!("{new_code}\n{PW}\n"),
    );
    // Old backup still opens with the old code.
    let r3 = c.path("r3.keymesh");
    c.ok_at(
        &r3,
        &["recover", "--from", bak.to_str().unwrap()],
        &format!("{code}\n{PW}\n"),
    );

    // Restore a password backup over the vault (needs the backup's password).
    let o = c.run_at(
        &v,
        &["restore", "--from", bak.to_str().unwrap(), "--force"],
        &format!("{PW3}\n"),
    );
    assert!(!o.status.success(), "backup still has the old password");
    c.ok_at(
        &v,
        &["restore", "--from", bak.to_str().unwrap(), "--force"],
        &format!("{PW}\n"),
    );
    assert_eq!(std::fs::read(&v).unwrap(), file);
}

#[test]
fn init_requires_the_recovery_code_back_and_refuses_weak_passwords() {
    let c = Ctx::new();
    let v = c.path("vault.keymesh");
    let (o, _) = c.with_code(&v, &["init"], &format!("{PW}\n"), Some("AAAA-BBBB"));
    assert!(!o.status.success());
    assert!(!v.exists(), "nothing written without confirmation");
    let (o, code) = c.with_code(&v, &["init"], &format!("{PW}\n"), Some(&"A".repeat(56)));
    assert!(!o.status.success());
    assert!(!v.exists());
    assert_no_secrets(&o.stderr, &[PW, &code]);
    for weak in ["short", "passwordpassword", &"z".repeat(30)] {
        let o = c.run_at(&v, &["init"], &format!("{weak}\n"));
        assert!(!o.status.success(), "weak password refused");
        assert!(!v.exists());
    }
    // A terminal is required without --password-stdin.
    let o = Command::new(env!("CARGO_BIN_EXE_keymesh"))
        .env_clear()
        .arg("--vault")
        .arg(&v)
        .arg("init")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!o.status.success());
    let code = c.init(&v, PW);
    // init never replaces an existing vault.
    let before = std::fs::read(&v).unwrap();
    let o = c.run_at(&v, &["init"], &format!("{PW2}\n"));
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&v).unwrap(), before);
    assert_no_secrets(&o.stderr, &[PW, PW2, &code]);
}

#[test]
fn demo_and_password_vaults_stay_separate() {
    let c = Ctx::new();
    let demo = c.path("demo.keymesh");
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).unwrap();
    let key = data_encoding::HEXLOWER.encode(&k);
    let o = Command::new(env!("CARGO_BIN_EXE_keymesh"))
        .env_clear()
        .env("KEYMESH_DEMO_KEY", &key)
        .args(["--vault", demo.to_str().unwrap(), "init", "--demo"])
        .output()
        .unwrap();
    assert!(o.status.success());
    // A demo file never opens with a password, and there is no recovery code.
    assert!(!c
        .run_at(&demo, &["list"], &format!("{PW}\n"))
        .status
        .success());
    assert!(!c
        .run_at(&demo, &["passwd"], &format!("{PW}\n{PW2}\n"))
        .status
        .success());
    let r = c.path("r.keymesh");
    let fake = "A".repeat(56);
    assert!(!c
        .run_at(
            &r,
            &["recover", "--from", demo.to_str().unwrap()],
            &format!("{fake}\n{PW}\n")
        )
        .status
        .success());
    // A password vault ignores KEYMESH_DEMO_KEY entirely.
    let v = c.path("vault.keymesh");
    c.init(&v, PW);
    let o = Command::new(env!("CARGO_BIN_EXE_keymesh"))
        .env_clear()
        .env("KEYMESH_DEMO_KEY", &key)
        .args(["--password-stdin", "--vault", v.to_str().unwrap(), "list"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!o.status.success(), "no password, no access");
}

/// A directory that can be written and searched but not opened (mode 0300):
/// `passwd` must fail BEFORE replacing the file, so the old password keeps
/// working and the new one does not.
#[cfg(unix)]
#[test]
fn passwd_that_cannot_sync_the_directory_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores directory permissions
    }
    let c = Ctx::new();
    let sub = c.path("locked-dir");
    std::fs::create_dir(&sub).unwrap();
    let v = sub.join("vault.keymesh");
    c.init(&v, PW);
    let before = std::fs::read(&v).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o300)).unwrap();
    let o = c.run_at(&v, &["passwd"], &format!("{PW}\n{PW2}\n"));
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&v).unwrap(), before, "file not replaced");
    list(&c, &v, PW); // old password still opens (ok_at asserts success)
    assert!(!c
        .run_at(&v, &["list"], &format!("{PW2}\n"))
        .status
        .success());
}

#[test]
fn rotate_key_replaces_both_credentials_and_keeps_old_backups_on_old_ones() {
    let c = Ctx::new();
    let v = c.path("vault.keymesh");
    let code = c.init(&v, PW);
    c.ok_at(
        &v,
        &["add", "note", "--title", "Synthetic note"],
        &format!("{PW}\nSYNTHETIC-NOTE-BODY\n"),
    );
    let bak = c.path("backup.keymesh");
    c.ok_at(
        &v,
        &["backup", "--to", bak.to_str().unwrap()],
        &format!("{PW}\n"),
    );
    let before = std::fs::read(&v).unwrap();

    // Wrong current password, weak or unchanged new password, wrong code
    // typed back: refused, file untouched.
    let o = c.run_at(
        &v,
        &["rotate-key"],
        &format!("synthetic wrong passphrase\n{PW2}\n"),
    );
    assert!(!o.status.success());
    let o = c.run_at(&v, &["rotate-key"], &format!("{PW}\nshort\n"));
    assert!(!o.status.success());
    let o = c.run_at(&v, &["rotate-key"], &format!("{PW}\n{PW}\n"));
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("different password"));
    let (o, shown) = c.with_code(&v, &["rotate-key"], &format!("{PW}\n{PW2}\n"), Some(&code));
    assert!(!o.status.success());
    assert_eq!(std::fs::read(&v).unwrap(), before);
    assert_no_secrets(&o.stderr, &[PW, PW2, &code, &shown]);

    let (o, new_code) = c.with_code(&v, &["rotate-key"], &format!("{PW}\n{PW2}\n"), None);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("OLD password and code"),
        "backup semantics stated"
    );
    assert!(out.contains("website and service credentials"));
    assert_ne!(new_code, code);
    let after = std::fs::read(&v).unwrap();
    assert_no_secrets(
        &after,
        &[PW2, &new_code, "SYNTHETIC-NOTE-BODY", "Synthetic note"],
    );
    // Only the new password opens it; the old one does not.
    assert!(list(&c, &v, PW2).contains("Synthetic note"));
    assert!(!c.run_at(&v, &["list"], &format!("{PW}\n")).status.success());
    // The old recovery code no longer resets it; the new one does.
    let o = c.run_at(&v, &["passwd", "--recovery"], &format!("{code}\n{PW3}\n"));
    assert!(!o.status.success());
    c.ok_at(
        &v,
        &["passwd", "--recovery"],
        &format!("{new_code}\n{PW3}\n"),
    );
    assert!(list(&c, &v, PW3).contains("Synthetic note"));
    // The backup from before still opens with the OLD credentials only.
    assert!(list(&c, &bak, PW).contains("Synthetic note"));
    assert!(!c
        .run_at(&bak, &["list"], &format!("{PW2}\n"))
        .status
        .success());
    assert!(!c
        .run_at(&bak, &["list"], &format!("{PW3}\n"))
        .status
        .success());

    // Demo vaults are not rotated.
    let demo = c.path("demo.keymesh");
    let mut d = cmd(&demo);
    d.env("KEYMESH_DEMO_KEY", "11".repeat(32))
        .args(["init", "--demo"]);
    assert!(d.output().unwrap().status.success());
    let mut d = cmd(&demo);
    d.env("KEYMESH_DEMO_KEY", "11".repeat(32)).arg("rotate-key");
    assert!(!d.output().unwrap().status.success());
}
