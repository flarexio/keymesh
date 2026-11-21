//! Local encrypted persistence (native only).
//!
//! Writes go to a temporary file in the destination directory, are fsynced,
//! then atomically renamed over the target, and the directory is fsynced.
//! Files are created with mode 0600 on Unix.
//!
//! Safety rules:
//! * `create` refuses to replace an existing file.
//! * `load` never returns an empty vault for a file it cannot decrypt.
//! * `save` re-reads the file and refuses to overwrite unless it is byte for
//!   byte what this vault last read or wrote (SHA-256 compare; lost-update
//!   guard). This is a check-then-rename, not a lock: two processes saving
//!   at the same instant can still race. Keymesh assumes a single writer per
//!   vault file and does not implement file locking.
//! * `backup` and `restore` verify the source decrypts before writing.
//! * Reads and writes share one size bound ([`MAX_VAULT_BYTES`]); an oversize
//!   vault is refused before anything is written.
//! * A failure reported before the rename means the old file is untouched; a
//!   directory-sync failure after it is [`Error::DurabilityUncertain`]: the
//!   change is in effect and in-memory state already matches it.

use crate::crypto::KeyProvider;
use crate::error::{Error, Result};
use crate::rng::RandomSource;
use crate::vault::{read_header, Vault};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Maximum vault file size. The same bound applies to reading and writing,
/// so a successful save can always be loaded again.
pub const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

fn too_large() -> Error {
    Error::Format("vault exceeds the maximum file size".into())
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > limit {
        return Err(too_large());
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(buf)
}

/// Checked before any temporary file is created.
fn check_write_size(bytes: &[u8], limit: u64) -> Result<()> {
    if bytes.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// Test-only fault injection: make the post-rename directory sync fail.
    static FAIL_DIR_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Atomically write `bytes` to `path`. With `no_clobber`, fails if `path`
/// already exists.
///
/// Outcome contract:
/// * `Err(Error::Io | ..)`: **nothing was replaced**; the old file (if any) is
///   untouched. Everything that can fail deterministically (creating, writing
///   and syncing the temp file, and opening the directory for the final sync)
///   happens before the rename.
/// * `Err(Error::DurabilityUncertain)`: the rename **already happened** (the
///   new bytes are in place), but syncing the directory failed, so durability
///   across a crash is not confirmed. Callers must treat the write as
///   committed (see [`committed`]).
pub fn atomic_write(path: &Path, bytes: &[u8], no_clobber: bool) -> Result<()> {
    let dir = parent_dir(path);
    // Opened up front: a directory we cannot open for syncing fails here,
    // before the target is replaced.
    #[cfg(unix)]
    let dir_handle = fs::File::open(&dir)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".keymesh-")
        .suffix(".tmp")
        .tempfile_in(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    if no_clobber {
        tmp.persist_noclobber(path).map_err(|e| e.error)?;
    } else {
        tmp.persist(path).map_err(|e| e.error)?;
    }
    // From here on the new file is in place.
    #[cfg(unix)]
    sync_dir(&dir_handle).map_err(|e| Error::DurabilityUncertain(e.to_string()))?;
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &fs::File) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_DIR_SYNC.with(|f| f.get()) {
        return Err(std::io::Error::other("injected directory sync failure"));
    }
    dir.sync_all()
}

/// After [`atomic_write`] for `vault`'s sealed `revision`: on success or on
/// a post-rename durability failure the bytes are on disk, so memory is
/// reconciled to them (revision and exact-byte snapshot) before the
/// durability error, if any, is returned. A pre-rename failure leaves memory
/// unchanged, matching the untouched file.
fn committed(vault: &mut Vault, revision: u64, bytes: &[u8], write: Result<()>) -> Result<()> {
    match write {
        Ok(()) => vault.mark_written(revision, bytes),
        Err(e @ Error::DurabilityUncertain(_)) => {
            vault.mark_written(revision, bytes)?;
            Err(e)
        }
        Err(e) => Err(e),
    }
}

pub fn create(
    path: &Path,
    vault: &mut Vault,
    provider: &dyn KeyProvider,
    rng: &mut dyn RandomSource,
) -> Result<()> {
    create_limited(path, vault, provider, rng, MAX_VAULT_BYTES)
}

pub(crate) fn create_limited(
    path: &Path,
    vault: &mut Vault,
    provider: &dyn KeyProvider,
    rng: &mut dyn RandomSource,
    limit: u64,
) -> Result<()> {
    if path.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "vault file already exists",
        )));
    }
    if vault.revision() != 0 {
        return Err(Error::validation("create expects a new vault"));
    }
    let (bytes, rev) = vault.seal_next(provider, rng)?;
    check_write_size(&bytes, limit)?;
    let write = atomic_write(path, &bytes, true);
    committed(vault, rev, &bytes, write)
}

pub fn load(path: &Path, provider: &dyn KeyProvider) -> Result<Vault> {
    load_limited(path, provider, MAX_VAULT_BYTES)
}

pub(crate) fn load_limited(path: &Path, provider: &dyn KeyProvider, limit: u64) -> Result<Vault> {
    let bytes = read_bounded(path, limit)?;
    Vault::decrypt(&bytes, provider)
}

/// Saves the next revision. If the sealed vault would exceed
/// [`MAX_VAULT_BYTES`], nothing is written and the in-memory revision is
/// unchanged; the caller must shrink the vault before saving.
pub fn save(
    path: &Path,
    vault: &mut Vault,
    provider: &dyn KeyProvider,
    rng: &mut dyn RandomSource,
) -> Result<()> {
    save_limited(path, vault, provider, rng, MAX_VAULT_BYTES)
}

pub(crate) fn save_limited(
    path: &Path,
    vault: &mut Vault,
    provider: &dyn KeyProvider,
    rng: &mut dyn RandomSource,
    limit: u64,
) -> Result<()> {
    check_unchanged(path, vault, limit)?;
    let (bytes, rev) = vault.seal_next(provider, rng)?;
    check_write_size(&bytes, limit)?;
    let write = atomic_write(path, &bytes, false);
    committed(vault, rev, &bytes, write)
}

/// The file must still be exactly what `vault` last read or wrote.
fn check_unchanged(path: &Path, vault: &Vault, limit: u64) -> Result<()> {
    let current = read_bounded(path, limit)?;
    let on_disk = read_header(&current)?;
    if on_disk.vault_id != vault.vault_id() {
        return Err(Error::Integrity(
            "target file holds a different vault".into(),
        ));
    }
    let digest: [u8; 32] = Sha256::digest(&current).into();
    if on_disk.revision != vault.revision() || vault.snapshot_digest() != Some(digest) {
        return Err(Error::Integrity(
            "vault changed on disk since it was loaded; reload and retry".into(),
        ));
    }
    Ok(())
}

// --- v2 (password + recovery) ----------------------------------------------

/// Write a new password-protected vault. Refused until its recovery code was
/// confirmed ([`Vault::confirm_recovery`]) and if `path` exists.
pub fn create_protected(path: &Path, vault: &mut Vault, rng: &mut dyn RandomSource) -> Result<()> {
    if path.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "vault file already exists",
        )));
    }
    if vault.revision() != 0 {
        return Err(Error::validation("create expects a new vault"));
    }
    let (bytes, rev) = vault.seal_next_protected(rng)?;
    check_write_size(&bytes, MAX_VAULT_BYTES)?;
    let write = atomic_write(path, &bytes, true);
    committed(vault, rev, &bytes, write)
}

/// Bounded read of an envelope (for password/recovery unlock).
pub fn read_envelope(path: &Path) -> Result<Vec<u8>> {
    read_bounded(path, MAX_VAULT_BYTES)
}

pub fn save_protected(path: &Path, vault: &mut Vault, rng: &mut dyn RandomSource) -> Result<()> {
    check_unchanged(path, vault, MAX_VAULT_BYTES)?;
    let (bytes, rev) = vault.seal_next_protected(rng)?;
    check_write_size(&bytes, MAX_VAULT_BYTES)?;
    let write = atomic_write(path, &bytes, false);
    committed(vault, rev, &bytes, write)
}

/// Write `vault` (already opened, e.g. from a backup with its recovery code
/// and given a new password) as the next revision to `dest`. Without
/// `overwrite`, an existing `dest` is never replaced.
pub fn write_protected_to(
    dest: &Path,
    vault: &mut Vault,
    rng: &mut dyn RandomSource,
    overwrite: bool,
) -> Result<()> {
    let (bytes, rev) = vault.seal_next_protected(rng)?;
    check_write_size(&bytes, MAX_VAULT_BYTES)?;
    let write = atomic_write(dest, &bytes, !overwrite);
    committed(vault, rev, &bytes, write)
}

/// Write backup bytes the caller already opened to `dest` (restore).
/// Without `overwrite`, an existing `dest` is never replaced.
pub fn restore_verified(bytes: &[u8], dest: &Path, overwrite: bool) -> Result<()> {
    check_write_size(bytes, MAX_VAULT_BYTES)?;
    atomic_write(dest, bytes, !overwrite)
}

/// Copy verified bytes to a new file (never clobbers). The caller has already
/// opened `bytes` with a valid credential.
pub fn write_backup(dest: &Path, bytes: &[u8]) -> Result<()> {
    check_write_size(bytes, MAX_VAULT_BYTES)?;
    atomic_write(dest, bytes, true)
}

/// Copy an encrypted vault to `dest` after verifying it decrypts with
/// `provider`. The backup stays encrypted under the same key hierarchy.
pub fn backup(src: &Path, dest: &Path, provider: &dyn KeyProvider) -> Result<()> {
    let bytes = read_bounded(src, MAX_VAULT_BYTES)?;
    Vault::decrypt(&bytes, provider)?;
    atomic_write(dest, &bytes, true)
}

/// Restore an encrypted backup to `dest`. The backup must decrypt. Without
/// `overwrite`, an existing `dest` is never replaced.
pub fn restore(
    backup: &Path,
    dest: &Path,
    provider: &dyn KeyProvider,
    overwrite: bool,
) -> Result<()> {
    let bytes = read_bounded(backup, MAX_VAULT_BYTES)?;
    Vault::decrypt(&bytes, provider)?;
    atomic_write(dest, &bytes, !overwrite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EphemeralKeyProvider;
    use crate::model::{Item, ItemData, SecureNote};
    use crate::rng::OsRandom;
    use crate::secret::SecretString;

    fn note(t: &str) -> Item {
        Item::new(
            t,
            ItemData::SecureNote(SecureNote {
                body: SecretString::new("synthetic"),
            }),
            &mut OsRandom,
        )
        .unwrap()
    }

    fn setup() -> (tempfile::TempDir, PathBuf, EphemeralKeyProvider) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.keymesh");
        let p = EphemeralKeyProvider::generate("t", &mut OsRandom).unwrap();
        (dir, path, p)
    }

    #[test]
    fn create_load_edit_save_round_trip() {
        let (_d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        v.insert(note("a")).unwrap();
        create(&path, &mut v, &p, &mut OsRandom).unwrap();
        let mut v2 = load(&path, &p).unwrap();
        v2.insert(note("b")).unwrap();
        save(&path, &mut v2, &p, &mut OsRandom).unwrap();
        let v3 = load(&path, &p).unwrap();
        assert_eq!(v3.len(), 2);
        assert_eq!(v3.revision(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn create_refuses_existing_file() {
        let (_d, path, p) = setup();
        fs::write(&path, b"precious").unwrap();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        assert!(create(&path, &mut v, &p, &mut OsRandom).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"precious");
    }

    #[test]
    fn failed_decrypt_never_overwrites() {
        let (_d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        v.insert(note("a")).unwrap();
        create(&path, &mut v, &p, &mut OsRandom).unwrap();
        let original = fs::read(&path).unwrap();
        let wrong = EphemeralKeyProvider::generate("t", &mut OsRandom).unwrap();
        assert!(load(&path, &wrong).is_err());
        // A fresh vault cannot be saved over an existing one.
        let mut fresh = Vault::create(&wrong, &mut OsRandom).unwrap();
        assert!(save(&path, &mut fresh, &wrong, &mut OsRandom).is_err());
        assert!(create(&path, &mut fresh, &wrong, &mut OsRandom).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn concurrent_modification_detected() {
        let (_d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        create(&path, &mut v, &p, &mut OsRandom).unwrap();
        let mut a = load(&path, &p).unwrap();
        let mut b = load(&path, &p).unwrap();
        a.insert(note("a")).unwrap();
        save(&path, &mut a, &p, &mut OsRandom).unwrap();
        b.insert(note("b")).unwrap();
        assert!(save(&path, &mut b, &p, &mut OsRandom).is_err());
        assert_eq!(load(&path, &p).unwrap().len(), 1);
    }

    #[test]
    fn backup_and_restore() {
        let (d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        v.insert(note("a")).unwrap();
        create(&path, &mut v, &p, &mut OsRandom).unwrap();
        let bak = d.path().join("v.bak");
        backup(&path, &bak, &p).unwrap();
        assert!(backup(&path, &bak, &p).is_err(), "backup must not clobber");
        let restored = d.path().join("restored.keymesh");
        restore(&bak, &restored, &p, false).unwrap();
        assert_eq!(load(&restored, &p).unwrap().len(), 1);
        assert!(restore(&bak, &restored, &p, false).is_err());
        restore(&bak, &restored, &p, true).unwrap();

        // Corrupt / truncated backups are rejected and do not touch dest.
        let bad = d.path().join("bad.bak");
        let bytes = fs::read(&bak).unwrap();
        fs::write(&bad, &bytes[..bytes.len() - 20]).unwrap();
        let before = fs::read(&restored).unwrap();
        assert!(restore(&bad, &restored, &p, true).is_err());
        assert_eq!(fs::read(&restored).unwrap(), before);
        let wrong = EphemeralKeyProvider::generate("t", &mut OsRandom).unwrap();
        assert!(restore(&bak, &restored, &wrong, true).is_err());
        assert!(backup(&path, &d.path().join("x.bak"), &wrong).is_err());
    }

    fn big_note(n_bytes: usize) -> Item {
        Item::new(
            "big",
            ItemData::SecureNote(SecureNote {
                body: SecretString::new("x".repeat(n_bytes)),
            }),
            &mut OsRandom,
        )
        .unwrap()
    }

    #[test]
    fn oversize_create_is_rejected_without_leaving_a_file() {
        let (d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        v.insert(big_note(8 * 1024)).unwrap();
        let err = create_limited(&path, &mut v, &p, &mut OsRandom, 4 * 1024).unwrap_err();
        assert!(matches!(err, Error::Format(_)), "{err:?}");
        assert!(!path.exists());
        assert_eq!(v.revision(), 0);
        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            0,
            "no temp files left"
        );
    }

    #[test]
    fn oversize_save_keeps_old_file_and_revision() {
        let (d, path, p) = setup();
        let limit = 16 * 1024;
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        v.insert(note("small")).unwrap();
        create_limited(&path, &mut v, &p, &mut OsRandom, limit).unwrap();
        let before = fs::read(&path).unwrap();
        let mut v = load_limited(&path, &p, limit).unwrap();
        v.insert(big_note(32 * 1024)).unwrap();
        let err = save_limited(&path, &mut v, &p, &mut OsRandom, limit).unwrap_err();
        assert!(matches!(err, Error::Format(_)), "{err:?}");
        assert_eq!(fs::read(&path).unwrap(), before, "old bytes untouched");
        assert_eq!(v.revision(), 1, "revision not advanced");
        assert_eq!(
            load_limited(&path, &p, limit).unwrap().len(),
            1,
            "old file loadable"
        );
        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temp files left"
        );
        // After removing the oversize item the same in-memory vault saves fine.
        let big = v.items().find(|i| i.title == "big").unwrap().id.clone();
        v.remove(&big).unwrap();
        save_limited(&path, &mut v, &p, &mut OsRandom, limit).unwrap();
        assert_eq!(v.revision(), 2);
    }

    #[test]
    fn exactly_at_limit_round_trips() {
        let (_d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        v.insert(note("a")).unwrap();
        let (bytes, _) = v.seal_next(&p, &mut OsRandom).unwrap();
        // The sealed size is deterministic for a fixed vault content.
        let limit = bytes.len() as u64;
        create_limited(&path, &mut v, &p, &mut OsRandom, limit).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), limit);
        load_limited(&path, &p, limit).unwrap();
    }

    /// Production wiring: the public API refuses to write what it could not
    /// read back with `MAX_VAULT_BYTES`. Builds a vault just over 64 MiB.
    #[test]
    fn public_save_enforces_production_limit() {
        let (_d, path, p) = setup();
        let mut v = Vault::create(&p, &mut OsRandom).unwrap();
        create(&path, &mut v, &p, &mut OsRandom).unwrap();
        let before = fs::read(&path).unwrap();
        // Each 60 KiB body becomes ~80 KiB sealed + base64; 850 items > 64 MiB.
        for _ in 0..850 {
            v.insert(big_note(60 * 1024)).unwrap();
        }
        let err = save(&path, &mut v, &p, &mut OsRandom).unwrap_err();
        assert!(matches!(err, Error::Format(_)), "{err:?}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(v.revision(), 1);
        load(&path, &p).unwrap();
        // Read side uses the same bound (sparse file, no real allocation).
        let huge = path.with_extension("huge");
        fs::File::create(&huge)
            .unwrap()
            .set_len(MAX_VAULT_BYTES + 1)
            .unwrap();
        assert!(matches!(load(&huge, &p), Err(Error::Format(_))));
    }

    #[test]
    fn missing_file_is_error_not_empty_vault() {
        let (_d, path, p) = setup();
        assert!(load(&path, &p).is_err());
    }

    // --- v2 ------------------------------------------------------------------

    const PW: &str = "synthetic storage passphrase";

    fn protected_file(path: &Path) -> Vec<u8> {
        let (mut v, code) = Vault::create_with_password(PW, &mut OsRandom).unwrap();
        // Refused until the recovery code was confirmed: nothing written.
        assert!(create_protected(path, &mut v, &mut OsRandom).is_err());
        assert!(!path.exists());
        v.confirm_recovery(&code).unwrap();
        v.insert(note("a")).unwrap();
        create_protected(path, &mut v, &mut OsRandom).unwrap();
        fs::read(path).unwrap()
    }

    #[test]
    fn protected_save_uses_exact_bytes_not_just_revision() {
        let (d, path, _p) = setup();
        let original = protected_file(&path);
        let bytes = read_envelope(&path).unwrap();
        let mut a = Vault::open_with_password(&bytes, PW).unwrap();
        let mut b = Vault::open_with_password(&bytes, PW).unwrap();
        // Another writer replaces the file with different content at the SAME
        // revision (e.g. a restore of a sibling backup).
        let mut sibling = Vault::open_with_password(&bytes, PW).unwrap();
        sibling.insert(note("sibling")).unwrap();
        let sib_path = d.path().join("sibling.keymesh");
        write_protected_to(&sib_path, &mut sibling, &mut OsRandom, false).unwrap();
        a.insert(note("a2")).unwrap();
        save_protected(&path, &mut a, &mut OsRandom).unwrap();
        let after_a = fs::read(&path).unwrap();
        b.insert(note("b2")).unwrap();
        assert!(save_protected(&path, &mut b, &mut OsRandom).is_err());
        assert_eq!(fs::read(&path).unwrap(), after_a);
        // Same revision (2) as `a`'s save, different bytes: still refused.
        let mut c = Vault::open_with_password(&after_a, PW).unwrap();
        fs::copy(&sib_path, &path).unwrap();
        assert_eq!(
            read_header(&fs::read(&path).unwrap()).unwrap().revision,
            c.revision()
        );
        c.insert(note("c")).unwrap();
        assert!(save_protected(&path, &mut c, &mut OsRandom).is_err());
        assert_eq!(fs::read(&path).unwrap(), fs::read(&sib_path).unwrap());
        assert_ne!(original, after_a);
    }

    #[test]
    fn protected_failures_leave_the_file_intact() {
        let (d, path, _p) = setup();
        let original = protected_file(&path);
        assert!(create_protected(
            &path,
            &mut Vault::create_with_password(PW, &mut OsRandom).unwrap().0,
            &mut OsRandom
        )
        .is_err());
        assert!(Vault::open_with_password(
            &read_envelope(&path).unwrap(),
            "synthetic wrong passphrase"
        )
        .is_err());
        // Restoring/recovering never clobbers without overwrite.
        let mut v = Vault::open_with_password(&original, PW).unwrap();
        assert!(write_protected_to(&path, &mut v, &mut OsRandom, false).is_err());
        assert!(restore_verified(&original, &path, false).is_err());
        assert!(write_backup(&path, &original).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        // Oversize envelopes are refused on read.
        let huge = d.path().join("huge.keymesh");
        fs::File::create(&huge)
            .unwrap()
            .set_len(MAX_VAULT_BYTES + 1)
            .unwrap();
        assert!(matches!(read_envelope(&huge), Err(Error::Format(_))));
        let leftovers = fs::read_dir(d.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    // --- persistence outcome: before vs after the replacing rename ------------

    use crate::keyslot::{Authority, PasswordSetup};

    /// Turns on the test-only post-rename directory-sync fault for its scope.
    struct DirSyncFault;
    impl DirSyncFault {
        fn on() -> Self {
            FAIL_DIR_SYNC.with(|f| f.set(true));
            DirSyncFault
        }
    }
    impl Drop for DirSyncFault {
        fn drop(&mut self) {
            FAIL_DIR_SYNC.with(|f| f.set(false));
        }
    }

    const PW2: &str = "synthetic storage passphrase two";

    /// Open `path` with PW and change its password to PW2 in memory.
    fn with_new_password(path: &Path) -> Vault {
        let bytes = read_envelope(path).unwrap();
        let mut v = Vault::open_with_password(&bytes, PW).unwrap();
        let cur = v.password_setup().unwrap().derive(PW).unwrap();
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let new = setup.derive(PW2).unwrap();
        v.change_password(Authority::PasswordKey(&cur), &setup, &new, &mut OsRandom)
            .unwrap();
        v
    }

    fn digest(path: &Path) -> [u8; 32] {
        Sha256::digest(fs::read(path).unwrap()).into()
    }

    #[cfg(unix)]
    struct DirMode(PathBuf);
    #[cfg(unix)]
    impl DirMode {
        fn set(dir: &Path, mode: u32) -> Self {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
            DirMode(dir.to_path_buf())
        }
    }
    #[cfg(unix)]
    impl Drop for DirMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    #[cfg(unix)]
    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    /// A directory that can be written and searched but not opened (mode
    /// 0300): the failure must happen BEFORE the file is replaced.
    #[cfg(unix)]
    #[test]
    fn unopenable_directory_fails_before_replacing_and_keeps_old_credentials() {
        if is_root() {
            return; // root ignores directory permissions
        }
        let (d, path, p) = setup();
        let original = protected_file(&path);
        let mut v = with_new_password(&path);
        let r = {
            let _mode = DirMode::set(d.path(), 0o300);
            save_protected(&path, &mut v, &mut OsRandom)
        };
        assert!(matches!(r, Err(Error::Io(_))), "{r:?}");
        assert_eq!(fs::read(&path).unwrap(), original, "file not replaced");
        assert_eq!(v.revision(), 1, "memory not advanced");
        assert!(
            Vault::open_with_password(&original, PW).is_ok(),
            "old password still opens"
        );
        assert!(Vault::open_with_password(&original, PW2).is_err());
        // Same boundary for create and the v1 demo save.
        let fresh = d.path().join("fresh.keymesh");
        let (mut n, code) = Vault::create_with_password(PW, &mut OsRandom).unwrap();
        n.confirm_recovery(&code).unwrap();
        let demo = d.path().join("demo.keymesh");
        let mut dv = Vault::create(&p, &mut OsRandom).unwrap();
        create(&demo, &mut dv, &p, &mut OsRandom).unwrap();
        let demo_before = fs::read(&demo).unwrap();
        dv.insert(note("x")).unwrap();
        {
            let _mode = DirMode::set(d.path(), 0o300);
            assert!(matches!(
                create_protected(&fresh, &mut n, &mut OsRandom),
                Err(Error::Io(_))
            ));
            assert!(matches!(
                save(&demo, &mut dv, &p, &mut OsRandom),
                Err(Error::Io(_))
            ));
        }
        assert!(!fresh.exists());
        assert_eq!(n.revision(), 0);
        assert_eq!(fs::read(&demo).unwrap(), demo_before);
        assert_eq!(dv.revision(), 1);
        let leftovers = fs::read_dir(d.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0, "no temp files left");
    }

    const PW3: &str = "synthetic storage rotated passphrase";

    /// Open `path` with PW and rotate in memory to PW3 and a new code.
    fn rotated(path: &Path) -> (Vault, Vault, crate::recovery::RecoveryCode) {
        let bytes = read_envelope(path).unwrap();
        let v = Vault::open_with_password(&bytes, PW).unwrap();
        let cur = v.password_setup().unwrap().derive(PW).unwrap();
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let new = setup.derive(PW3).unwrap();
        let p = v
            .begin_rotation(Authority::PasswordKey(&cur), &setup, &new, &mut OsRandom)
            .unwrap();
        let code = crate::recovery::RecoveryCode::parse(&p.code().to_text()).unwrap();
        let r = v.finish_rotation(&p, &code).unwrap();
        (v, r, code)
    }

    #[test]
    fn rotation_save_is_check_then_replace_with_old_file_kept_on_failure() {
        let (d, path, _p) = setup();
        let original = protected_file(&path);
        // Concurrent change on disk: refused, nothing replaced.
        let (_old, mut r, _code) = rotated(&path);
        let mut other = Vault::open_with_password(&original, PW).unwrap();
        other.insert(note("other writer")).unwrap();
        save_protected(&path, &mut other, &mut OsRandom).unwrap();
        let after_other = fs::read(&path).unwrap();
        assert!(matches!(
            save_protected(&path, &mut r, &mut OsRandom),
            Err(Error::Integrity(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), after_other);
        // Pre-rename failure (unopenable directory): old file and old
        // credentials kept; the rotated vault did not advance.
        #[cfg(unix)]
        if !is_root() {
            let (_old, mut r, code) = rotated(&path);
            let res = {
                let _mode = DirMode::set(d.path(), 0o300);
                save_protected(&path, &mut r, &mut OsRandom)
            };
            assert!(matches!(res, Err(Error::Io(_))), "{res:?}");
            assert_eq!(fs::read(&path).unwrap(), after_other);
            assert_eq!(r.revision(), 2);
            assert!(Vault::open_with_password(&after_other, PW).is_ok());
            assert!(Vault::open_with_recovery(&after_other, &code).is_err());
        }
        // Success: only the new credentials open the file.
        let (_old, mut r, code) = rotated(&path);
        save_protected(&path, &mut r, &mut OsRandom).unwrap();
        let now = fs::read(&path).unwrap();
        assert!(Vault::open_with_password(&now, PW3).is_ok());
        assert!(Vault::open_with_recovery(&now, &code).is_ok());
        assert!(Vault::open_with_password(&now, PW).is_err());
        assert_eq!(r.snapshot_digest(), Some(digest(&path)));
    }

    #[test]
    fn dir_sync_failure_after_a_rotation_save_is_reported_as_committed() {
        let (_d, path, _p) = setup();
        let original = protected_file(&path);
        let (old, mut r, code) = rotated(&path);
        let res = {
            let _f = DirSyncFault::on();
            save_protected(&path, &mut r, &mut OsRandom)
        };
        assert!(matches!(res, Err(Error::DurabilityUncertain(_))), "{res:?}");
        let now = fs::read(&path).unwrap();
        assert_ne!(now, original);
        assert!(Vault::open_with_password(&now, PW3).is_ok());
        assert!(Vault::open_with_recovery(&now, &code).is_ok());
        assert!(Vault::open_with_password(&now, PW).is_err());
        // The rotated vault is reconciled to the file; the old value is stale.
        assert_eq!(r.snapshot_digest(), Some(digest(&path)));
        let mut old = old;
        old.insert(note("stale")).unwrap();
        assert!(save_protected(&path, &mut old, &mut OsRandom).is_err());
        r.insert(note("after")).unwrap();
        save_protected(&path, &mut r, &mut OsRandom).unwrap();
    }

    #[test]
    fn dir_sync_failure_after_a_credential_save_is_reported_as_committed() {
        let (_d, path, _p) = setup();
        let original = protected_file(&path);
        let mut v = with_new_password(&path);
        let r = {
            let _f = DirSyncFault::on();
            save_protected(&path, &mut v, &mut OsRandom)
        };
        assert!(matches!(r, Err(Error::DurabilityUncertain(_))), "{r:?}");
        // The replacement happened: the NEW password is the one that opens it.
        let now = fs::read(&path).unwrap();
        assert_ne!(now, original);
        assert!(Vault::open_with_password(&now, PW2).is_ok());
        assert!(Vault::open_with_password(&now, PW).is_err());
        // Memory is reconciled to the committed file, so work can continue.
        assert_eq!(v.revision(), 2);
        assert_eq!(v.snapshot_digest(), Some(digest(&path)));
        v.insert(note("after")).unwrap();
        save_protected(&path, &mut v, &mut OsRandom).unwrap();
        assert_eq!(v.revision(), 3);
        // The message tells the caller the change is in effect.
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("in effect") && msg.contains("treat the new one as active"),
            "{msg}"
        );
    }

    #[test]
    fn dir_sync_failure_after_create_recover_restore_and_backup_is_committed() {
        let (d, path, p) = setup();
        let (mut n, code) = Vault::create_with_password(PW, &mut OsRandom).unwrap();
        n.confirm_recovery(&code).unwrap();
        {
            let _f = DirSyncFault::on();
            assert!(matches!(
                create_protected(&path, &mut n, &mut OsRandom),
                Err(Error::DurabilityUncertain(_))
            ));
        }
        assert!(path.exists());
        assert_eq!(n.revision(), 1);
        assert_eq!(n.snapshot_digest(), Some(digest(&path)));
        save_protected(&path, &mut n, &mut OsRandom).unwrap();

        // Recover into a new file (recovery code + new password).
        let bytes = read_envelope(&path).unwrap();
        let mut r = Vault::open_with_recovery(&bytes, &code).unwrap();
        let setup = PasswordSetup::generate(&mut OsRandom).unwrap();
        let key = setup.derive(PW2).unwrap();
        r.change_password(Authority::Recovery(&code), &setup, &key, &mut OsRandom)
            .unwrap();
        let dest = d.path().join("recovered.keymesh");
        {
            let _f = DirSyncFault::on();
            assert!(matches!(
                write_protected_to(&dest, &mut r, &mut OsRandom, false),
                Err(Error::DurabilityUncertain(_))
            ));
        }
        assert!(Vault::open_with_password(&fs::read(&dest).unwrap(), PW2).is_ok());
        assert_eq!(r.snapshot_digest(), Some(digest(&dest)));

        // Restore / backup copies (no in-memory state to reconcile).
        let bak = d.path().join("copy.keymesh");
        let restored = d.path().join("restored.keymesh");
        {
            let _f = DirSyncFault::on();
            assert!(matches!(
                write_backup(&bak, &bytes),
                Err(Error::DurabilityUncertain(_))
            ));
            assert!(matches!(
                restore_verified(&bytes, &restored, false),
                Err(Error::DurabilityUncertain(_))
            ));
        }
        assert_eq!(fs::read(&bak).unwrap(), bytes);
        assert_eq!(fs::read(&restored).unwrap(), bytes);

        // v1 demo create/save follow the same rule.
        let demo = d.path().join("demo.keymesh");
        let mut dv = Vault::create(&p, &mut OsRandom).unwrap();
        {
            let _f = DirSyncFault::on();
            assert!(matches!(
                create(&demo, &mut dv, &p, &mut OsRandom),
                Err(Error::DurabilityUncertain(_))
            ));
        }
        assert_eq!(dv.revision(), 1);
        dv.insert(note("demo")).unwrap();
        {
            let _f = DirSyncFault::on();
            assert!(matches!(
                save(&demo, &mut dv, &p, &mut OsRandom),
                Err(Error::DurabilityUncertain(_))
            ));
        }
        assert_eq!(dv.revision(), 2);
        assert_eq!(load(&demo, &p).unwrap().len(), 1);
        save(&demo, &mut dv, &p, &mut OsRandom).unwrap();
    }
}
