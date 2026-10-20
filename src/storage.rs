//! Local encrypted persistence (native only).
//!
//! Writes go to a temporary file in the destination directory, are fsynced,
//! then atomically renamed over the target, and the directory is fsynced.
//! Files are created with mode 0600 on Unix.
//!
//! Safety rules:
//! * `create` refuses to replace an existing file.
//! * `load` never returns an empty vault for a file it cannot decrypt.
//! * `save` re-reads the on-disk header and refuses to overwrite if the file's
//!   vault id or revision differs from what was loaded (lost-update guard).
//! * `backup` and `restore` verify the source decrypts before writing.

use crate::crypto::KeyProvider;
use crate::error::{Error, Result};
use crate::rng::RandomSource;
use crate::vault::{read_header, Vault};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Refuse to read vault files larger than this.
pub const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > MAX_VAULT_BYTES {
        return Err(Error::Format("vault file too large".into()));
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(MAX_VAULT_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_VAULT_BYTES {
        return Err(Error::Format("vault file too large".into()));
    }
    Ok(buf)
}

fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Atomically write `bytes` to `path`. With `no_clobber`, fails if `path`
/// already exists.
pub fn atomic_write(path: &Path, bytes: &[u8], no_clobber: bool) -> Result<()> {
    let dir = parent_dir(path);
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
    #[cfg(unix)]
    {
        fs::File::open(&dir)?.sync_all()?;
    }
    Ok(())
}

pub fn create(
    path: &Path,
    vault: &mut Vault,
    provider: &dyn KeyProvider,
    rng: &mut dyn RandomSource,
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
    atomic_write(path, &bytes, true)?;
    vault.mark_persisted(rev);
    Ok(())
}

pub fn load(path: &Path, provider: &dyn KeyProvider) -> Result<Vault> {
    let bytes = read_bounded(path)?;
    Vault::decrypt(&bytes, provider)
}

pub fn save(
    path: &Path,
    vault: &mut Vault,
    provider: &dyn KeyProvider,
    rng: &mut dyn RandomSource,
) -> Result<()> {
    let on_disk = read_header(&read_bounded(path)?)?;
    if on_disk.vault_id != vault.vault_id() {
        return Err(Error::Integrity(
            "target file holds a different vault".into(),
        ));
    }
    if on_disk.revision != vault.revision() {
        return Err(Error::Integrity(
            "vault changed on disk since it was loaded; reload and retry".into(),
        ));
    }
    let (bytes, rev) = vault.seal_next(provider, rng)?;
    atomic_write(path, &bytes, false)?;
    vault.mark_persisted(rev);
    Ok(())
}

/// Copy an encrypted vault to `dest` after verifying it decrypts with
/// `provider`. The backup stays encrypted under the same key hierarchy.
pub fn backup(src: &Path, dest: &Path, provider: &dyn KeyProvider) -> Result<()> {
    let bytes = read_bounded(src)?;
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
    let bytes = read_bounded(backup)?;
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

    #[test]
    fn missing_file_is_error_not_empty_vault() {
        let (_d, path, p) = setup();
        assert!(load(&path, &p).is_err());
    }
}
