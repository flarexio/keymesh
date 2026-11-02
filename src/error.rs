//! Crate-wide error type.
//!
//! Error messages never include secret material, decrypted payloads or raw
//! provider output. They describe *what* failed, not the data involved.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("random number generator failure")]
    Rng,

    #[error("invalid generator policy: {0}")]
    Policy(String),

    #[error("key provider error: {0}")]
    KeyProvider(String),

    /// Authentication/decryption failed. Deliberately does not distinguish a
    /// wrong key from tampered ciphertext.
    #[error("decryption failed: wrong key or corrupted data")]
    Decrypt,

    #[error("unsupported or unknown format: {0}")]
    Format(String),

    #[error("vault integrity check failed: {0}")]
    Integrity(String),

    #[error("item not found")]
    NotFound,

    #[error("TOTP error: {0}")]
    Totp(String),

    #[error("Ed25519 key error: {0}")]
    Ed25519(String),

    #[error("import error: {0}")]
    Import(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The new file already replaced the old one, but the system could not
    /// confirm it is durable (the directory sync failed). The caller must
    /// treat the change as committed: memory is reconciled to the new file,
    /// and new credentials may already be the only ones that open it.
    #[error(
        "the change was written and is now in effect, but the system could not confirm it is \
         safely on disk ({0}); if it changed a password or recovery code, treat the new one as \
         active and keep the previous one until the vault opens with the new one; then make a \
         fresh backup"
    )]
    DurabilityUncertain(String),
}

impl Error {
    pub(crate) fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }
}
