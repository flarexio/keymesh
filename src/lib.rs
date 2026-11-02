//! Keymesh vault core — **M1 foundation, not production ready.**
//!
//! Local-first encrypted vault with typed items, strong generators, Ed25519
//! key storage, RFC 6238 TOTP and import from the 1Password CLI.
//!
//! Not implemented: production unlock/recovery (only synthetic key providers
//! exist), Keymesh's own authentication, UI, sync. See `README.md`.
//!
//! Modules other than [`storage`], [`import::process`] and the CLI binary are
//! free of filesystem/process access, keeping the core WASM-compatible by
//! design (not yet CI-verified for `wasm32`).

pub mod crypto;
pub mod ed25519;
pub mod error;
pub mod generate;
pub mod import;
pub mod kdf;
pub mod keyslot;
pub mod model;
pub mod recovery;
pub mod rng;
pub mod secret;
#[cfg(feature = "native")]
pub mod storage;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};
