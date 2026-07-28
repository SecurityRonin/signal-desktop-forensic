//! **Signal Desktop reader** — decrypt and parse a Signal Desktop profile.
//!
//! Signal Desktop is an Electron/Chromium app. Its messages, conversations,
//! contacts, and attachment metadata live in a single **SQLCipher-encrypted**
//! database, `sql/db.sqlite`. The SQLCipher key is not stored in the clear:
//! `config.json` holds an `encryptedKey` that is itself wrapped by the OS
//! **Safe Storage** (Electron `safeStorage`: macOS Keychain "Signal Safe
//! Storage", Windows DPAPI, Linux libsecret).
//!
//! # Pipeline
//!
//! ```text
//! OS Safe Storage key  ──(chromium-safestorage)──▶ RecoveredKey (AES-128-CBC)
//!         │
//!         ▼  decrypt config.json `encryptedKey` (v10 blob)
//! SQLCipher raw key (64 hex chars = 32 bytes)
//!         │
//!         ▼  PRAGMA key = "x'…'"  (SQLCipher 4 defaults)
//! sql/db.sqlite  ──▶ messages · conversations · contacts · attachments · timeline
//! ```
//!
//! # Honest crypto
//!
//! All crypto is an audited implementation: the `encryptedKey` unwrap uses
//! [`chromium_safestorage_core`] (RustCrypto AES-128-CBC), and the database is
//! opened through rusqlite's bundled **SQLCipher** (the reference C library) —
//! no primitive is hand-rolled and no placeholder ever returns
//! plausible-but-wrong bytes. A wrong OS key, a wrong SQLCipher key, or a
//! corrupt blob is a typed [`SignalError`], never a fabricated key or plaintext.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod error;
pub mod keys;
pub mod paths;
pub mod records;
pub mod store;

pub use error::{Result, SignalError};
