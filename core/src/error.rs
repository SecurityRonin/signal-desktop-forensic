//! The single typed error for the Signal Desktop reader.
//!
//! Every failure along the pipeline — a malformed `config.json`, a wrong OS
//! Safe Storage key that cannot unwrap the SQLCipher key, a wrong SQLCipher key
//! that cannot open the database, a malformed row — is a loud, typed
//! [`SignalError`]. The reader never fabricates a key, a plaintext, or a record:
//! a wrong/missing key is an error, never plausible-but-wrong bytes.

use thiserror::Error;

/// A Signal Desktop reader failure.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SignalError {
    /// A profile file could not be read from disk (carries the path).
    #[error("cannot read {path}: {source}")]
    ConfigRead {
        /// The path that failed.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// `config.json` is not valid JSON.
    #[error("config.json is not valid JSON: {0}")]
    ConfigJson(#[source] serde_json::Error),

    /// `ephemeral.json` is not valid JSON.
    #[error("ephemeral.json is not valid JSON: {0}")]
    EphemeralJson(#[source] serde_json::Error),

    /// `config.json` carries neither a modern `encryptedKey` nor a legacy `key`.
    #[error("config.json has no `encryptedKey` (modern) or `key` (legacy) field")]
    NoKeyField,

    /// The `encryptedKey` / legacy `key` field is not valid lowercase hex.
    #[error("config key field is not valid hex (offending prefix: {prefix})")]
    ConfigKeyNotHex {
        /// Up to the first 8 chars of the offending value, for diagnosis.
        prefix: String,
    },

    /// Unwrapping the SQLCipher key from `encryptedKey` failed — the OS Safe
    /// Storage key was wrong or the blob is corrupt. A loud failure, never a
    /// guessed key (carries the underlying `chromium-safestorage` reason).
    #[error("cannot unwrap the SQLCipher key from encryptedKey: {0}")]
    KeyUnwrap(#[source] chromium_safestorage_core::SafeStorageError),

    /// The unwrapped/legacy SQLCipher key is not the expected 64 lowercase-hex
    /// characters (a Signal raw 32-byte key). Carries the actual length so the
    /// analyst can see what was recovered instead of a fabricated key.
    #[error("recovered SQLCipher key is not 64 hex chars (got {len} chars)")]
    BadSqlcipherKeyLength {
        /// The length actually recovered.
        len: usize,
    },

    /// Opening the SQLCipher database failed. The most common cause is a wrong
    /// SQLCipher key (SQLCipher reports the decrypted header as "not a
    /// database"); a wrong key fails LOUD here rather than returning empty rows.
    #[error("cannot open the SQLCipher database (wrong key or corrupt DB): {0}")]
    DbOpen(#[source] rusqlite::Error),

    /// A query or row decode against the opened database failed.
    #[error("SQLCipher query failed: {0}")]
    Query(#[source] rusqlite::Error),
}

/// Convenience alias for the reader's fallible operations.
pub type Result<T> = std::result::Result<T, SignalError>;
