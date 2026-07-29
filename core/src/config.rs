//! Parse Signal Desktop's `config.json` — the key store.
//!
//! Two schemas exist:
//!
//! - **Modern:** an `encryptedKey` string — a hex-encoded Chromium v10 blob
//!   wrapped by the OS Safe Storage. Decoded here to raw bytes; unwrapped to the
//!   SQLCipher key in [`crate::keys`].
//! - **Legacy:** a plaintext `key` string — the SQLCipher raw key as 64 hex
//!   chars, stored in the clear (older Signal builds).
//!
//! This module only *parses* the file. It never decrypts, and a file carrying
//! neither field is a loud [`SignalError::NoKeyField`], never a silent empty.

use std::path::Path;

use serde::Deserialize;

use crate::error::{Result, SignalError};

/// The parsed contents of `config.json` relevant to decryption.
#[derive(Debug, Clone)]
pub struct SignalConfig {
    /// Decoded bytes of the modern `encryptedKey` (a v10 blob), if present.
    pub encrypted_key: Option<Vec<u8>>,
    /// The legacy plaintext `key` (64 hex chars = the SQLCipher raw key), if
    /// present. Validated as a proper key in [`crate::keys`], not here.
    pub legacy_key_hex: Option<String>,
}

#[derive(Deserialize)]
struct RawConfig {
    #[serde(rename = "encryptedKey", default)]
    encrypted_key: Option<String>,
    #[serde(rename = "key", default)]
    key: Option<String>,
}

impl SignalConfig {
    /// Parse `config.json` from its raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: RawConfig = serde_json::from_slice(bytes).map_err(SignalError::ConfigJson)?;

        let encrypted_key = match raw.encrypted_key {
            Some(hex_str) => Some(decode_hex(&hex_str)?),
            None => None,
        };

        if encrypted_key.is_none() && raw.key.is_none() {
            return Err(SignalError::NoKeyField);
        }

        Ok(Self {
            encrypted_key,
            legacy_key_hex: raw.key,
        })
    }

    /// Read and parse `config.json` from a Signal profile directory.
    ///
    /// The relative path (`config.json`) is taken from the KNOWLEDGE leaf via
    /// [`crate::paths`], not hardcoded here.
    pub fn from_profile(profile: &Path) -> Result<Self> {
        let rel = crate::paths::config_relpath().unwrap_or("config.json");
        let path = profile.join(rel);
        let bytes = std::fs::read(&path).map_err(|source| SignalError::ConfigRead {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_bytes(&bytes)
    }

    /// Whether the config carries any usable key material.
    #[must_use]
    pub fn has_key(&self) -> bool {
        self.encrypted_key.is_some() || self.legacy_key_hex.is_some()
    }
}

/// Decode a lowercase-or-uppercase hex string, mapping a non-hex value to a
/// loud [`SignalError::ConfigKeyNotHex`] carrying the offending prefix.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|_| SignalError::ConfigKeyNotHex {
        prefix: s.chars().take(8).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // "763130" is ASCII "v10" — the Chromium blob prefix, on a real config value.
    const MODERN: &str = r#"{"encryptedKey":"7631300739c14f15","mediaPermissions":true}"#;

    #[test]
    fn parses_modern_encrypted_key() {
        let c = SignalConfig::from_bytes(MODERN.as_bytes()).unwrap();
        let ek = c.encrypted_key.as_ref().expect("encrypted_key");
        assert_eq!(&ek[..3], b"v10");
        assert!(c.legacy_key_hex.is_none());
        assert!(c.has_key());
    }

    #[test]
    fn parses_legacy_plaintext_key() {
        let json = r#"{"key":"0123456789abcdef"}"#;
        let c = SignalConfig::from_bytes(json.as_bytes()).unwrap();
        assert_eq!(c.legacy_key_hex.as_deref(), Some("0123456789abcdef"));
        assert!(c.encrypted_key.is_none());
    }

    #[test]
    fn no_key_field_is_loud() {
        let json = r#"{"mediaPermissions":true}"#;
        assert!(matches!(
            SignalConfig::from_bytes(json.as_bytes()),
            Err(SignalError::NoKeyField)
        ));
    }

    #[test]
    fn bad_hex_encrypted_key_is_loud() {
        let json = r#"{"encryptedKey":"zzzz"}"#;
        assert!(matches!(
            SignalConfig::from_bytes(json.as_bytes()),
            Err(SignalError::ConfigKeyNotHex { .. })
        ));
    }

    #[test]
    fn invalid_json_is_loud() {
        assert!(matches!(
            SignalConfig::from_bytes(b"not json at all"),
            Err(SignalError::ConfigJson(_))
        ));
    }

    #[test]
    fn from_profile_reads_config_json() {
        let dir = tempfile::tempdir().unwrap();
        // config_relpath() is "config.json" (from the KNOWLEDGE leaf).
        std::fs::write(dir.path().join("config.json"), MODERN).unwrap();
        let c = SignalConfig::from_profile(dir.path()).unwrap();
        assert!(c.has_key());
        assert_eq!(&c.encrypted_key.unwrap()[..3], b"v10");
    }

    #[test]
    fn from_profile_missing_file_is_loud() {
        // An empty profile dir (no config.json) is a loud ConfigRead, never a
        // silent empty config.
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            SignalConfig::from_profile(dir.path()),
            Err(SignalError::ConfigRead { .. })
        ));
    }
}
