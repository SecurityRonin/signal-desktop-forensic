//! Unwrap the SQLCipher raw key from `config.json`.
//!
//! Modern Signal: the `encryptedKey` v10 blob is decrypted with the OS Safe
//! Storage key (a [`RecoveredKey`] from `chromium-safestorage`) to yield 64
//! lowercase-hex characters — the SQLCipher 32-byte raw key. Legacy Signal: the
//! plaintext `key` is already that hex string.
//!
//! The unwrap is audited crypto (RustCrypto AES-128-CBC, via
//! `chromium-safestorage`). A wrong OS key, a wrong-length result, or a non-hex
//! result is a loud [`SignalError`] — never a fabricated key.

use chromium_safestorage_core::RecoveredKey;

use crate::config::SignalConfig;
use crate::error::{Result, SignalError};

/// A validated Signal SQLCipher raw key: exactly 64 lowercase-hex characters.
///
/// `Debug` is redacted so key material never lands in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct SqlcipherKey {
    hex: String,
}

impl std::fmt::Debug for SqlcipherKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqlcipherKey([64 hex chars redacted])")
    }
}

impl SqlcipherKey {
    /// Validate a 64-lowercase-hex-char SQLCipher key.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        // A Signal SQLCipher raw key is exactly 32 bytes = 64 hex chars.
        if hex_str.len() != 64 {
            return Err(SignalError::BadSqlcipherKeyLength { len: hex_str.len() });
        }
        // Must actually be hex (decode confirms it); normalize to lowercase so
        // the PRAGMA is deterministic.
        let lower = hex_str.to_ascii_lowercase();
        if hex::decode(&lower).is_err() {
            return Err(SignalError::ConfigKeyNotHex {
                prefix: hex_str.chars().take(8).collect(),
            });
        }
        Ok(Self { hex: lower })
    }

    /// The key as a SQLCipher `PRAGMA key` argument: `x'<64 hex>'` (raw key, no
    /// KDF), matching Signal's SQLCipher 4 usage.
    #[must_use]
    pub fn as_pragma(&self) -> String {
        format!("x'{}'", self.hex)
    }

    /// The raw 64-hex-char key string.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

/// Recover the SQLCipher key: legacy plaintext key if present, otherwise unwrap
/// the modern `encryptedKey` with the OS Safe Storage [`RecoveredKey`].
pub fn unwrap_sqlcipher_key(
    recovered: &RecoveredKey,
    config: &SignalConfig,
) -> Result<SqlcipherKey> {
    // Legacy path: the key is already the plaintext hex string.
    if let Some(legacy) = &config.legacy_key_hex {
        return SqlcipherKey::from_hex(legacy);
    }

    // Modern path: decrypt the v10 blob with the OS Safe Storage key. A wrong
    // key surfaces as a padding failure inside decrypt_cookie — loud, never a
    // fabricated key.
    let Some(blob) = &config.encrypted_key else {
        return Err(SignalError::NoKeyField);
    };
    let plaintext = recovered
        .decrypt_cookie(blob)
        .map_err(SignalError::KeyUnwrap)?;

    // The decrypted plaintext is the ASCII hex key. A wrong-but-valid-padding
    // result, or a truncated key, fails the length/hex check below — never
    // proceeds with a guessed key.
    let hex_str =
        std::str::from_utf8(&plaintext).map_err(|_| SignalError::BadSqlcipherKeyLength {
            len: plaintext.len(),
        })?;
    SqlcipherKey::from_hex(hex_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use cbc::Encryptor;
    use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes128CbcEnc = Encryptor<Aes128>;
    const CBC_IV: [u8; 16] = [0x20; 16];
    const KEY16: [u8; 16] = *b"0123456789abcdef";
    // A valid 64-hex-char SQLCipher key (what a decrypted encryptedKey contains).
    const SQLKEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// Mint a Chromium v10 blob: `"v10"` + AES-128-CBC(key, IV=16 spaces, PKCS7).
    fn mint_v10(key: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let pad = 16 - (buf.len() % 16);
        buf.resize(buf.len() + pad, 0);
        let ct = Aes128CbcEnc::new(key.into(), &CBC_IV.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .to_vec();
        let mut blob = b"v10".to_vec();
        blob.extend_from_slice(&ct);
        blob
    }

    fn config_with_encrypted(blob: Vec<u8>) -> SignalConfig {
        SignalConfig {
            encrypted_key: Some(blob),
            legacy_key_hex: None,
        }
    }

    #[test]
    fn from_hex_accepts_64_hex_and_builds_pragma() {
        let k = SqlcipherKey::from_hex(SQLKEY_HEX).unwrap();
        assert_eq!(k.hex(), SQLKEY_HEX);
        assert_eq!(k.as_pragma(), format!("x'{SQLKEY_HEX}'"));
    }

    #[test]
    fn from_hex_rejects_wrong_length_loud() {
        assert!(matches!(
            SqlcipherKey::from_hex("deadbeef"),
            Err(SignalError::BadSqlcipherKeyLength { len: 8 })
        ));
    }

    #[test]
    fn from_hex_rejects_non_hex_loud() {
        let sixty_four_non_hex: String = "z".repeat(64);
        assert!(matches!(
            SqlcipherKey::from_hex(&sixty_four_non_hex),
            Err(SignalError::ConfigKeyNotHex { .. })
        ));
    }

    #[test]
    fn debug_is_redacted() {
        let k = SqlcipherKey::from_hex(SQLKEY_HEX).unwrap();
        let dbg = format!("{k:?}");
        assert!(
            !dbg.contains(SQLKEY_HEX),
            "Debug leaked key material: {dbg}"
        );
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn legacy_plaintext_key_passthrough() {
        let cfg = SignalConfig {
            encrypted_key: None,
            legacy_key_hex: Some(SQLKEY_HEX.to_string()),
        };
        // The OS key is irrelevant for the legacy path.
        let k = unwrap_sqlcipher_key(&RecoveredKey::Aes128Cbc(KEY16), &cfg).unwrap();
        assert_eq!(k.hex(), SQLKEY_HEX);
    }

    #[test]
    fn modern_encrypted_key_roundtrips() {
        let blob = mint_v10(&KEY16, SQLKEY_HEX.as_bytes());
        let cfg = config_with_encrypted(blob);
        let k = unwrap_sqlcipher_key(&RecoveredKey::Aes128Cbc(KEY16), &cfg).unwrap();
        assert_eq!(k.hex(), SQLKEY_HEX);
    }

    #[test]
    fn wrong_os_key_fails_loud() {
        let blob = mint_v10(&KEY16, SQLKEY_HEX.as_bytes());
        let cfg = config_with_encrypted(blob);
        let wrong = RecoveredKey::Aes128Cbc(*b"WRONGwrongWRONGw");
        // Wrong key ⇒ PKCS#7 padding failure inside decrypt_cookie ⇒ loud, never
        // a fabricated key.
        assert!(matches!(
            unwrap_sqlcipher_key(&wrong, &cfg),
            Err(SignalError::KeyUnwrap(_))
        ));
    }

    #[test]
    fn recovered_wrong_length_fails_loud() {
        // A blob that correctly decrypts to a NON-64-char string ⇒ loud length error.
        let blob = mint_v10(&KEY16, b"tooshort");
        let cfg = config_with_encrypted(blob);
        assert!(matches!(
            unwrap_sqlcipher_key(&RecoveredKey::Aes128Cbc(KEY16), &cfg),
            Err(SignalError::BadSqlcipherKeyLength { len: 8 })
        ));
    }

    #[test]
    fn no_key_at_all_fails_loud() {
        let cfg = SignalConfig {
            encrypted_key: None,
            legacy_key_hex: None,
        };
        assert!(matches!(
            unwrap_sqlcipher_key(&RecoveredKey::Aes128Cbc(KEY16), &cfg),
            Err(SignalError::NoKeyField)
        ));
    }
}
