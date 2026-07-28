#![no_main]
//! Fuzz the SQLCipher key-unwrap path: arbitrary OS key + arbitrary v10 blob in,
//! never a panic (only typed errors or a validated key).

use chromium_safestorage_core::RecoveredKey;
use libfuzzer_sys::fuzz_target;
use signal_desktop_core::{unwrap_sqlcipher_key, SignalConfig};

fuzz_target!(|data: &[u8]| {
    // First 16 bytes = the OS Safe Storage AES-128 key; the rest = the
    // encrypted-key blob. Too-short inputs still must not panic.
    if data.len() < 16 {
        return;
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&data[..16]);
    let blob = data[16..].to_vec();

    let config = SignalConfig {
        encrypted_key: Some(blob),
        legacy_key_hex: None,
    };
    let _ = unwrap_sqlcipher_key(&RecoveredKey::Aes128Cbc(key), &config);
});
