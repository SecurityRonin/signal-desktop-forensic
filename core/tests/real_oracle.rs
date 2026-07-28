//! Tier-2 real-artifact oracle, env-gated (skips cleanly when absent).
//!
//! Point `SIGNAL_PROFILE` at a real Signal Desktop profile directory (e.g. a
//! copy under `/tmp`, or `~/Library/Application Support/Signal`) to validate the
//! parsers against genuine app-authored bytes. In CI, without the env var, these
//! tests skip — the committed gate runs on minted fixtures. See
//! `docs/validation.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use signal_desktop_core::config::SignalConfig;

fn profile() -> Option<PathBuf> {
    std::env::var_os("SIGNAL_PROFILE").map(PathBuf::from)
}

#[test]
fn real_config_json_parses_and_is_modern_v10() {
    let Some(profile) = profile() else {
        eprintln!("SIGNAL_PROFILE not set — skipping real-artifact oracle");
        return;
    };
    let cfg = SignalConfig::from_profile(&profile).expect("real config.json parses");
    // Modern Signal wraps the SQLCipher key; the encryptedKey is a Chromium v10
    // blob: 3-byte 'v10' prefix + AES-128-CBC ciphertext.
    let ek = cfg
        .encrypted_key
        .as_ref()
        .expect("modern config carries encryptedKey");
    assert_eq!(&ek[..3], b"v10", "real encryptedKey must start with v10");
    // 3-byte prefix + a whole number of 16-byte AES-CBC blocks.
    assert_eq!(
        (ek.len() - 3) % 16,
        0,
        "ciphertext must be a whole number of AES blocks (got {} bytes)",
        ek.len() - 3
    );
    eprintln!(
        "real oracle OK: encryptedKey {} bytes (v10 + {} ciphertext bytes)",
        ek.len(),
        ek.len() - 3
    );
}
