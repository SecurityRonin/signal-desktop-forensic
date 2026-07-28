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
use signal_desktop_core::{SignalError, SignalStore, SqlcipherKey};

fn profile() -> Option<PathBuf> {
    std::env::var_os("SIGNAL_PROFILE").map(PathBuf::from)
}

/// The real encrypted `db.sqlite`, at `$SIGNAL_DB` or `$SIGNAL_PROFILE/db.sqlite`
/// or the standard `$SIGNAL_PROFILE/sql/db.sqlite`.
fn real_db() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SIGNAL_DB") {
        return Some(PathBuf::from(p));
    }
    let profile = profile()?;
    for rel in ["sql/db.sqlite", "db.sqlite"] {
        let candidate = profile.join(rel);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
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

#[test]
fn real_db_is_sqlcipher_and_rejects_a_wrong_key_loud() {
    let Some(db) = real_db() else {
        eprintln!("no real db.sqlite (SIGNAL_DB / SIGNAL_PROFILE) — skipping");
        return;
    };
    // A wrong key against the REAL encrypted database must fail loud (DbOpen),
    // never open to zero rows — proving the store is genuinely SQLCipher and the
    // wrong-key path works on real app-authored bytes (not just minted fixtures).
    let wrong =
        SqlcipherKey::from_hex("00000000000000000000000000000000000000000000000000000000deadbeef")
            .unwrap();
    let result = SignalStore::open_at(&db, &wrong);
    assert!(
        matches!(result, Err(SignalError::DbOpen(_))),
        "wrong key on the real encrypted DB must be a loud DbOpen error"
    );
    eprintln!("real oracle OK: real db.sqlite rejected a wrong SQLCipher key loudly");
}
