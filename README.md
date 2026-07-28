# signal-desktop-forensic

[![Crates.io core](https://img.shields.io/crates/v/signal-desktop-core.svg?label=signal-desktop-core)](https://crates.io/crates/signal-desktop-core)
[![Crates.io forensic](https://img.shields.io/crates/v/signal-desktop-forensic.svg?label=signal-desktop-forensic)](https://crates.io/crates/signal-desktop-forensic)
[![Docs](https://img.shields.io/badge/docs-signal--desktop--forensic-blue)](https://securityronin.github.io/signal-desktop-forensic/)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/signal-desktop-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/signal-desktop-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Security advisories](https://img.shields.io/badge/advisories-clean-success.svg)](https://rustsec.org/)

**Decrypt a Signal Desktop profile and read its messages — key recovery,
SQLCipher, and Signal's schema handled for you.**

Signal Desktop keeps every message, conversation, contact, and attachment record
in one **SQLCipher-encrypted** database. The key is not in the clear: it is
wrapped inside `config.json` by the OS Safe Storage. This crate walks the whole
chain and hands you typed records.

```rust,no_run
use signal_desktop_core::{config::SignalConfig, keys::unwrap_sqlcipher_key, store::SignalStore};
use chromium_safestorage_core::RecoveredKey;

# fn demo(profile: &std::path::Path, os_key: RecoveredKey) -> signal_desktop_core::Result<()> {
// 1. Parse config.json and unwrap the SQLCipher key with the OS Safe Storage key.
let config = SignalConfig::from_profile(profile)?;
let sqlcipher_key = unwrap_sqlcipher_key(&os_key, &config)?;

// 2. Open the encrypted database and read typed records + a timeline.
let store = SignalStore::open_profile(profile, &sqlcipher_key)?;
for msg in store.messages()? {
    println!("{} [{}] {}", msg.sent_at.unwrap_or(0), msg.direction, msg.body.unwrap_or_default());
}
for entry in store.timeline()? {
    println!("{:?}", entry);
}
# Ok(())
# }
```

A **wrong or missing key fails loud** — a typed `SignalError`, never empty rows
and never fabricated plaintext. All crypto is audited: RustCrypto AES-128-CBC
for the `encryptedKey` unwrap, the reference SQLCipher library for the database.

## The two crates

| Crate | Role |
|---|---|
| `signal-desktop-core` | Reader: recover key, open the DB, expose `Conversation` / `Message` / `Contact` / `Attachment` + a `TimelineEntry` stream. No findings. |
| `signal-desktop-forensic` | Analyzer: grade the records into normalized `forensicnomicon` findings (consistent-with language, never verdicts). |

## Pipeline

```text
OS Safe Storage key ─▶ decrypt config.json encryptedKey (v10, AES-128-CBC)
                    ─▶ SQLCipher raw key (64 hex = 32 bytes)
                    ─▶ PRAGMA key ─▶ sql/db.sqlite
                    ─▶ messages · conversations · contacts · attachments · timeline
```

The OS Safe Storage key itself is recovered by
[`chromium-safestorage`](https://github.com/SecurityRonin/chromium-safestorage)
(macOS Keychain / Windows DPAPI / Linux libsecret); this crate takes the
`RecoveredKey` as input.

## Trust, but verify

- **Input-fuzzed.** One `cargo-fuzz` target per parsed structure — the
  `config.json` decode, the v10 key-unwrap path, and the per-message JSON —
  smoke-run on every push, time-boxed on a schedule. Invariant: never panic on
  arbitrary bytes.
- **Panic-free by lint.** `unsafe_code = forbid`, `unwrap_used`/`expect_used =
  deny` in production, bounded reads via `safe-read`.
- **Validated against the real app's bytes.** The `config.json` schema and the
  `encryptedKey` v10 format are confirmed against a real on-host Signal profile;
  record parsing is validated over a minted SQLCipher DB in Signal's documented
  schema. See [`docs/validation.md`](docs/validation.md) for the honest tier.

---

[Privacy Policy](https://securityronin.github.io/signal-desktop-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/signal-desktop-forensic/terms/) · © 2026 Security Ronin Ltd
