# 2. The SQLCipher key pipeline — audited crypto only, wrong key fails loud

Date: 2026-07-29

## Status

Accepted.

## Context

Modern Signal Desktop does not store its SQLCipher key in the clear. The chain
is:

1. `config.json` holds `encryptedKey` — a Chromium **v10** blob (3-byte `v10`
   prefix + AES-128-CBC ciphertext, IV = 16 space bytes, PKCS#7).
2. The AES-128 key that decrypts it is the OS **Safe Storage** key (Electron
   `safeStorage`): macOS Keychain "Signal Safe Storage", Windows DPAPI, Linux
   libsecret.
3. The decrypted plaintext is the SQLCipher **raw key**: 64 lowercase-hex
   characters = a 32-byte key, applied as `PRAGMA key = "x'…'"` with SQLCipher 4
   defaults.

Two crypto decisions had to be made: how to unwrap the config blob, and how to
decrypt the database.

## Decision

**Reuse audited implementations for both; never hand-roll, never a placeholder.**

- The `encryptedKey` unwrap goes through `chromium-safestorage-core`
  (RecoveredKey → `decrypt_cookie` = RustCrypto AES-128-CBC). The fleet crate
  already owns the OS-key recovery per platform.
- The database is opened through **rusqlite's bundled SQLCipher** (the reference
  SQLCipher C library + vendored OpenSSL). SQLCipher's KDF/HMAC/page cipher is
  the audited reference implementation; re-deriving it by hand from RustCrypto
  primitives would be exactly the placeholder-crypto risk the fleet forbids.

**A wrong or missing key fails loud.** A wrong OS Safe Storage key yields
PKCS#7 padding failure (`SignalError::KeyUnwrap`); a recovered value of the
wrong length is `BadSqlcipherKeyLength { len }`; a wrong SQLCipher key makes
SQLCipher report the decrypted header as "not a database"
(`SignalError::DbOpen`). None of these paths returns empty records or fabricated
plaintext — the failure is a typed error carrying what was actually recovered.

## Consequences

The repo carries the vendored-OpenSSL + SQLCipher C build (a ~1-minute first
compile) — accepted per the fleet Batteries-Included rule rather than shipping a
partial hand-rolled decryptor. The unwrap step depends only on `-core` fleet
crypto crates, so a bug fix in the OS-key recovery propagates here for free.
