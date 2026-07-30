# Purpose & Scope — signal-desktop-forensic

## Purpose

Give a DFIR analyst the decrypted contents of a Signal Desktop profile as typed,
timeline-ready records, and an anomaly grading over them — without hand-driving
SQLCipher, the OS keystore, and Signal's JSON schema.

## In scope

- Parse `config.json` (modern `encryptedKey`, legacy plaintext `key`).
- Parse the unencrypted `ephemeral.json` (theme/spell-check/locale + last window
  geometry — provenance and mild forensic context).
- Unwrap the SQLCipher key from `encryptedKey` given an OS Safe Storage
  `RecoveredKey` (via `chromium-safestorage-core`).
- Open `sql/db.sqlite` (SQLCipher 4) with the raw key; fail loud on a wrong key.
- Typed records from the DB: `Conversation`, `Message`, `Contact`,
  `Attachment` (from the modern `message_attachments` table and the legacy
  message JSON).
- A merged `TimelineEntry` stream ordered by timestamp.
- Anomaly findings (`signal-desktop-forensic`) in the normalized report model.

## Out of scope (for now)

- **Recovering the OS Safe Storage key itself** on a live host — that is
  `chromium-safestorage`'s job (Keychain / DPAPI / libsecret). This crate takes
  a `RecoveredKey` as input.
- **Decrypting attachment blobs** under `attachments.noindex` (per-attachment
  keys derived from the master key). Only attachment *metadata* is parsed here;
  blob decryption is a documented follow-up.
- Chromium `Local Storage` / `IndexedDB` app-state stores in the profile (owned
  by the `chromium-storage-forensic` / `browser-forensic` crates).

## Non-goals

No GUI, no live acquisition, no network. Pure-Rust library (plus the bundled
SQLCipher C library for the encrypted-DB read).
