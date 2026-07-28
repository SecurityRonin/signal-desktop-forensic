# 3. Panic-free, fuzzed parsing of untrusted Signal artifacts

Date: 2026-07-29

## Status

Accepted.

## Context

Every input this crate parses is attacker-controllable: `config.json`, the
`encryptedKey` blob, and — once decrypted — the SQLCipher rows and the JSON
`json` column of each message. A malformed artifact must never panic, read out
of bounds, or silently produce a wrong record.

## Decision

Adopt the fleet Paranoid Gatekeeper posture:

- `unsafe_code = "forbid"` across the workspace (earns the `unsafe-forbidden`
  badge — the crate holds no `unsafe`).
- `clippy::unwrap_used` / `expect_used = "deny"` in production code; tests may
  unwrap.
- This crate parses **no raw binary offsets**: structured data arrives through
  `serde_json` (the JSON columns / `config.json`) and `rusqlite` (typed SQLCipher
  columns), so there is no hand-rolled `bytes.rs` and `safe-read` is not pulled.
  Should a future feature parse a raw byte layout, its integer/length reads must
  go through the fleet `safe-read` bounded readers — never a hand-rolled reader.
- One `cargo-fuzz` target per parsed structure: `fuzz_config` (the `config.json`
  JSON + hex decode), `fuzz_key_unwrap` (the v10-blob unwrap path), and
  `fuzz_message_json` (the per-message JSON decode). Invariant: never panic on
  arbitrary bytes.

## Consequences

Robustness is enforced statically (lints) and empirically (fuzzing). The
SQLCipher page cipher itself is not fuzzed here — it is the audited SQLCipher C
library (see ADR-0002); the fuzz surface is our own parsing on top of it.
