# Test data — signal-desktop-forensic

Provenance for every test artifact, per the fleet Test-Data Provenance Standard.
Cross-references the fleet catalog (`ronin-issen/docs/test-data-catalog.md`); it
is the machine index, this is the co-located human detail.

## Real artifacts (REAL-self, gitignored — NOT committed)

Signal Desktop is installed on the development host. Its real store was copied to
`/tmp/signal-oracle/` for validation (see `docs/validation.md`). These are a
live user's private messages — **never committed** (see `.gitignore`).

#### config.json (real)
- **Source:** the on-host Signal Desktop profile,
  `~/Library/Application Support/Signal/config.json`.
- **Identity/contents:** modern-Signal key store — a single `encryptedKey`
  (166 hex chars / 83 bytes, decoded prefix ASCII `v10`), plus
  `mediaPermissions` / `mediaCameraPermissions`. No legacy plaintext `key`.
- **Classification:** REAL-self (`~` — real app-authored, host-specific).
- **Use case:** tier-2 confirmation of the `config.json` schema and the
  `encryptedKey` v10 wire format (see `docs/validation.md`).

#### sql/db.sqlite (real, header only)
- **Source:** `~/Library/Application Support/Signal/sql/db.sqlite` (~295 MB).
- **Identity:** first 16 bytes are high-entropy (NOT `SQLite format 3\0`),
  confirming SQLCipher encryption at rest.
- **Classification:** REAL-self. Not decryptable in the unattended build (the
  live Keychain secret is policy-blocked from materialization).
- **Use case:** tier-2 confirmation of the encrypted-at-rest posture only.

## Synthetic fixtures (SYNTHETIC — minted in-test, no download URL)

The record parsers are validated over **minted SQLCipher databases** built by
the test code (a real SQLCipher 4 DB via the reader's own audited SQLCipher
library, opened with a known raw key). There is no committed binary fixture —
the DB is generated per test run.

- **Generator:** `signal-desktop-core` test builder
  `core/src/store.rs` → `#[cfg(test)] fn mint_signal_db(...)` (and the analyzer's
  `forensic/tests/` builder). Rows follow Signal's documented schema
  (`messages`, `conversations`, message `json` column).
- **Classification:** SYNTHETIC (`✓` — generator committed in-repo).
- **Use case:** structural validation of `Conversation` / `Message` / `Contact`
  / `Attachment` / timeline parsing, and the wrong-key-fails-loud paths.

## Schema source

Signal's DB schema is taken from Signal Desktop's open-source and Alexander
Bilz, *A Forensic Gold Mine II: Forensic Analysis of Signal Messenger on
Windows 10* (cited in `forensicnomicon-core::messenger_desktop`), not invented.
