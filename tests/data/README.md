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

- **Generators (in-code, no external command) — three, deliberately kept in sync:**
  - `core/src/store.rs:256` — `#[cfg(test)] testsupport::mint_signal_db(db_path)`, the
    canonical builder.
  - `core/tests/differential_sqlcipher.rs:50` — `mint_signal_db(db_path)`, a mirror.
    The `cfg(test)` builder above is unreachable from an integration-test crate, so
    the schema + rows are reproduced there on purpose.
  - `forensic/src/analyze.rs:228` — `#[cfg(test)] fn mint_db(path, key_hex)`, the
    analyzer-side builder.
- **Fixture key (ground truth):**
  `FIXTURE_KEY_HEX = 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`
  (raw SQLCipher key, set via `PRAGMA key = "x'…'"`).
- **Ground-truth rows written by `mint_signal_db`:** two `conversations` —
  `conv-alice` (`private`, `active_at` 1700000000000, `profileName` Alice, `e164`
  `+15551230001`, `serviceId` `uuid-alice`) and `conv-team` (`group`, `active_at`
  1700000500000, name `Team`); three `messages` — `msg-1` incoming `hey there`
  (`sent_at` 1700000100000), `msg-2` outgoing `photo!` (`sent_at` 1700000200000) with
  one `image/jpeg` attachment (`pic.jpg`, 20480 bytes, path `ab/abcdef0123`), and
  `msg-3` incoming `gm all` in the group (`sent_at` 1700000600000).
- **Column semantics the fixture reproduces (load-bearing):** `received_at` holds a
  small monotonically increasing **ordering counter** (1, 2, 3), and the wall-clock
  receive time is in **`received_at_ms`** (1700000100050, 1700000200010,
  1700000600030) — Signal Desktop's real semantics. An epoch written into
  `received_at` would let a reader that mistakes the counter for a time pass
  (circular validation), so the fixture keeps the two distinct.
- **Extra shapes minted by the sibling builders in `core/src/store.rs`:**
  - `testsupport::add_receive_only_messages(db)` — appends `msg-recv-only`
    (`sent_at` NULL, `received_at` counter 42, `received_at_ms` 1700000900000) and
    `msg-server-only` (`sent_at` NULL, `received_at` counter 43, `received_at_ms`
    NULL, `serverTimestamp` 1700001000000): the rows whose time can only come from a
    wall-clock column.
  - `testsupport::mint_legacy_signal_db(db)` — a legacy revision whose `messages`
    table has **no** `received_at_ms`/`serverTimestamp` column, carrying
    `msg-legacy-sent` (`sent_at` 1700000100000, counter 6) and `msg-legacy-recv`
    (`sent_at` NULL, counter 7): the graceful-degradation path.
- **Classification:** SYNTHETIC (`✓` — generator committed in-repo).
- **Use case:** structural validation of `Conversation` / `Message` / `Contact`
  / `Attachment` / timeline parsing, and the wrong-key-fails-loud paths.

## Independent oracle — the `sqlcipher` CLI (tier-2)

`core/tests/differential_sqlcipher.rs::differential_reader_matches_sqlcipher_cli`
decrypts and reads the same minted DB two independent ways — our `SignalStore` and a
separate **`sqlcipher` CLI** process — and reconciles the rows. Because the CLI links
its own SQLCipher/OpenSSL build, agreement also cross-checks that our bundled library
emitted a spec-compliant SQLCipher-4 file a different implementation can open.

```sh
SIGNAL_SQLCIPHER_ORACLE=$(which sqlcipher) cargo test -p signal-desktop-core --test differential_sqlcipher
```

Skips cleanly (prints a skip, passes) when `SIGNAL_SQLCIPHER_ORACLE` is unset, so the
committed gate never depends on the tool being installed.

## Env gates for the real host artifacts

| Env var | Purpose |
|---|---|
| `SIGNAL_PROFILE` | path to a real Signal Desktop profile directory (`config.json` lives here) |
| `SIGNAL_DB` | path to a real `sql/db.sqlite` (overrides the one under `SIGNAL_PROFILE`) |

Consumed by `core/tests/real_oracle.rs` —
`real_config_json_parses_and_is_modern_v10`,
`real_db_is_sqlcipher_and_rejects_a_wrong_key_loud`, `real_ephemeral_json_parses`.
Both skip cleanly when unset.

## Schema source

Signal's DB schema is taken from Signal Desktop's open-source and Alexander
Bilz, *A Forensic Gold Mine II: Forensic Analysis of Signal Messenger on
Windows 10* (cited in `forensicnomicon-core::messenger_desktop`), not invented.
