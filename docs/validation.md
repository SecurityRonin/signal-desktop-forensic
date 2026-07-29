# Validation

## Oracle selection (the honesty rule)

The fleet honesty rule requires trying oracles in order and recording which one
actually yielded validation data.

**Step 1 — the real app on this host — SUCCEEDED (partial).** Signal Desktop is
installed on the development host
(`~/Library/Application Support/Signal`). Its real, app-authored artifacts were
copied to `/tmp/signal-oracle/` and used as a genuine tier-2 oracle for the
**key-store half** of the pipeline:

- **`config.json`** — real `encryptedKey`: a 166-hex-char (83-byte) value whose
  decoded bytes begin with the ASCII `v10` prefix. This confirms, on real
  app-authored bytes, the modern-Signal wire format the `config` parser and the
  key-unwrap path target (3-byte prefix + 80 bytes AES-128-CBC ciphertext = 64
  hex plaintext + one PKCS#7 pad block = a 32-byte SQLCipher raw key).
- **`sql/db.sqlite`** — the first 16 bytes are **not** `SQLite format 3\0`; they
  are high-entropy, confirming the database is genuinely SQLCipher-encrypted (a
  plaintext SQLite header would defeat the whole premise). This validates the
  "encrypted-at-rest, needs the key" posture, not the row schema.

**What step 1 did NOT yield: a decrypted real message corpus.** Decrypting the
real `db.sqlite` requires the live OS "Signal Safe Storage" Keychain secret. The
host's security policy (correctly) blocks materializing that live credential
into the toolchain, so the real decrypted messages/conversations were **not**
available as an oracle. Producing them would be authorized live-key decryption
on the analyst's own machine — out of scope for an unattended build.

**Steps 2 and 3 — record-schema validation.** Because no decrypted real corpus
and no public third-party Signal Desktop SQLCipher sample with a published key
were available, the **record parsers** (`Conversation`, `Message`, `Contact`,
`Attachment`, timeline) are validated **structurally** over a **minted SQLCipher
database** built in-test: a real SQLCipher 4 DB (via the same audited SQLCipher
library the reader uses) carrying rows in Signal's documented schema
(`messages`, `conversations`, the message `json` column), opened with a known
raw key and parsed back.

## Validation tier

**T2 overall, honestly bounded.**

| Path | Tier | Oracle |
|---|---|---|
| `config.json` parse + `encryptedKey` v10 shape | **T2** | Real app-authored `config.json` on host (bytes we did not author) |
| SQLCipher-at-rest posture | **T2** | Real app-authored `db.sqlite` header (non-plaintext) |
| Key unwrap (wrong key ⇒ loud error) | **T2** | Real v10 blob + audited RustCrypto AES-128-CBC; wrong key ⇒ PKCS#7 failure |
| SQLCipher open (wrong key ⇒ loud error) | **T2** | Reference SQLCipher library; wrong key ⇒ "not a database" |
| Record schema (`messages`/`conversations`/attachment JSON) | **T3→T2** | Minted SQLCipher DB in Signal's documented schema (self-constructed scenario; we chose the rows) |
| Reader row read reconciled against an independent decrypt+read | **T2** | The `sqlcipher` CLI (a separate SQLCipher build + process) over the same minted DB — see below |

The record-schema row is **not tier-1**: no independent party authored both the
artifact and the answer key. The schema itself is taken from Signal's
open-source and the Bilz "Forensic Gold Mine II" writeup (cited in the KNOWLEDGE
leaf), not invented — but the *values* are ours, so a real-world quirk (a schema
revision, an unusual `type`, an odd JSON shape) could be missed.

## Differential against the sqlcipher CLI

`core/tests/differential_sqlcipher.rs`, env-gated on **`SIGNAL_SQLCIPHER_ORACLE`**
(the path to a `sqlcipher` binary); it skips cleanly when the var is unset, so
the committed gate never depends on the tool.

The test mints a SQLCipher database (built with the reader's own bundled
SQLCipher, in Signal's documented `messages`/`conversations` schema, encrypted
with a known raw key), then decrypts and reads it **two independent ways**:

1. **Our reader** — `SignalStore::open_at` → `messages()` / `conversations()`.
2. **The `sqlcipher` CLI** — a separate process that sets the same
   `PRAGMA key = "x'…'"` and `SELECT`s the rows in `.mode json`.

It reconciles both directions: equal **counts**, and equal **contents** per row
(`id`, `conversationId`, `sent_at`, `received_at`, `type`, `body` for messages;
`id`, `type`, `active_at` for conversations). Any divergence fails loud with the
mismatched rows.

**Independence, stated honestly.** This is **tier-2**: we authored the fixture
and its rows, so it is not tier-1 (no independent party wrote both the artifact
and the answer key). What is genuinely independent is the **oracle**: the
`sqlcipher` CLI is a distinct SQLCipher build in a separate process. Two things
follow. (a) It independently reads the SQL rows, so agreement validates our
**SQL-layer read** (column selection, row→record mapping) against an outside
implementation rather than only against our own bundled library. (b) Because the
CLI links its own SQLCipher + OpenSSL, its ability to decrypt the DB our library
wrote also cross-checks that we produced a **spec-compliant SQLCipher-4
database** a different implementation can open — a real, if bounded, decrypt
cross-check. What it does **not** establish is real-world message-corpus
fidelity (the rows are ours, not a third party's) — that remains the T1 upgrade
below.

Run it:

```sh
SIGNAL_SQLCIPHER_ORACLE=$(command -v sqlcipher) \
  cargo test -p signal-desktop-core --test differential_sqlcipher -- --nocapture
```

Latest run: **3 messages + 2 conversations reconciled**, oracle
`sqlcipher 3.53.3 (SQLCipher 4.17.0 community)`.

## Robustness (fuzzing) — measured

One `cargo-fuzz` target per untrusted-input parser, built under the nightly
address sanitizer and smoke-run locally (20 s each):

| Target | Parser | Execs (local smoke) | Result |
|---|---|---|---|
| `fuzz_config` | `config.json` decode | ~4.6M | no crash |
| `fuzz_key_unwrap` | v10 key-unwrap path | ~3.2M | no crash |
| `fuzz_message_json` | attachment JSON | ~2.9M | no crash |

~10.7M total executions, zero panics — present-robustness evidence, paired with
the static `panic-free by lint` posture (`forbid(unsafe)`,
`unwrap_used`/`expect_used = deny`). Fuzzing tests robustness empirically; it does
not prove the absence of all panics.

## What would upgrade this to T1

1. A **public DFIR/DLEAPP Signal Desktop sample** (an `sql/db.sqlite` +
   `config.json` or a published raw key) authored by a third party — parse it
   and reconcile counts/contents against their ground truth.
2. **Authorized live-key decryption** of the on-host store (analyst-consented
   Keychain read), differentialed against Signal's own UI or an established tool
   (e.g. `signalbackup-tools`) for the same conversation set.

## Provenance

Real artifacts are documented in `tests/data/README.md`; they are **not
committed** (gitignored — they are a live user's private messages). The
committed test fixtures are the in-test minted SQLCipher databases, generated by
the test builders (no download URL — they are synthetic, see
`tests/data/README.md` for the exact builder functions).
