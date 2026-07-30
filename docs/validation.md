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
(`id`, `conversationId`, `sent_at`, `received_at`, `received_at_ms`, `type`,
`body` for messages; `id`, `type`, `active_at` for conversations). Any divergence
fails loud with the mismatched rows.

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

## Source differential against DLEAPP (tier-2, column semantics)

The timestamp columns were reconciled against **DLEAPP**'s production Signal
Desktop artifact (`scripts/artifacts/signalMessages.py`), an independently
authored reference implementation. Its query selects **`received_at_ms`** and
formats that value as the message time; it never reads the bare `received_at`.
That matches Signal Desktop's own schema, where `received_at` is a
**monotonically increasing ordering counter** and `received_at_ms` is the
wall-clock receive time (`serverTimestamp` for server-stamped rows).

Our reader previously took `sent_at`, else `received_at` — so a row with no
`sent_at` published the counter as an epoch (a ~1970 timestamp in a forensic
timeline). The minted fixture had concealed it by writing an epoch into
`received_at`; it now carries small counters there and the epoch in
`received_at_ms`. Note the fixture's counters are *deliberately* small so a
confusion of the two columns is unmissable — that is **not** what a real profile
looks like: Signal seeds `receivedAtCounter` from `Date.now()` and then
increments, so a real `received_at` is an epoch-magnitude integer. The practical
consequence is that on real data the pre-fix defect published a
**plausible-but-wrong** time rather than an obvious 1970 — the more insidious
failure, and the reason the column identity matters more than the magnitude.

The reader's preference is `sent_at` → `received_at_ms` → `serverTimestamp` →
none, and `received_at` is retained and documented as the ordering value it is
(useful as a stable-ordering tiebreak, never as a time).

**Legacy revisions keep these times in the `json`, and they are read.** A schema
predating the columns still reads (they are probed via `PRAGMA table_info` and
projected as `NULL` when absent), and the wall-clock time is then taken from the
message `json` (`$.received_at_ms`, `$.serverTimestamp`) — the same
column-else-json rule the `isViewOnce`/`isErased` flags use. This is not a
courtesy fallback: Signal-Desktop migration 1270
(`1270-normalize-messages.std.ts`) *adds* those columns and backfills them with
`json_extract(json, '$.received_at_ms')`, which is only possible because every
earlier revision stored them in the json — so for any 2021–2025 profile the json
is the sole home of the receive time. A row with no wall-clock datum in either
place has no timestamp; it never degrades to the counter.

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
