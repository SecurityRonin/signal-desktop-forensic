# signal-desktop-forensic

Decrypt and parse a **Signal Desktop** profile: recover the SQLCipher key from
`config.json` via the OS Safe Storage, open `sql/db.sqlite`, and read messages,
conversations, contacts, and attachment metadata into typed records and a
timeline — then grade them into normalized forensic findings.

- **Reader:** [`signal-desktop-core`](https://crates.io/crates/signal-desktop-core)
- **Analyzer:** [`signal-desktop-forensic`](https://crates.io/crates/signal-desktop-forensic)

See [Validation](validation.md) for the oracle and validation tier, and
[Purpose & Scope](PRD.md) for what the crate does and does not cover.

## Pipeline

```text
OS Safe Storage key ─▶ decrypt config.json encryptedKey (v10) ─▶ SQLCipher raw key
                     ─▶ PRAGMA key ─▶ sql/db.sqlite ─▶ records + timeline ─▶ findings
```

All crypto is audited (RustCrypto AES-128-CBC for the key unwrap; the reference
SQLCipher library for the database). A wrong or missing key is a typed error,
never fabricated plaintext.
