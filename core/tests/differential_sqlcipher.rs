//! Differential validation against the independent `sqlcipher` CLI (tier-2).
//!
//! Env-gated on `SIGNAL_SQLCIPHER_ORACLE` (path to the `sqlcipher` binary);
//! skips cleanly when unset, so the committed gate never depends on it.
//!
//! What it proves: a minted SQLCipher database (built with the reader's own
//! bundled SQLCipher, in Signal's documented `messages`/`conversations` schema)
//! is decrypted and read two independent ways — by OUR `SignalStore` reader and
//! by a separate `sqlcipher` CLI process — and the rows reconcile (same counts,
//! same message/conversation contents). Because the CLI links its own
//! SQLCipher/OpenSSL build, agreement also cross-checks that our bundled library
//! produced a spec-compliant SQLCipher-4 database a different implementation can
//! decrypt. Divergence fails loud. See `docs/validation.md`.
//!
//! The minted dataset mirrors the canonical builder in
//! `core/src/store.rs` (`#[cfg(test)] testsupport::mint_signal_db`) — that
//! function is test-cfg-gated and therefore not reachable from an integration
//! crate, so the schema + rows are reproduced here (kept in sync deliberately).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use rusqlite::Connection;
use serde_json::Value;

use signal_desktop_core::{ConversationKind, SignalStore, SqlcipherKey};

/// A comparable message row:
/// `(id, conversationId, sent_at, received_at, received_at_ms, type, body)`.
type MsgRow = (
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    String,
    Option<String>,
);

/// The known raw key the fixture is encrypted with (mirrors
/// `store.rs::testsupport::FIXTURE_KEY_HEX`).
const FIXTURE_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// Mint a real SQLCipher DB in Signal's documented schema with the known key.
///
/// Mirrors `core/src/store.rs::testsupport::mint_signal_db`: two conversations
/// (private "Alice", group "Team") and three messages (incoming text, outgoing
/// with one image attachment, incoming group text).
fn mint_signal_db(db_path: &Path) {
    let conn = Connection::open(db_path).expect("open new db");
    conn.execute_batch(&format!("PRAGMA key = \"x'{FIXTURE_KEY_HEX}'\";"))
        .expect("set key");
    conn.execute_batch(
        "CREATE TABLE conversations (
             id TEXT PRIMARY KEY,
             type TEXT,
             active_at INTEGER,
             json TEXT
         );
         CREATE TABLE messages (
             id TEXT PRIMARY KEY,
             conversationId TEXT,
             sent_at INTEGER,
             received_at INTEGER,
             received_at_ms INTEGER,
             serverTimestamp INTEGER,
             type TEXT,
             body TEXT,
             json TEXT
         );",
    )
    .expect("create schema");

    let conversations = [
        (
            "conv-alice",
            "private",
            1_700_000_000_000i64,
            r#"{"id":"conv-alice","type":"private","serviceId":"uuid-alice","e164":"+15551230001","profileName":"Alice"}"#,
        ),
        (
            "conv-team",
            "group",
            1_700_000_500_000i64,
            r#"{"id":"conv-team","type":"group","name":"Team"}"#,
        ),
    ];
    for (id, typ, active_at, json) in conversations {
        conn.execute(
            "INSERT INTO conversations (id, type, active_at, json) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, typ, active_at, json],
        )
        .expect("insert conversation");
    }

    // `received_at` is the ordering counter, `received_at_ms` the wall clock —
    // mirroring the canonical builder's realistic column semantics.
    let messages = [
        (
            "msg-1",
            "conv-alice",
            1_700_000_100_000i64,
            1i64,
            1_700_000_100_050i64,
            "incoming",
            "hey there",
            r#"{"id":"msg-1","conversationId":"conv-alice","sourceServiceId":"uuid-alice","attachments":[]}"#,
        ),
        (
            "msg-2",
            "conv-alice",
            1_700_000_200_000,
            2,
            1_700_000_200_010,
            "outgoing",
            "photo!",
            r#"{"id":"msg-2","conversationId":"conv-alice","attachments":[{"contentType":"image/jpeg","fileName":"pic.jpg","size":20480,"path":"ab/abcdef0123"}]}"#,
        ),
        (
            "msg-3",
            "conv-team",
            1_700_000_600_000,
            3,
            1_700_000_600_030,
            "incoming",
            "gm all",
            r#"{"id":"msg-3","conversationId":"conv-team","sourceServiceId":"uuid-bob","attachments":[]}"#,
        ),
    ];
    for (id, conv, sent, recv_counter, recv_ms, typ, body, json) in messages {
        conn.execute(
            "INSERT INTO messages
                 (id, conversationId, sent_at, received_at, received_at_ms, type, body, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![id, conv, sent, recv_counter, recv_ms, typ, body, json],
        )
        .expect("insert message");
    }
}

/// Drive the independent `sqlcipher` CLI over `db` with the raw key and return
/// the rows of one `SELECT` as JSON objects. Fails loud on a non-zero exit, an
/// unparseable body, or a missing JSON array (showing the raw CLI bytes).
fn cli_rows(oracle: &Path, db: &Path, select_sql: &str) -> Vec<Value> {
    // PRAGMA key first (default mode prints a bare "ok"), then json mode, then
    // the single SELECT — so stdout is `ok\n[ ...json... ]`.
    let script = format!("PRAGMA key = \"x'{FIXTURE_KEY_HEX}'\";\n.mode json\n{select_sql}\n");

    let mut child = Command::new(oracle)
        .arg(db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn sqlcipher oracle {}: {e}", oracle.display()));
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(script.as_bytes())
        .expect("write sql to sqlcipher stdin");
    let out = child.wait_with_output().expect("wait for sqlcipher");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "sqlcipher CLI failed (status {:?}) for SQL `{select_sql}`\nstdout: {stdout}\nstderr: {stderr}",
        out.status.code()
    );

    // Slice from the first '[' — the SELECT's JSON array — past the PRAGMA "ok".
    let start = stdout.find('[').unwrap_or_else(|| {
        panic!("no JSON array in sqlcipher output for `{select_sql}`\nstdout: {stdout}\nstderr: {stderr}")
    });
    let json = &stdout[start..];
    match serde_json::from_str::<Value>(json.trim()) {
        Ok(Value::Array(rows)) => rows,
        other => panic!(
            "sqlcipher output is not a JSON array for `{select_sql}`: {other:?}\nraw: {json}"
        ),
    }
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn opt_i64(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

/// The raw `type` string our reader would round-trip a `ConversationKind` back
/// to — for reconciling against the CLI's raw `type` column.
fn kind_type(kind: &ConversationKind) -> String {
    match kind {
        ConversationKind::Private => "private".to_owned(),
        ConversationKind::Group => "group".to_owned(),
        ConversationKind::Other(s) => s.clone(),
    }
}

#[test]
fn differential_reader_matches_sqlcipher_cli() {
    let Some(oracle) = std::env::var_os("SIGNAL_SQLCIPHER_ORACLE") else {
        eprintln!("SIGNAL_SQLCIPHER_ORACLE not set — skipping sqlcipher CLI differential");
        return;
    };
    let oracle = Path::new(&oracle);

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db.sqlite");
    mint_signal_db(&db);

    let key = SqlcipherKey::from_hex(FIXTURE_KEY_HEX).unwrap();
    let store = SignalStore::open_at(&db, &key).expect("our reader opens the minted db");

    // --- Messages: reconcile
    // (id, conversationId, sent_at, received_at, received_at_ms, type, body). ---
    let mut ours_msgs: Vec<MsgRow> = store
        .messages()
        .unwrap()
        .into_iter()
        .map(|m| {
            (
                m.id,
                m.conversation_id,
                m.sent_at,
                m.received_at,
                m.received_at_ms,
                m.direction.to_string(),
                m.body,
            )
        })
        .collect();
    ours_msgs.sort();

    let cli_msg_rows = cli_rows(
        oracle,
        &db,
        "SELECT id, conversationId, sent_at, received_at, received_at_ms, type, body \
         FROM messages ORDER BY id;",
    );
    let mut cli_msgs: Vec<MsgRow> = cli_msg_rows
        .iter()
        .map(|r| {
            (
                opt_str(r, "id").expect("cli message id"),
                opt_str(r, "conversationId"),
                opt_i64(r, "sent_at"),
                opt_i64(r, "received_at"),
                opt_i64(r, "received_at_ms"),
                opt_str(r, "type").expect("cli message type"),
                opt_str(r, "body"),
            )
        })
        .collect();
    cli_msgs.sort();

    assert_eq!(
        ours_msgs.len(),
        cli_msgs.len(),
        "message COUNT diverges: our reader {} vs sqlcipher CLI {}",
        ours_msgs.len(),
        cli_msgs.len()
    );
    assert_eq!(
        ours_msgs, cli_msgs,
        "message CONTENTS diverge between our reader and the sqlcipher CLI"
    );

    // --- Conversations: reconcile (id, type, active_at). ---
    let mut ours_convs: Vec<(String, String, Option<i64>)> = store
        .conversations()
        .unwrap()
        .into_iter()
        .map(|c| (c.id, kind_type(&c.kind), c.active_at))
        .collect();
    ours_convs.sort();

    let cli_conv_rows = cli_rows(
        oracle,
        &db,
        "SELECT id, type, active_at FROM conversations ORDER BY id;",
    );
    let mut cli_convs: Vec<(String, String, Option<i64>)> = cli_conv_rows
        .iter()
        .map(|r| {
            (
                opt_str(r, "id").expect("cli conversation id"),
                opt_str(r, "type").expect("cli conversation type"),
                opt_i64(r, "active_at"),
            )
        })
        .collect();
    cli_convs.sort();

    assert_eq!(
        ours_convs.len(),
        cli_convs.len(),
        "conversation COUNT diverges: our reader {} vs sqlcipher CLI {}",
        ours_convs.len(),
        cli_convs.len()
    );
    assert_eq!(
        ours_convs, cli_convs,
        "conversation CONTENTS diverge between our reader and the sqlcipher CLI"
    );

    eprintln!(
        "differential OK: {} messages + {} conversations reconciled between our reader and the sqlcipher CLI ({})",
        ours_msgs.len(),
        ours_convs.len(),
        oracle.display()
    );
}
