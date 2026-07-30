//! Open the decrypted SQLCipher database and read typed records.
//!
//! [`SignalStore::open_at`] opens `sql/db.sqlite` **read-only** (forensic
//! posture — evidence is never modified) with the SQLCipher raw key, then reads
//! [`Conversation`], [`Message`], [`Contact`], and [`Attachment`] records and a
//! merged timeline.
//!
//! Identity fields that drift across Signal versions (`serviceId`/`uuid`, group
//! name, `sourceServiceId`) are read from each row's `json` column rather than
//! from a volatile denormalized column — parsed defensively (a malformed row's
//! json degrades to `None` fields, never a panic).

use std::path::Path;

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;

use crate::error::{Result, SignalError};
use crate::keys::SqlcipherKey;
use crate::records::{Attachment, Contact, Conversation, ConversationKind, Direction, Message};

/// An opened, decrypted Signal database.
pub struct SignalStore {
    conn: Connection,
}

impl SignalStore {
    /// Open a `db.sqlite` file directly with the SQLCipher raw key.
    ///
    /// A wrong key makes SQLCipher report the decrypted header as "not a
    /// database" — surfaced here as [`SignalError::DbOpen`], never empty rows.
    pub fn open_at(db_path: &Path, key: &SqlcipherKey) -> Result<Self> {
        // Read-only: forensic evidence is never modified.
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(SignalError::DbOpen)?;

        // Raw-key form: PRAGMA key = "x'<hex>'" (SQLCipher 4 defaults, matching
        // Signal). The quoted x'..' tells SQLCipher this is the raw key, no KDF.
        conn.execute_batch(&format!("PRAGMA key = \"{}\";", key.as_pragma()))
            .map_err(SignalError::DbOpen)?;

        // Force a decrypt: a wrong key makes SQLCipher reject the header here
        // ("file is not a database") rather than at first query — fail loud now,
        // never hand back a store that silently reads zero rows.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map_err(SignalError::DbOpen)?;

        Ok(Self { conn })
    }

    /// Open the `sql/db.sqlite` inside a Signal profile directory. The relative
    /// path is taken from the KNOWLEDGE leaf, not hardcoded.
    pub fn open_profile(profile: &Path, key: &SqlcipherKey) -> Result<Self> {
        let rel = crate::paths::messages_db_relpath().unwrap_or("sql/db.sqlite");
        Self::open_at(&profile.join(rel), key)
    }

    /// All conversations (contacts + groups).
    pub fn conversations(&self) -> Result<Vec<Conversation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, type, active_at, json FROM conversations")
            .map_err(SignalError::Query)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(SignalError::Query)?;

        let mut out = Vec::new();
        for row in rows {
            let (id, typ, active_at, json) = row.map_err(SignalError::Query)?;
            // Malformed json degrades to None fields — never a panic.
            let v: Option<Value> = json.as_deref().and_then(|s| serde_json::from_str(s).ok());
            let kind = ConversationKind::from_type(typ.as_deref().unwrap_or_default());
            let (service_id, e164, name) = match &v {
                Some(v) => (
                    first_str(v, &["serviceId", "uuid"]),
                    str_field(v, "e164"),
                    first_str(v, &["name", "profileName", "profileFullName"]),
                ),
                None => (None, None, None),
            };
            out.push(Conversation {
                id,
                kind,
                service_id,
                e164,
                name,
                active_at,
            });
        }
        Ok(out)
    }

    /// All messages.
    pub fn messages(&self) -> Result<Vec<Message>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, conversationId, sent_at, received_at, type, body, json FROM messages",
            )
            .map_err(SignalError::Query)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(SignalError::Query)?;

        let mut out = Vec::new();
        for row in rows {
            let (id, conversation_id, sent_at, received_at, typ, body, json) =
                row.map_err(SignalError::Query)?;
            let v: Option<Value> = json.as_deref().and_then(|s| serde_json::from_str(s).ok());
            let direction = Direction::from_type(typ.as_deref().unwrap_or_default());
            let (source_service_id, has_attachments) = match &v {
                Some(v) => (
                    first_str(v, &["sourceServiceId", "source"]),
                    v.get("attachments")
                        .and_then(Value::as_array)
                        .is_some_and(|a| !a.is_empty()),
                ),
                None => (None, false),
            };
            out.push(Message {
                id,
                conversation_id,
                direction,
                body,
                sent_at,
                received_at,
                source_service_id,
                has_attachments,
            });
        }
        Ok(out)
    }

    /// Attachment metadata across all messages, parsed from each message's
    /// `json.attachments[]`.
    pub fn attachments(&self) -> Result<Vec<Attachment>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, json FROM messages")
            .map_err(SignalError::Query)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })
            .map_err(SignalError::Query)?;

        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row.map_err(SignalError::Query)?;
            if let Some(json) = json {
                out.extend(parse_attachments_json(&id, &json));
            }
        }
        Ok(out)
    }

    /// A timestamp-ordered timeline of all messages.
    pub fn timeline(&self) -> Result<Vec<crate::timeline::TimelineEntry>> {
        Ok(crate::timeline::build_timeline(&self.messages()?))
    }

    /// Contacts — the private conversations projected to their identity fields.
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        Ok(self
            .conversations()?
            .into_iter()
            .filter(|c| c.kind == ConversationKind::Private)
            .map(|c| Contact {
                conversation_id: c.id,
                service_id: c.service_id,
                e164: c.e164,
                name: c.name,
            })
            .collect())
    }
}

/// Parse the `attachments[]` array out of one message's `json` column.
///
/// This is the untrusted-input parser fuzzed by `fuzz_message_json`: arbitrary
/// bytes in, never a panic. Malformed json, a missing `attachments` key, or a
/// non-array value all yield an empty list.
#[must_use]
pub fn parse_attachments_json(message_id: &str, json: &str) -> Vec<Attachment> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let Some(arr) = v.get("attachments").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter(|a| a.is_object())
        .map(|a| Attachment {
            message_id: message_id.to_owned(),
            content_type: str_field(a, "contentType"),
            file_name: str_field(a, "fileName"),
            size: a.get("size").and_then(Value::as_i64),
            path: str_field(a, "path"),
        })
        .collect()
}

/// Read a string field from a JSON object, if present and a string.
fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}

/// First present string among several candidate keys (schema drift tolerance).
fn first_str(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| str_field(v, k))
}

#[cfg(test)]
pub(crate) mod testsupport {
    //! Mint a real SQLCipher database in Signal's documented schema, for the
    //! structural (tier-2/3) validation described in `docs/validation.md`.

    use super::*;
    use rusqlite::Connection;

    /// The known raw key every minted fixture is encrypted with.
    pub(crate) const FIXTURE_KEY_HEX: &str =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    pub(crate) fn fixture_key() -> SqlcipherKey {
        SqlcipherKey::from_hex(FIXTURE_KEY_HEX).expect("valid fixture key")
    }

    /// Create a minted `db.sqlite` at `db_path` carrying a canonical dataset:
    /// two conversations (one private contact "Alice", one group "Team") and
    /// three messages (incoming text, outgoing with one image attachment,
    /// incoming group text).
    pub(crate) fn mint_signal_db(db_path: &Path) {
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

        let messages = [
            (
                "msg-1",
                "conv-alice",
                1_700_000_100_000i64,
                1_700_000_100_050i64,
                "incoming",
                "hey there",
                r#"{"id":"msg-1","conversationId":"conv-alice","sourceServiceId":"uuid-alice","attachments":[]}"#,
            ),
            (
                "msg-2",
                "conv-alice",
                1_700_000_200_000,
                1_700_000_200_010,
                "outgoing",
                "photo!",
                r#"{"id":"msg-2","conversationId":"conv-alice","attachments":[{"contentType":"image/jpeg","fileName":"pic.jpg","size":20480,"path":"ab/abcdef0123"}]}"#,
            ),
            (
                "msg-3",
                "conv-team",
                1_700_000_600_000,
                1_700_000_600_030,
                "incoming",
                "gm all",
                r#"{"id":"msg-3","conversationId":"conv-team","sourceServiceId":"uuid-bob","attachments":[]}"#,
            ),
        ];
        for (id, conv, sent, recv, typ, body, json) in messages {
            conn.execute(
                "INSERT INTO messages (id, conversationId, sent_at, received_at, type, body, json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![id, conv, sent, recv, typ, body, json],
            )
            .expect("insert message");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testsupport::{fixture_key, mint_signal_db, FIXTURE_KEY_HEX};
    use super::*;
    use crate::keys::SqlcipherKey;

    fn minted() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("db.sqlite");
        mint_signal_db(&db);
        (dir, db)
    }

    /// Add rows whose `json` column carries no parseable object — one NULL and
    /// one syntactically broken — into an already-minted fixture. This is the
    /// schema-drift / corruption path the module doc promises degrades to `None`
    /// identity fields rather than panicking or dropping the row.
    fn add_unparseable_json_rows(db: &Path) {
        let conn = Connection::open(db).expect("reopen minted db");
        conn.execute_batch(&format!("PRAGMA key = \"x'{FIXTURE_KEY_HEX}'\";"))
            .expect("set key");
        conn.execute_batch(
            "INSERT INTO conversations (id, type, active_at, json)
                 VALUES ('conv-nulljson', 'private', 1700000700000, NULL),
                        ('conv-badjson',  'private', 1700000800000, '{not json');
             INSERT INTO messages (id, conversationId, sent_at, received_at, type, body, json)
                 VALUES ('msg-nulljson', 'conv-nulljson', 1700000700000, 1700000700010,
                         'incoming', 'no json column', NULL),
                        ('msg-badjson',  'conv-badjson',  1700000800000, 1700000800010,
                         'incoming', 'broken json column', '{not json');",
        )
        .expect("insert unparseable-json rows");
    }

    #[test]
    fn opens_with_correct_key() {
        let (_dir, db) = minted();
        assert!(SignalStore::open_at(&db, &fixture_key()).is_ok());
    }

    #[test]
    fn wrong_key_fails_loud() {
        let (_dir, db) = minted();
        let wrong =
            SqlcipherKey::from_hex(&FIXTURE_KEY_HEX.replace("00112233", "ffffffff")).unwrap();
        // A wrong key must be a loud DbOpen error, never a store that reads zero
        // rows (which is indistinguishable from an empty DB).
        assert!(matches!(
            SignalStore::open_at(&db, &wrong),
            Err(SignalError::DbOpen(_))
        ));
    }

    #[test]
    fn reads_conversations() {
        let (_dir, db) = minted();
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let convs = store.conversations().unwrap();
        assert_eq!(convs.len(), 2);

        let alice = convs.iter().find(|c| c.id == "conv-alice").unwrap();
        assert_eq!(alice.kind, ConversationKind::Private);
        assert_eq!(alice.e164.as_deref(), Some("+15551230001"));
        assert_eq!(alice.name.as_deref(), Some("Alice"));
        assert_eq!(alice.service_id.as_deref(), Some("uuid-alice"));
        assert_eq!(alice.active_at, Some(1_700_000_000_000));

        let team = convs.iter().find(|c| c.id == "conv-team").unwrap();
        assert_eq!(team.kind, ConversationKind::Group);
        assert_eq!(team.name.as_deref(), Some("Team"));
    }

    #[test]
    fn reads_messages() {
        let (_dir, db) = minted();
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let msgs = store.messages().unwrap();
        assert_eq!(msgs.len(), 3);

        let m1 = msgs.iter().find(|m| m.id == "msg-1").unwrap();
        assert_eq!(m1.direction, Direction::Incoming);
        assert_eq!(m1.body.as_deref(), Some("hey there"));
        assert_eq!(m1.conversation_id.as_deref(), Some("conv-alice"));
        assert_eq!(m1.sent_at, Some(1_700_000_100_000));
        assert_eq!(m1.source_service_id.as_deref(), Some("uuid-alice"));
        assert!(!m1.has_attachments);

        let m2 = msgs.iter().find(|m| m.id == "msg-2").unwrap();
        assert_eq!(m2.direction, Direction::Outgoing);
        assert!(m2.has_attachments);

        let m3 = msgs.iter().find(|m| m.id == "msg-3").unwrap();
        assert_eq!(m3.source_service_id.as_deref(), Some("uuid-bob"));
    }

    #[test]
    fn reads_contacts_from_private_conversations_only() {
        let (_dir, db) = minted();
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let contacts = store.contacts().unwrap();
        // Only the private conversation is a contact — the group is not.
        assert_eq!(contacts.len(), 1);
        let alice = &contacts[0];
        assert_eq!(alice.conversation_id, "conv-alice");
        assert_eq!(alice.e164.as_deref(), Some("+15551230001"));
        assert_eq!(alice.name.as_deref(), Some("Alice"));
        assert_eq!(alice.service_id.as_deref(), Some("uuid-alice"));
    }

    #[test]
    fn reads_attachment_metadata() {
        let (_dir, db) = minted();
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let atts = store.attachments().unwrap();
        // Only msg-2 carries an attachment.
        assert_eq!(atts.len(), 1);
        let a = &atts[0];
        assert_eq!(a.message_id, "msg-2");
        assert_eq!(a.content_type.as_deref(), Some("image/jpeg"));
        assert_eq!(a.file_name.as_deref(), Some("pic.jpg"));
        assert_eq!(a.size, Some(20480));
        assert_eq!(a.path.as_deref(), Some("ab/abcdef0123"));
    }

    #[test]
    fn timeline_is_time_ordered_over_the_store() {
        let (_dir, db) = minted();
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let tl = store.timeline().unwrap();
        assert_eq!(tl.len(), 3);
        // Ascending by sent_at: msg-1 (…100k) < msg-2 (…200k) < msg-3 (…600k).
        let ids: Vec<&str> = tl.iter().map(|e| e.message_id.as_str()).collect();
        assert_eq!(ids, ["msg-1", "msg-2", "msg-3"]);
        assert!(tl.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));
    }

    #[test]
    fn open_profile_resolves_db_from_the_knowledge_leaf() {
        // messages_db_relpath() is "sql/db.sqlite": mint under that subdir and
        // open by profile root, exercising the leaf-sourced path resolution.
        let dir = tempfile::tempdir().unwrap();
        let sql = dir.path().join("sql");
        std::fs::create_dir_all(&sql).unwrap();
        mint_signal_db(&sql.join("db.sqlite"));
        let store = SignalStore::open_profile(dir.path(), &fixture_key()).unwrap();
        assert_eq!(store.conversations().unwrap().len(), 2);
    }

    #[test]
    fn open_profile_missing_db_fails_loud() {
        // A profile with no sql/db.sqlite is a loud DbOpen, never an empty store.
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            SignalStore::open_profile(dir.path(), &fixture_key()),
            Err(SignalError::DbOpen(_))
        ));
    }

    #[test]
    fn conversation_with_unparseable_json_keeps_the_row_with_none_identity() {
        let (_dir, db) = minted();
        add_unparseable_json_rows(&db);
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let convs = store.conversations().unwrap();
        // Both degenerate rows are KEPT — dropping a row loses evidence.
        assert_eq!(convs.len(), 4);
        for id in ["conv-nulljson", "conv-badjson"] {
            let c = convs.iter().find(|c| c.id == id).unwrap();
            // Identity fields live in `json`, so with no parseable json they are
            // None — never a panic, and never a fabricated value.
            assert_eq!(c.service_id, None);
            assert_eq!(c.e164, None);
            assert_eq!(c.name, None);
            // The columns that do NOT come from json still read normally.
            assert_eq!(c.kind, ConversationKind::Private);
            assert!(c.active_at.is_some());
        }
        // Such a row is still projected as a contact (a private conversation),
        // just an unidentified one.
        let contacts = store.contacts().unwrap();
        assert_eq!(contacts.len(), 3);
        assert!(contacts
            .iter()
            .any(|c| c.conversation_id == "conv-nulljson" && c.name.is_none()));
    }

    #[test]
    fn message_with_unparseable_json_keeps_the_row_with_no_source_or_attachments() {
        let (_dir, db) = minted();
        add_unparseable_json_rows(&db);
        let store = SignalStore::open_at(&db, &fixture_key()).unwrap();
        let msgs = store.messages().unwrap();
        assert_eq!(msgs.len(), 5);
        for id in ["msg-nulljson", "msg-badjson"] {
            let m = msgs.iter().find(|m| m.id == id).unwrap();
            // `sourceServiceId` and `attachments[]` are json-only fields.
            assert_eq!(m.source_service_id, None);
            assert!(!m.has_attachments);
            // The non-json columns are unaffected — the body is still evidence.
            assert_eq!(m.direction, Direction::Incoming);
            assert!(m.body.is_some());
            assert!(m.sent_at.is_some());
        }
        // A row with no parseable json contributes no attachment metadata.
        let atts = store.attachments().unwrap();
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].message_id, "msg-2");
    }

    #[test]
    fn parse_attachments_tolerates_garbage() {
        // A malformed json column must never panic — it yields no attachments.
        assert!(parse_attachments_json("m", "not json").is_empty());
        assert!(parse_attachments_json("m", r#"{"attachments":"nope"}"#).is_empty());
        assert!(parse_attachments_json("m", r#"{"no_attachments_key":1}"#).is_empty());
    }
}
