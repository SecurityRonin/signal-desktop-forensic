//! A merged, time-ordered view of Signal activity.
//!
//! [`build_timeline`] turns parsed [`Message`]s into [`TimelineEntry`]s ordered
//! by timestamp — the reader's contribution to a cross-artifact super-timeline.
//! A message with no timestamp is kept (timestamp `0`) rather than dropped:
//! losing an entry loses evidence.

use crate::records::{Direction, Message};

/// One time-ordered entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    /// Milliseconds since the Unix epoch — `sent_at`, else `received_at_ms`,
    /// else `serverTimestamp`, else 0.
    ///
    /// Signal's bare `received_at` column is deliberately **not** a source: it
    /// is an ordering counter, not a time (see
    /// [`Message::received_at`](crate::records::Message::received_at)).
    pub timestamp: i64,
    /// The conversation this activity belongs to.
    pub conversation_id: Option<String>,
    /// The backing message id.
    pub message_id: String,
    /// Direction of the message.
    pub direction: Direction,
    /// A short, char-safe preview of the body (or a placeholder).
    pub summary: String,
}

/// Maximum chars in a timeline summary preview (char-safe truncation).
const SUMMARY_CHARS: usize = 80;

/// Build a timestamp-ordered timeline from parsed messages.
#[must_use]
pub fn build_timeline(messages: &[Message]) -> Vec<TimelineEntry> {
    let mut entries: Vec<TimelineEntry> = messages
        .iter()
        .map(|m| TimelineEntry {
            // Wall-clock columns only, in Signal's own order of authority. The
            // `received_at` counter is never a fallback: a small counter read as
            // an epoch dates the message to 1970.
            timestamp: m
                .sent_at
                .or(m.received_at_ms)
                .or(m.server_timestamp)
                .unwrap_or(0),
            conversation_id: m.conversation_id.clone(),
            message_id: m.id.clone(),
            direction: m.direction.clone(),
            summary: preview(m.body.as_deref(), m.has_attachments),
        })
        .collect();
    // Stable sort keeps input order among equal timestamps (deterministic).
    entries.sort_by_key(|e| e.timestamp);
    entries
}

/// Char-safe body preview — never slices mid-code-point (real bodies are full
/// of emoji / CJK).
fn preview(body: Option<&str>, has_attachments: bool) -> String {
    match body {
        Some(b) if !b.is_empty() => b.chars().take(SUMMARY_CHARS).collect(),
        _ if has_attachments => "[attachment]".to_owned(),
        _ => "[no body]".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: &str, sent: Option<i64>, recv_ms: Option<i64>, body: Option<&str>) -> Message {
        Message {
            id: id.to_owned(),
            conversation_id: Some("c".to_owned()),
            direction: Direction::Incoming,
            body: body.map(str::to_owned),
            sent_at: sent,
            // Every real row carries an ordering counter here. It is set on
            // purpose in every fixture: no test may pass by reading it as a time.
            received_at: Some(9),
            received_at_ms: recv_ms,
            server_timestamp: None,
            source_service_id: None,
            has_attachments: false,
        }
    }

    #[test]
    fn orders_by_timestamp_ascending() {
        let msgs = vec![
            msg("late", Some(300), None, Some("c")),
            msg("early", Some(100), None, Some("a")),
            msg("mid", Some(200), None, Some("b")),
        ];
        let tl = build_timeline(&msgs);
        let ids: Vec<&str> = tl.iter().map(|e| e.message_id.as_str()).collect();
        assert_eq!(ids, ["early", "mid", "late"]);
    }

    #[test]
    fn falls_back_to_received_at_ms_then_server_timestamp_then_zero() {
        let mut server_only = msg("server_only", None, None, Some("z"));
        server_only.server_timestamp = Some(70);
        let msgs = vec![
            msg("no_ts", None, None, Some("x")),
            msg("recv_ms_only", None, Some(50), Some("y")),
            server_only,
        ];
        let tl = build_timeline(&msgs);
        // The message with no wall-clock datum keeps timestamp 0 — the ordering
        // counter in `received_at` (9) is not a time and must not surface here.
        assert_eq!(tl[0].message_id, "no_ts");
        assert_eq!(tl[0].timestamp, 0);
        assert_eq!(tl[1].message_id, "recv_ms_only");
        assert_eq!(tl[1].timestamp, 50);
        assert_eq!(tl[2].message_id, "server_only");
        assert_eq!(tl[2].timestamp, 70);
    }

    #[test]
    fn bodyless_messages_get_the_attachment_or_no_body_placeholder() {
        // An attachment-only message (Signal stores no body for one) must read as
        // "[attachment]", not as an empty summary — the entry is still evidence
        // that something was sent.
        let mut absent_body_with_att = msg("att", Some(1), None, None);
        absent_body_with_att.has_attachments = true;
        // An empty-string body is the same case as an absent one: SQLite stores
        // '' as well as NULL, and both mean "no text to preview".
        let mut empty_body_with_att = msg("empty_att", Some(2), None, Some(""));
        empty_body_with_att.has_attachments = true;
        // No body and no attachment: the fallback placeholder.
        let absent_body = msg("nothing", Some(3), None, None);
        let empty_body = msg("empty", Some(4), None, Some(""));

        let tl = build_timeline(&[
            absent_body_with_att,
            empty_body_with_att,
            absent_body,
            empty_body,
        ]);
        let summaries: Vec<&str> = tl.iter().map(|e| e.summary.as_str()).collect();
        assert_eq!(
            summaries,
            ["[attachment]", "[attachment]", "[no body]", "[no body]"]
        );
    }

    #[test]
    fn summary_is_char_safe_and_has_placeholders() {
        let mut m = msg("emoji", Some(1), None, Some("😀 привет 中文 hello"));
        // truncation must not panic on multibyte content.
        m.body = Some("😀".repeat(200));
        let tl = build_timeline(&[m]);
        assert_eq!(tl[0].summary.chars().count(), SUMMARY_CHARS);
    }
}
