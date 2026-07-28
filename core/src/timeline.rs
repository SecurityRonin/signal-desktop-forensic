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
    /// Milliseconds since the Unix epoch (`sent_at`, else `received_at`, else 0).
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
    let _ = messages;
    todo!("GREEN implements timeline building")
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

    fn msg(id: &str, sent: Option<i64>, recv: Option<i64>, body: Option<&str>) -> Message {
        Message {
            id: id.to_owned(),
            conversation_id: Some("c".to_owned()),
            direction: Direction::Incoming,
            body: body.map(str::to_owned),
            sent_at: sent,
            received_at: recv,
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
    fn falls_back_to_received_at_then_zero() {
        let msgs = vec![
            msg("no_ts", None, None, Some("x")),
            msg("recv_only", None, Some(50), Some("y")),
        ];
        let tl = build_timeline(&msgs);
        // no-timestamp message sorts first at 0, then the received-at one.
        assert_eq!(tl[0].message_id, "no_ts");
        assert_eq!(tl[0].timestamp, 0);
        assert_eq!(tl[1].timestamp, 50);
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
