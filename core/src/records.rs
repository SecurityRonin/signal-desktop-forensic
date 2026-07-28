//! Typed records read from the decrypted Signal database.
//!
//! These are the reader's output — plain data, no findings. Enum-typed fields
//! (`ConversationKind`, `Direction`) keep the raw string as an `Other(_)` arm so
//! an unexpected value is preserved verbatim, never silently dropped.

/// A row of the `conversations` table: a 1:1 contact or a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    /// Signal's conversation id (primary key).
    pub id: String,
    /// Private (1:1) vs Group vs an unrecognized `type` (kept verbatim).
    pub kind: ConversationKind,
    /// The account/service identifier (`serviceId`, formerly `uuid`), if any.
    pub service_id: Option<String>,
    /// The E.164 phone number, if any (1:1 conversations).
    pub e164: Option<String>,
    /// Display name — group name or contact profile name.
    pub name: Option<String>,
    /// Last-active timestamp (ms since the Unix epoch), if recorded.
    pub active_at: Option<i64>,
}

/// The kind of a Signal conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationKind {
    /// A 1:1 conversation with a contact.
    Private,
    /// A group conversation.
    Group,
    /// An unrecognized `type` value, preserved verbatim.
    Other(String),
}

impl ConversationKind {
    /// Classify Signal's `type` column value.
    #[must_use]
    pub fn from_type(raw: &str) -> Self {
        match raw {
            "private" => Self::Private,
            "group" => Self::Group,
            other => Self::Other(other.to_string()),
        }
    }
}

/// A contact — a private conversation projected to its identity fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// The backing conversation id.
    pub conversation_id: String,
    /// The contact's service identifier (`serviceId`/`uuid`), if any.
    pub service_id: Option<String>,
    /// The contact's E.164 phone number, if any.
    pub e164: Option<String>,
    /// The contact's display / profile name, if any.
    pub name: Option<String>,
}

/// A row of the `messages` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Signal's message id.
    pub id: String,
    /// The conversation this message belongs to.
    pub conversation_id: Option<String>,
    /// Incoming vs outgoing vs an unrecognized `type` (kept verbatim).
    pub direction: Direction,
    /// The message body text, if any (attachments-only messages have none).
    pub body: Option<String>,
    /// Send timestamp (ms since the Unix epoch), if recorded.
    pub sent_at: Option<i64>,
    /// Receive timestamp (ms since the Unix epoch), if recorded.
    pub received_at: Option<i64>,
    /// The sender's service id (`sourceServiceId`/`source`), if any.
    pub source_service_id: Option<String>,
    /// Whether the message carries attachment metadata.
    pub has_attachments: bool,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Direction::Incoming => "incoming",
            Direction::Outgoing => "outgoing",
            Direction::Other(s) => s,
        })
    }
}

/// The direction of a Signal message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Direction {
    /// Received message.
    Incoming,
    /// Sent message.
    Outgoing,
    /// An unrecognized `type` value, preserved verbatim.
    Other(String),
}

impl Direction {
    /// Classify Signal's message `type` column value.
    #[must_use]
    pub fn from_type(raw: &str) -> Self {
        match raw {
            "incoming" => Self::Incoming,
            "outgoing" => Self::Outgoing,
            other => Self::Other(other.to_string()),
        }
    }
}

/// Attachment metadata, parsed from a message's `json.attachments[]`.
///
/// This is the metadata only — the encrypted blob under `attachments.noindex`
/// is not decrypted here (see the crate PRD scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The message this attachment belongs to.
    pub message_id: String,
    /// MIME content type (`contentType`), if recorded.
    pub content_type: Option<String>,
    /// Original file name (`fileName`), if recorded.
    pub file_name: Option<String>,
    /// Byte size (`size`), if recorded.
    pub size: Option<i64>,
    /// Relative path under `attachments.noindex` (`path`), if recorded.
    pub path: Option<String>,
}
