//! Grade decrypted Signal records into normalized findings.
//!
//! The analyzer emits **observations, never verdicts** (consistent-with
//! language). Each anomaly is a typed [`SignalAnomaly`] that converts to a
//! canonical [`Finding`] via the [`Observation`] trait.

use forensicnomicon_core::report::{Category, Finding, Observation, Severity, Source, SubjectRef};
use signal_desktop_core::{Attachment, Conversation, Message, SignalStore};

use crate::ANALYZER;

/// A graded anomaly observed in a Signal profile.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalAnomaly {
    /// A message references a `conversationId` that has no row in the
    /// `conversations` table — consistent with a deleted conversation whose
    /// message rows still remain.
    OrphanMessage {
        /// The message id.
        message_id: String,
        /// The dangling conversation id it references.
        conversation_id: String,
    },
    /// A message carries attachment metadata pointing at an on-disk blob under
    /// `attachments.noindex` — residue that survives message-body deletion.
    AttachmentResidue {
        /// The message id.
        message_id: String,
        /// The relative path under `attachments.noindex`.
        path: String,
    },
}

impl Observation for SignalAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            SignalAnomaly::OrphanMessage { .. } => Severity::Medium,
            SignalAnomaly::AttachmentResidue { .. } => Severity::Info,
        })
    }

    fn code(&self) -> &'static str {
        match self {
            SignalAnomaly::OrphanMessage { .. } => "SIGNAL-ORPHAN-MESSAGE",
            SignalAnomaly::AttachmentResidue { .. } => "SIGNAL-ATTACHMENT-RESIDUE",
        }
    }

    fn category(&self) -> Category {
        Category::Residue
    }

    fn note(&self) -> String {
        match self {
            SignalAnomaly::OrphanMessage {
                message_id,
                conversation_id,
            } => format!(
                "message {message_id} references conversation {conversation_id}, which has no row \
                 in the conversations table — consistent with a deleted conversation whose \
                 messages remain"
            ),
            SignalAnomaly::AttachmentResidue { message_id, path } => format!(
                "message {message_id} carries attachment metadata for '{path}' under \
                 attachments.noindex — residue that can survive message-body deletion"
            ),
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (kind, id) = match self {
            SignalAnomaly::OrphanMessage { message_id, .. } => ("message", message_id.clone()),
            SignalAnomaly::AttachmentResidue { message_id, .. } => {
                ("attachment", message_id.clone())
            }
        };
        vec![SubjectRef {
            scheme: "signal".to_owned(),
            kind: kind.to_owned(),
            id,
            label: None,
        }]
    }
}

/// The producing source stamped on every finding.
fn source() -> Source {
    Source {
        analyzer: ANALYZER.to_owned(),
        scope: "signal profile".to_owned(),
        version: Some(env!("CARGO_PKG_VERSION").to_owned()),
    }
}

/// Grade the parsed records into findings.
#[must_use]
pub fn audit(
    conversations: &[Conversation],
    messages: &[Message],
    attachments: &[Attachment],
) -> Vec<Finding> {
    use std::collections::HashSet;

    let known: HashSet<&str> = conversations.iter().map(|c| c.id.as_str()).collect();
    let src = source();
    let mut findings = Vec::new();

    for m in messages {
        if let Some(cid) = &m.conversation_id {
            if !known.contains(cid.as_str()) {
                findings.push(
                    SignalAnomaly::OrphanMessage {
                        message_id: m.id.clone(),
                        conversation_id: cid.clone(),
                    }
                    .to_finding(src.clone()),
                );
            }
        }
    }

    for a in attachments {
        if let Some(path) = &a.path {
            findings.push(
                SignalAnomaly::AttachmentResidue {
                    message_id: a.message_id.clone(),
                    path: path.clone(),
                }
                .to_finding(src.clone()),
            );
        }
    }

    findings
}

/// Open the store's records and grade them.
pub fn audit_store(store: &SignalStore) -> signal_desktop_core::Result<Vec<Finding>> {
    Ok(audit(
        &store.conversations()?,
        &store.messages()?,
        &store.attachments()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use signal_desktop_core::{ConversationKind, Direction};

    fn conv(id: &str) -> Conversation {
        Conversation {
            id: id.to_owned(),
            kind: ConversationKind::Private,
            service_id: None,
            e164: None,
            name: None,
            active_at: None,
        }
    }

    fn msg(id: &str, conv: Option<&str>) -> Message {
        Message {
            id: id.to_owned(),
            conversation_id: conv.map(str::to_owned),
            direction: Direction::Incoming,
            body: Some("hi".to_owned()),
            sent_at: Some(1),
            received_at: None,
            source_service_id: None,
            has_attachments: false,
        }
    }

    #[test]
    fn flags_orphan_message() {
        let conversations = vec![conv("c1")];
        // m2 references a conversation that does not exist.
        let messages = vec![msg("m1", Some("c1")), msg("m2", Some("c-deleted"))];
        let findings = audit(&conversations, &messages, &[]);
        let orphan = findings
            .iter()
            .find(|f| f.code == "SIGNAL-ORPHAN-MESSAGE")
            .expect("orphan finding");
        assert_eq!(orphan.severity, Some(Severity::Medium));
        assert!(orphan.note.contains("m2"));
        assert!(orphan.note.contains("c-deleted"));
        // The present message must NOT be flagged.
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.code == "SIGNAL-ORPHAN-MESSAGE")
                .count(),
            1
        );
    }

    #[test]
    fn flags_attachment_residue_as_info() {
        let att = Attachment {
            message_id: "m1".to_owned(),
            content_type: Some("image/jpeg".to_owned()),
            file_name: Some("pic.jpg".to_owned()),
            size: Some(1),
            path: Some("ab/cd".to_owned()),
        };
        let findings = audit(&[], &[], &[att]);
        let res = findings
            .iter()
            .find(|f| f.code == "SIGNAL-ATTACHMENT-RESIDUE")
            .expect("attachment finding");
        assert_eq!(res.severity, Some(Severity::Info));
        assert_eq!(res.category, Category::Residue);
        assert!(res.note.contains("ab/cd"));
    }

    #[test]
    fn clean_records_produce_no_findings() {
        let conversations = vec![conv("c1")];
        let messages = vec![msg("m1", Some("c1"))];
        assert!(audit(&conversations, &messages, &[]).is_empty());
    }
}
