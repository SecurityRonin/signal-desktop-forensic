//! Signal Desktop on-disk layout — reused from the KNOWLEDGE leaf, not
//! re-hardcoded here.
//!
//! The profile base directories and the store roles/paths (`sql/db.sqlite`,
//! `config.json`, `attachments.noindex`) are facts owned by
//! [`forensicnomicon_core::messenger_desktop`]. This module is a thin, typed
//! accessor so a caller resolves them through one constant instead of pasting
//! path literals — the single-source-of-truth rule.

use forensicnomicon_core::messenger_desktop::{self, MessengerSpec, StoreRole};

/// The canonical app key for Signal Desktop in the messenger catalog.
pub const APP: &str = "Signal Desktop";

/// The Signal Desktop artifact spec (paths, stores, encryption posture).
///
/// # Panics
/// Never in practice: the `"Signal Desktop"` entry is a compile-time constant in
/// the KNOWLEDGE leaf. The `Option` is unwrapped defensively via `expect` only
/// in tests; production callers use [`spec`].
#[must_use]
pub fn spec() -> Option<&'static MessengerSpec> {
    messenger_desktop::spec(APP)
}

/// Relative path of the SQLCipher message/conversation database
/// (`sql/db.sqlite`), read from the KNOWLEDGE leaf.
#[must_use]
pub fn messages_db_relpath() -> Option<&'static str> {
    spec()?.store(StoreRole::Messages).map(|s| s.relative_path)
}

/// Relative path of the key store (`config.json`), read from the KNOWLEDGE leaf.
#[must_use]
pub fn config_relpath() -> Option<&'static str> {
    spec()?
        .store(StoreRole::EncryptionKey)
        .map(|s| s.relative_path)
}

/// Relative path of the attachments directory (`attachments.noindex`).
#[must_use]
pub fn attachments_relpath() -> Option<&'static str> {
    spec()?
        .store(StoreRole::Attachments)
        .map(|s| s.relative_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_paths_come_from_the_knowledge_leaf() {
        // Reused, not re-hardcoded: these must match the messenger_desktop spec.
        assert_eq!(messages_db_relpath(), Some("sql/db.sqlite"));
        assert_eq!(config_relpath(), Some("config.json"));
        assert_eq!(attachments_relpath(), Some("attachments.noindex"));
    }
}
