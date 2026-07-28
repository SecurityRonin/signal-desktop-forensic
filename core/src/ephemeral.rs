//! Parse Signal Desktop's unencrypted `ephemeral.json` — app/UI state.
//!
//! Unlike `config.json`, `ephemeral.json` holds no key material — it is
//! plaintext application preferences (theme, spell-check, locale) and the last
//! window geometry. The window position/size is mild forensic context (the
//! display the app last ran on); the rest is provenance.
//!
//! `ephemeral.json` is not (yet) a store in the `messenger_desktop` KNOWLEDGE
//! leaf, so its filename is named here, sourced from Bilz, *A Forensic Gold Mine
//! II* (the same writeup the leaf cites for `config.json`).

use std::path::Path;

use serde::Deserialize;

use crate::error::{Result, SignalError};

/// Relative path of the ephemeral app-state file within a Signal profile.
pub const EPHEMERAL_RELPATH: &str = "ephemeral.json";

/// Parsed `ephemeral.json` — all fields optional (schema varies by version).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct EphemeralConfig {
    /// `theme-setting` — e.g. `system` / `light` / `dark`.
    #[serde(rename = "theme-setting", default)]
    pub theme: Option<String>,
    /// `spell-check` — whether spell-checking is enabled.
    #[serde(rename = "spell-check", default)]
    pub spell_check: Option<bool>,
    /// `localeOverride` — a forced UI locale, if set.
    #[serde(rename = "localeOverride", default)]
    pub locale_override: Option<String>,
    /// Last window geometry/state.
    #[serde(default)]
    pub window: Option<WindowState>,
}

/// The last-recorded main-window geometry and state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct WindowState {
    /// Window width in pixels.
    #[serde(default)]
    pub width: Option<i64>,
    /// Window height in pixels.
    #[serde(default)]
    pub height: Option<i64>,
    /// Window x position.
    #[serde(default)]
    pub x: Option<i64>,
    /// Window y position.
    #[serde(default)]
    pub y: Option<i64>,
    /// Whether the window was maximized.
    #[serde(default)]
    pub maximized: Option<bool>,
    /// Whether the window was fullscreen.
    #[serde(default)]
    pub fullscreen: Option<bool>,
}

impl EphemeralConfig {
    /// Parse `ephemeral.json` from its raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let _ = bytes;
        todo!("GREEN implements ephemeral.json parsing")
    }

    /// Read and parse `ephemeral.json` from a Signal profile directory.
    pub fn from_profile(profile: &Path) -> Result<Self> {
        let path = profile.join(EPHEMERAL_RELPATH);
        let bytes = std::fs::read(&path).map_err(|source| SignalError::ConfigRead {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact shape of a real on-host ephemeral.json (values changed).
    const REAL_SHAPE: &str = r#"{
        "localeOverride": null,
        "spell-check": true,
        "theme-setting": "system",
        "window": { "maximized": false, "fullscreen": false, "width": 1305, "height": 1355, "x": 299, "y": 277 }
    }"#;

    #[test]
    fn parses_real_shape() {
        let e = EphemeralConfig::from_bytes(REAL_SHAPE.as_bytes()).unwrap();
        assert_eq!(e.theme.as_deref(), Some("system"));
        assert_eq!(e.spell_check, Some(true));
        assert_eq!(e.locale_override, None);
        let w = e.window.expect("window");
        assert_eq!(w.width, Some(1305));
        assert_eq!(w.height, Some(1355));
        assert_eq!(w.x, Some(299));
        assert_eq!(w.y, Some(277));
        assert_eq!(w.maximized, Some(false));
    }

    #[test]
    fn empty_object_is_all_none() {
        let e = EphemeralConfig::from_bytes(b"{}").unwrap();
        assert_eq!(e, EphemeralConfig::default());
    }

    #[test]
    fn invalid_json_is_loud() {
        assert!(matches!(
            EphemeralConfig::from_bytes(b"not json"),
            Err(SignalError::EphemeralJson(_))
        ));
    }
}
