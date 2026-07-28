//! **Signal Desktop anomaly auditor** — the analyzer layer over
//! [`signal_desktop_core`].
//!
//! The reader ([`signal_desktop_core`]) decrypts and yields typed records; this
//! crate interprets them into normalized [`forensicnomicon_core::report`]
//! findings — observations, never verdicts (consistent-with language). Anomaly
//! kinds are typed and convert via the [`Observation`] trait.
//!
//! [`Observation`]: forensicnomicon_core::report::Observation

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Analyzer name stamped on every emitted [`Source`].
///
/// [`Source`]: forensicnomicon_core::report::Source
pub const ANALYZER: &str = "signal-desktop-forensic";
