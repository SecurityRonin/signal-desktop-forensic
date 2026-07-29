# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/SecurityRonin/signal-desktop-forensic/releases/tag/signal-desktop-core-v0.1.0) - 2026-07-29

### Added

- *(ephemeral)* GREEN — parse unencrypted ephemeral.json app-state
- *(timeline)* GREEN — timestamp-ordered message timeline
- *(store)* GREEN — attachment metadata parsing
- *(store)* GREEN — contacts projection
- *(store)* GREEN — messages parsing
- *(store)* GREEN — SQLCipher open (read-only, loud on wrong key) + conversations
- *(keys)* GREEN — unwrap the SQLCipher key from config.json
- *(config)* GREEN — parse config.json (modern encryptedKey + legacy key)

### Other

- *(coverage)* back-fill tests for the 8 uncovered functions + add gate
- *(ephemeral)* RED — ephemeral.json app-state parser spec
- *(core)* drop unused safe-read dep (no raw-offset parsing here)
- *(oracle)* real db.sqlite wrong-key rejection (tier-2 on real bytes)
- *(core)* re-export the public API + RecoveredKey at crate root
- *(timeline)* RED — time-ordered message timeline spec
- *(store)* RED — attachment metadata spec
- *(store)* RED — contacts spec
- *(store)* RED — messages spec
- *(store)* RED — SQLCipher open + conversations spec
- *(keys)* RED — SQLCipher key unwrap spec (legacy + encryptedKey + loud fails)
- *(config)* RED — config.json parser spec (modern/legacy/loud failures)
- scaffold signal-desktop-forensic parser suite
