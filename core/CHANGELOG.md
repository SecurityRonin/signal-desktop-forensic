# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/SecurityRonin/signal-desktop-forensic/compare/signal-desktop-core-v0.1.0...signal-desktop-core-v0.2.0) - 2026-07-30

### Added

- *(records)* expose isViewOnce / isErased / plaintextHash
- *(store)* read attachments from the message_attachments table

### Fixed

- *(store)* read the wall-clock time from the message json on legacy schemas
- *(store)* time messages by received_at_ms, never the ordering counter

### Other

- *(store)* RED — a legacy profile's json wall-clock time is dropped to 0
- *(store)* assert the flags without an unreachable closure
- *(store)* RED — isViewOnce / isErased / plaintextHash are dropped
- *(store)* RED — a migrated attachment must not be counted twice
- *(store)* RED — attachments in message_attachments are invisible
- *(store)* RED — received_at is an ordering counter, not an epoch
- *(coverage)* close line-coverage gap (6 lines: 6 tests, 0 annotated arms)
- *(differential)* reconcile our SQLCipher reader against the sqlcipher CLI
