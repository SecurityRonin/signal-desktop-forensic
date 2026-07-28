# 1. Reader / analyzer split (`-core` + `-forensic`)

Date: 2026-07-29

## Status

Accepted.

## Context

Signal Desktop is a single artifact family (one profile, one SQLCipher DB plus a
`config.json` key store), so the repo follows the fleet Pattern-A shape: one
`<x>-forensic` workspace with a raw reader and an anomaly auditor
(ADR-0008/0009 in `ronin-issen`).

## Decision

Two members:

- **`signal-desktop-core`** — the raw reader. Recovers the SQLCipher key,
  opens the database, and exposes typed records (`Conversation`, `Message`,
  `Contact`, `Attachment`) plus a merged `TimelineEntry` stream. It emits **no
  findings** and makes no forensic judgements.
- **`signal-desktop-forensic`** — the analyzer. Consumes the reader's records
  and grades them into normalized `forensicnomicon_core::report::Finding`s via
  the `Observation` trait — observations in consistent-with language, never
  verdicts.

## Consequences

A consumer that only needs the decrypted records depends on `-core` alone; the
graded-findings surface is opt-in. The split matches every other fleet parser,
so the reader/analyzer boundary is where a reviewer expects it.
