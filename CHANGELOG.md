# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-10-18

First standalone release, extracted from a production decision-integrity
platform where the same code records HITL approvals, signed attestations,
guardrail verdicts, and correction dispatches.

### Added

- `LedgerWriter.append`: the single append path. Runs inside the caller's
  SQLAlchemy transaction, locks the head row, chains the entry, never commits.
- `verify_chain`: recomputes every payload hash and entry hash in a range,
  checks contiguity, checks the head row, and recomputes every checkpoint's
  Merkle root against the entries it covers.
- `build_checkpoint` and `merkle_root`: Merkle checkpoints over contiguous
  ranges, chained by `prev_checkpoint_root`, each also recorded as a ledger
  entry.
- `anchor_checkpoint`, `retry_failed_anchors`, `verify_anchor`: write a
  checkpoint's root to S3-compatible storage with Object Lock, retry failures,
  and read the anchored copy back as an independent witness.
- `install_immutability`: BEFORE UPDATE/DELETE triggers for PostgreSQL and
  SQLite so the application role cannot rewrite history even through a bug.
- `ledgerchain` CLI: `init-db`, `verify`, `checkpoint`, `anchor`.
- Canonical JSON (RFC 8785) via the `rfc8785` package; every hash in the
  system is computed over that exact byte form.
