# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- Entry hash version 2 covers `actor` and `subject_uri`. Version 1 hashed
  neither, so whoever could write the database could change who made a
  decision, or what it was about, without breaking any hash, checkpoint, or
  anchor. Version 2 hashes the fields as an RFC 8785 JSON array. The old
  newline-joined form was also ambiguous: a newline inside `event_type` or
  `tenant_id` could shift content between fields without changing the hash.
- Each row records `hash_version`. The writer stamps 2. Version 1 rows keep
  verifying, and `verify_chain` rejects a version lower than the one before
  it, so a v2 row cannot be quietly rewritten as v1.
- `verify_anchors` reads the bucket's version listing and checks each row
  against the oldest version of its anchor, the original witness. It also
  fails if an anchor key has a second version or a delete marker. Object
  Lock keeps old versions but does not stop either one, so someone holding
  the application's S3 credentials could previously shadow an anchor with a
  forged version, or hide it from the object listing behind a delete marker.
- `ledger_checkpoint` gets an immutability trigger. Rows cannot be deleted,
  and only `anchor_status` and `anchor_uri` may change.

### Fixed

- `anchor_checkpoint(..., commit=False)` leaves committing to the caller.
  The default (`commit=True`) still commits the whole session, as before,
  and its docstring now says so.
- `ledgerchain checkpoint --anchor` exits 1 when anchoring fails or is not
  configured. It used to exit 0.
- `verify_chain` streams rows instead of loading the whole ledger. Peak
  memory for 100k entries went from 295 MB to 6 MB; time is unchanged.
- `create_all` raises `ValueError` on a dialect with no immutability
  triggers (anything other than PostgreSQL and SQLite) instead of quietly
  creating an unprotected ledger. Pass `immutable=False` to accept that.
- `__version__` is read from the installed package metadata, so
  `pyproject.toml` is the only place the version is set.

### Changed

- `rfc8785` is capped below 0.2. Every stored hash depends on its exact
  output, so a new minor version should be adopted deliberately.
- CI and release workflows run with read-only `contents` permission, and
  every action is pinned to a commit SHA. Dependabot keeps the pins and
  dependencies current. The release workflow also checks formatting and
  runs the PostgreSQL tests against a service container.

### Upgrading

- Add the column before deploying. Existing rows become version 1, and the
  statement fires no row triggers:
  `ALTER TABLE decision_ledger ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1;`
  In Alembic, add the column with `server_default="1"`.
- `compute_entry_hash` takes `actor`, `subject_uri` and `hash_version`.
  Its default is still `hash_version=1`. An auditor recomputing new rows
  outside the library must pass the row's `hash_version` and use the v2
  layout from the README.
- `HASH_VERSION` is exported. `DecisionLedgerEntry.to_dict()` includes
  `hash_version`.
- Re-run `install_immutability` (it is idempotent) to add the
  `ledger_checkpoint` trigger to an existing database.
- Anchor verification lists object versions. The S3 client needs
  `list_object_versions` and `get_object(VersionId=...)` instead of
  `list_objects_v2`. On AWS, the verifying role needs
  `s3:ListBucketVersions` and `s3:GetObjectVersion`.

## [0.2.0] - 2026-10-29

Security release. Upgrade if you rely on anchoring or checkpoints.

### Upgrading

- Verification is stricter, so a ledger that passed under 0.1.0 can now
  report invalid. This happens if its checkpoint chain forked through
  concurrent checkpoint jobs, if checkpoint rows were edited or deleted, or
  if the application appended its own `"checkpoint"` events. Those are real
  problems that 0.1.0 missed.
- Run `verify --check-anchors` and `verify_anchors` with the same bucket
  and prefix the anchors were written with. A missing bucket configuration
  now fails instead of passing.
- The `s3` extra needs `boto3>=1.35.2`. Injected clients need
  `list_objects_v2` as well as `put_object` and `get_object`.
- `LedgerWriter.append(event_type="checkpoint")` now raises.

### Security

- `verify_anchor` now locates the anchored object from its `AnchorConfig`
  (bucket, prefix) and the checkpoint range, and ignores the row's
  `anchor_uri`. A database superuser could previously repoint `anchor_uri`
  at a bucket they control and pass the check. Verify with the same bucket
  and prefix the anchors were written with.
- Anchors are write-once (`IfNoneMatch="*"`). Previously a forged checkpoint
  flipped back to `failed` would be re-anchored to the same key, and in a
  versioned Object Lock bucket the forged copy became the version
  `get_object` returns. Re-anchoring an unchanged checkpoint still succeeds.
  The `s3` extra now requires `boto3>=1.35.2`.
- `ledgerchain verify --check-anchors` (now `verify_anchors`) starts from a
  listing of the bucket instead of trusting `anchor_status`, which a
  superuser could flip to skip checkpoints. Every anchor must match a
  checkpoint row of exactly its range, so deleting, merging, or re-ranging
  anchored checkpoints is detected. Rows with no anchor are reported as
  `unanchored`; `anchor_status` can only make the check stricter. A missing
  bucket configuration now fails instead of passing. The S3 client needs
  `list_objects_v2` in addition to `put_object` and `get_object`.

- `verify_chain` now checks that checkpoints tile the ledger: each starts
  right after the previous one and carries its root in
  `prev_checkpoint_root`. Every `checkpoint` entry in the chain must also
  have a `ledger_checkpoint` row that agrees with it. The table has no
  immutability triggers, so the application role could previously delete or
  edit checkpoint rows undetected. A ledger whose checkpoint chain already
  forked (see the next item) now reports invalid, which is accurate.
- `LedgerWriter.append` rejects `event_type="checkpoint"`, which was
  documented as reserved but not enforced. The verifier now trusts every
  `checkpoint` entry as the record of a checkpoint row, so an application
  event of that type would make verification fail. Ledgers that already
  contain such application events will report invalid.

### Fixed

- `build_checkpoint` locks the head row for the whole build. Two concurrent
  checkpoint jobs could both cover the same range and fork the checkpoint
  chain. On SQLite, where `FOR UPDATE` is a no-op, the verifier now reports
  such a fork.
- `LedgerWriter.append` refreshes the locked head row instead of reusing a
  stale copy from the session's identity map. `build_checkpoint` failed with
  `IntegrityError` when another writer committed while it ran.

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
