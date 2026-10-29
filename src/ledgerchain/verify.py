"""Recompute-and-compare verification.

One implementation shared by the CLI, by any HTTP endpoint a host app
exposes, and by the tamper tests, so "the API says valid" and "the CLI says
valid" can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .checkpoint import merkle_root
from .models import DecisionLedgerEntry, LedgerCheckpoint, LedgerHead
from .writer import (
    CHECKPOINT_EVENT_TYPE,
    GENESIS_PREV_HASH,
    REDACTION_EVENT_TYPE,
    compute_entry_hash,
    payload_digest,
)


@dataclass
class VerifyResult:
    """Outcome of :func:`verify_chain`.

    ``valid`` is the single answer. When it is ``False``, exactly one of
    these explains why: ``first_bad_seq`` and ``reason`` point at a chain
    break, ``head_valid=False`` means the entries check out but the head
    row disagrees, and a checkpoint with ``root_valid=False`` means a
    checkpoint row no longer matches the entries it covers.

    ``redacted`` lists the seqs whose payload was erased through
    :meth:`ledgerchain.LedgerWriter.redact`. That is not a failure.
    """

    valid: bool
    checked_entries: int
    first_bad_seq: int | None = None
    reason: str | None = None
    head_valid: bool = True
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    redacted: list[int] = field(default_factory=list)

    @property
    def checkpoints_valid(self) -> bool:
        return all(cp.get("root_valid") is not False for cp in self.checkpoints)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "checked_entries": self.checked_entries,
            "first_bad_seq": self.first_bad_seq,
            "reason": self.reason,
            "head_valid": self.head_valid,
            "checkpoints_valid": self.checkpoints_valid,
            "checkpoints": self.checkpoints,
            "redacted": self.redacted,
        }


def verify_chain(
    session: Session,
    *,
    from_seq: int | None = None,
    to_seq: int | None = None,
    check_checkpoints: bool = True,
) -> VerifyResult:
    """Recompute every hash in ``[from_seq, to_seq]`` and compare to storage.

    Walks entries in ``seq`` order recomputing ``payload_sha256`` and
    ``entry_hash`` from the stored row content, checking each against the
    previous entry's hash and against a strictly contiguous ``seq``. Stops
    at the first mismatch; that is the tamper site. When the walk reaches
    the current head, also checks the final hash against ``ledger_head`` to
    catch a forged head row even when every entry still checks out.

    With ``check_checkpoints=True`` every checkpoint overlapping the range
    is listed and its Merkle root is recomputed from the stored entry
    hashes it covers, and must start right after the previous checkpoint and
    carry its root. A checkpoint row whose root, range, or link no longer
    matches reports ``root_valid=False`` and makes the whole result invalid.
    Every ``checkpoint`` entry walked must also have a row that agrees with
    it, so deleting or editing checkpoint rows is caught.
    """
    start_seq = 1 if from_seq is None or from_seq <= 1 else from_seq
    expected_prev = GENESIS_PREV_HASH
    # Versions never go backwards: rewriting a v2 row as v1 would drop actor
    # and subject_uri from the hash.
    min_version = 1

    if start_seq > 1:
        anchor = session.get(DecisionLedgerEntry, start_seq - 1)
        if anchor is None:
            return VerifyResult(
                valid=False,
                checked_entries=0,
                first_bad_seq=start_seq,
                reason=f"no entry at seq={start_seq - 1} to anchor the range start",
            )
        expected_prev = anchor.entry_hash
        min_version = anchor.hash_version

    query = select(DecisionLedgerEntry).where(DecisionLedgerEntry.seq >= start_seq)
    if to_seq is not None:
        query = query.where(DecisionLedgerEntry.seq <= to_seq)
    query = query.order_by(DecisionLedgerEntry.seq.asc())
    # Streamed in batches: memory stays flat however long the ledger is.
    entries = session.execute(query.execution_options(yield_per=1000)).scalars()

    expected_seq = start_seq
    checked = 0
    last_entry: DecisionLedgerEntry | None = None
    checkpoint_entries: list[DecisionLedgerEntry] = []
    redacted: dict[int, str] = {}  # redacted seq -> its tenant
    # (redacted seq, tenant) -> latest redaction entry naming it from that tenant
    explained: dict[tuple[int, str], int] = {}
    try:
        for entry in entries:
            checked += 1
            if entry.seq != expected_seq:
                return VerifyResult(
                    valid=False,
                    checked_entries=checked,
                    first_bad_seq=entry.seq,
                    reason=(
                        f"seq gap: expected {expected_seq}, found {entry.seq} "
                        "(row deleted or reordered)"
                    ),
                )
            if entry.hash_version not in (1, 2) or entry.hash_version < min_version:
                return VerifyResult(
                    valid=False,
                    checked_entries=checked,
                    first_bad_seq=entry.seq,
                    reason=(
                        f"hash_version {entry.hash_version} is unknown or older than {min_version}"
                    ),
                )
            min_version = entry.hash_version
            # A redacted payload cannot be rehashed; entry_hash still covers
            # payload_sha256, and the redaction record is checked below.
            salt = entry.payload_salt if entry.hash_version >= 2 else None
            if entry.payload is None:
                redacted[entry.seq] = entry.tenant_id
            elif payload_digest(entry.payload, salt) != entry.payload_sha256:
                return VerifyResult(
                    valid=False,
                    checked_entries=checked,
                    first_bad_seq=entry.seq,
                    reason="payload_sha256 mismatch: payload was modified",
                )
            if entry.prev_hash != expected_prev:
                return VerifyResult(
                    valid=False,
                    checked_entries=checked,
                    first_bad_seq=entry.seq,
                    reason="prev_hash does not chain from the prior entry",
                )
            recomputed = compute_entry_hash(
                prev_hash=entry.prev_hash,
                payload_sha256=entry.payload_sha256,
                seq=entry.seq,
                event_type=entry.event_type,
                ts=entry.ts,
                tenant_id=entry.tenant_id,
                actor=entry.actor,
                subject_uri=entry.subject_uri,
                hash_version=entry.hash_version,
            )
            if recomputed != entry.entry_hash:
                return VerifyResult(
                    valid=False,
                    checked_entries=checked,
                    first_bad_seq=entry.seq,
                    reason="entry_hash does not match recomputed hash: row was tampered",
                )
            expected_prev = entry.entry_hash
            expected_seq += 1
            last_entry = entry
            if entry.event_type == CHECKPOINT_EVENT_TYPE:
                checkpoint_entries.append(entry)
            elif entry.event_type == REDACTION_EVENT_TYPE:
                _note_redaction(explained, entry)
    finally:
        entries.close()

    unexplained = _unexplained_redactions(session, redacted, explained, last_entry)
    if unexplained is not None:
        return VerifyResult(
            valid=False,
            checked_entries=checked,
            first_bad_seq=unexplained,
            reason="payload removed without a redaction entry",
            redacted=list(redacted),
        )

    head_valid = True
    head = session.execute(select(LedgerHead)).scalar_one_or_none()
    reached_current_head = head is not None and (to_seq is None or to_seq >= head.last_seq)
    if reached_current_head and head is not None:
        if last_entry is not None:
            head_valid = head.last_hash == last_entry.entry_hash and head.last_seq == last_entry.seq
        else:
            # The range produced zero entries but a head row exists: it
            # points somewhere this walk never reached.
            head_valid = head.last_seq == 0

    reason = (
        None
        if head_valid
        else "ledger_head does not match the last verified entry: forged or corrupt head"
    )

    checkpoints: list[dict[str, Any]] = []
    if check_checkpoints:
        checkpoints = _checkpoint_summaries(session, start_seq=start_seq, to_seq=to_seq)

    checkpoints_valid = all(cp["root_valid"] is not False for cp in checkpoints)
    if head_valid and not checkpoints_valid and reason is None:
        bad = next(cp for cp in checkpoints if cp["root_valid"] is False)
        reason = f"checkpoint {bad['id']}: {bad['root_reason']}"

    if check_checkpoints and head_valid and checkpoints_valid:
        mismatch = _checkpoint_entry_mismatch(session, checkpoint_entries)
        if mismatch is not None:
            return VerifyResult(
                valid=False,
                checked_entries=checked,
                first_bad_seq=mismatch[0],
                reason=mismatch[1],
                checkpoints=checkpoints,
                redacted=list(redacted),
            )

    return VerifyResult(
        valid=head_valid and checkpoints_valid,
        checked_entries=checked,
        head_valid=head_valid,
        reason=reason,
        checkpoints=checkpoints,
        redacted=list(redacted),
    )


def _checkpoint_summaries(
    session: Session, *, start_seq: int, to_seq: int | None
) -> list[dict[str, Any]]:
    query = select(LedgerCheckpoint).where(LedgerCheckpoint.to_seq >= start_seq)
    if to_seq is not None:
        query = query.where(LedgerCheckpoint.from_seq <= to_seq)
    query = query.order_by(LedgerCheckpoint.from_seq.asc())

    summaries: list[dict[str, Any]] = []
    prev: LedgerCheckpoint | None = None
    for cp in session.execute(query).scalars().all():
        hashes = (
            session.execute(
                select(DecisionLedgerEntry.entry_hash)
                .where(
                    DecisionLedgerEntry.seq >= cp.from_seq,
                    DecisionLedgerEntry.seq <= cp.to_seq,
                )
                .order_by(DecisionLedgerEntry.seq.asc())
            )
            .scalars()
            .all()
        )
        expected_count = cp.to_seq - cp.from_seq + 1
        if len(hashes) != expected_count:
            root_valid: bool | None = False
            root_reason: str | None = (
                f"checkpoint covers {expected_count} entries but {len(hashes)} exist"
            )
        elif merkle_root(hashes) != cp.merkle_root:
            root_valid = False
            root_reason = "stored merkle_root does not match recomputed root"
        else:
            root_valid = True
            root_reason = None
        # Checkpoints tile the ledger: each starts right after the previous
        # one and carries its root. The first listed one is only checkable
        # when it starts at seq 1; a partial range does not see its predecessor.
        if root_valid and (prev is not None or cp.from_seq == 1):
            want_from = prev.to_seq + 1 if prev is not None else 1
            want_root = prev.merkle_root if prev is not None else None
            if cp.from_seq != want_from or cp.prev_checkpoint_root != want_root:
                root_valid = False
                root_reason = (
                    f"does not chain from checkpoint {prev.id}"
                    if prev is not None
                    else "first checkpoint must have no prev_checkpoint_root"
                )
        prev = cp
        summary = cp.to_dict()
        summary["root_valid"] = root_valid
        summary["root_reason"] = root_reason
        summaries.append(summary)
    return summaries


_CHECKPOINT_FIELDS = ("from_seq", "to_seq", "merkle_root", "prev_checkpoint_root")


def _checkpoint_entry_mismatch(
    session: Session, entries: list[DecisionLedgerEntry]
) -> tuple[int, str] | None:
    """Every checkpoint entry in the chain must have a row that agrees with it.

    The entries are hash-chained and trigger-protected; the
    ``ledger_checkpoint`` table is neither, so the entries are the authority.
    Returns ``(seq, reason)`` for the first disagreement.
    """
    for entry in entries:
        if entry.payload is None:
            return entry.seq, f"checkpoint entry at seq={entry.seq} had its payload removed"
        cp_id = entry.payload.get("checkpoint_id")
        row = session.get(LedgerCheckpoint, cp_id) if isinstance(cp_id, int) else None
        if row is None:
            return entry.seq, f"checkpoint entry at seq={entry.seq} has no checkpoint row {cp_id}"
        if any(getattr(row, f) != entry.payload.get(f) for f in _CHECKPOINT_FIELDS):
            return entry.seq, f"checkpoint {row.id} row disagrees with its entry at seq={entry.seq}"
    return None


def _note_redaction(explained: dict[tuple[int, str], int], record: DecisionLedgerEntry) -> None:
    target = record.payload.get("seq") if record.payload is not None else None
    if isinstance(target, int):
        key = (target, record.tenant_id)
        explained[key] = max(explained.get(key, 0), record.seq)


def _unexplained_redactions(
    session: Session,
    redacted: dict[int, str],
    explained: dict[tuple[int, str], int],
    last_entry: DecisionLedgerEntry | None,
) -> int | None:
    """First redacted seq with no later ``redaction`` entry naming it from
    the same tenant.

    Records come from the walk. Only when one is still missing, and the
    walk stopped short of the end of the ledger, are later entries looked up
    by seq range; a full verify also checks those entries' own hashes.
    """

    def unexplained(seqs: list[int]) -> list[int]:
        return [seq for seq in seqs if explained.get((seq, redacted[seq]), 0) <= seq]

    missing = unexplained(list(redacted))
    if missing and last_entry is not None:
        beyond = select(DecisionLedgerEntry).where(
            DecisionLedgerEntry.seq > last_entry.seq,
            DecisionLedgerEntry.event_type == REDACTION_EVENT_TYPE,
        )
        for record in session.scalars(beyond):
            _note_redaction(explained, record)
        missing = unexplained(missing)
    return missing[0] if missing else None
