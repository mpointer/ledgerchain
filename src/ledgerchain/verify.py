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

from .canonical import sha256_hex
from .checkpoint import merkle_root
from .models import DecisionLedgerEntry, LedgerCheckpoint, LedgerHead
from .writer import GENESIS_PREV_HASH, compute_entry_hash


@dataclass
class VerifyResult:
    """Outcome of :func:`verify_chain`.

    ``valid`` is the single answer. When it is ``False``, exactly one of
    these explains why: ``first_bad_seq`` and ``reason`` point at a chain
    break, ``head_valid=False`` means the entries check out but the head
    row disagrees, and a checkpoint with ``root_valid=False`` means a
    checkpoint row no longer matches the entries it covers.
    """

    valid: bool
    checked_entries: int
    first_bad_seq: int | None = None
    reason: str | None = None
    head_valid: bool = True
    checkpoints: list[dict[str, Any]] = field(default_factory=list)

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
    hashes it covers. A checkpoint row whose root or range no longer
    matches reports ``root_valid=False`` and makes the whole result invalid.
    """
    start_seq = 1 if from_seq is None or from_seq <= 1 else from_seq
    expected_prev = GENESIS_PREV_HASH

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

    query = select(DecisionLedgerEntry).where(DecisionLedgerEntry.seq >= start_seq)
    if to_seq is not None:
        query = query.where(DecisionLedgerEntry.seq <= to_seq)
    query = query.order_by(DecisionLedgerEntry.seq.asc())
    entries = session.execute(query).scalars().all()

    expected_seq = start_seq
    checked = 0
    last_entry: DecisionLedgerEntry | None = None
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
        if sha256_hex(entry.payload) != entry.payload_sha256:
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
        reason = f"checkpoint {bad['id']} root does not match the entries it covers"

    return VerifyResult(
        valid=head_valid and checkpoints_valid,
        checked_entries=checked,
        head_valid=head_valid,
        reason=reason,
        checkpoints=checkpoints,
    )


def _checkpoint_summaries(
    session: Session, *, start_seq: int, to_seq: int | None
) -> list[dict[str, Any]]:
    query = select(LedgerCheckpoint).where(LedgerCheckpoint.to_seq >= start_seq)
    if to_seq is not None:
        query = query.where(LedgerCheckpoint.from_seq <= to_seq)
    query = query.order_by(LedgerCheckpoint.from_seq.asc())

    summaries: list[dict[str, Any]] = []
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
        summary = cp.to_dict()
        summary["root_valid"] = root_valid
        summary["root_reason"] = root_reason
        summaries.append(summary)
    return summaries
