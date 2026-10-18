"""Merkle checkpoints over the ledger.

A checkpoint summarizes a contiguous ``seq`` range with one Merkle root and
chains to the previous checkpoint's root via ``prev_checkpoint_root``. The
checkpoint is also appended to the ledger as a ``checkpoint`` entry, so the
chain carries its own checkpoint history. External anchoring is a separate
step (:mod:`ledgerchain.anchor`) so a storage outage never blocks
checkpoint creation.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import DecisionLedgerEntry, LedgerCheckpoint, LedgerHead
from .writer import CHECKPOINT_EVENT_TYPE, LedgerWriter

CHECKPOINT_ACTOR: dict[str, Any] = {"kind": "system", "sub": "ledger-checkpoint"}


def merkle_root(leaf_hexdigests: Sequence[str]) -> str:
    """Binary Merkle root over hex SHA-256 leaves, returned as hex.

    Pairs are hashed as ``sha256(left || right)`` over the raw 32-byte
    digests. An odd node at any level is promoted unchanged rather than
    duplicated, which avoids the known second-preimage weakness of the
    duplicate-last-node variant. Raises ``ValueError`` on an empty input.
    """
    if not leaf_hexdigests:
        raise ValueError("merkle_root requires at least one leaf")

    level = [bytes.fromhex(h) for h in leaf_hexdigests]
    while len(level) > 1:
        next_level = [
            hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2 == 1:
            next_level.append(level[-1])
        level = next_level
    return level[0].hex()


@dataclass(frozen=True)
class CheckpointResult:
    checkpoint: LedgerCheckpoint | None
    skipped_reason: str | None = None


def build_checkpoint(
    session: Session,
    *,
    tenant_id: str = "default",
    commit: bool = True,
) -> CheckpointResult:
    """Build one checkpoint over every entry since the last checkpoint.

    The range is ``(last_checkpoint.to_seq, head.last_seq]``, or
    ``[1, head.last_seq]`` when no checkpoint exists yet. Writes the
    ``LedgerCheckpoint`` row and appends a ``checkpoint`` ledger entry
    carrying the same ``{from_seq, to_seq, merkle_root,
    prev_checkpoint_root}``. With ``commit=True`` (the default) both land
    in one commit; pass ``commit=False`` to fold them into a larger
    transaction you control.

    Returns ``skipped_reason`` and no checkpoint when there is nothing new
    to cover: an empty ledger, or a head that has not advanced past the
    last checkpoint.
    """
    head = session.execute(select(LedgerHead)).scalar_one_or_none()
    if head is None:
        return CheckpointResult(checkpoint=None, skipped_reason="ledger is empty (no genesis yet)")

    last_checkpoint = (
        session.execute(select(LedgerCheckpoint).order_by(LedgerCheckpoint.to_seq.desc()))
        .scalars()
        .first()
    )
    from_seq = 1 if last_checkpoint is None else last_checkpoint.to_seq + 1
    to_seq = head.last_seq

    if from_seq > to_seq:
        covered = last_checkpoint.to_seq if last_checkpoint is not None else 0
        return CheckpointResult(
            checkpoint=None,
            skipped_reason=f"nothing new since last checkpoint (to_seq={covered})",
        )

    hashes = (
        session.execute(
            select(DecisionLedgerEntry.entry_hash)
            .where(DecisionLedgerEntry.seq >= from_seq, DecisionLedgerEntry.seq <= to_seq)
            .order_by(DecisionLedgerEntry.seq.asc())
        )
        .scalars()
        .all()
    )
    root = merkle_root(hashes)
    prev_root = last_checkpoint.merkle_root if last_checkpoint is not None else None

    checkpoint = LedgerCheckpoint(
        from_seq=from_seq,
        to_seq=to_seq,
        merkle_root=root,
        prev_checkpoint_root=prev_root,
        anchor_status="pending",
    )
    session.add(checkpoint)
    session.flush()

    LedgerWriter.append(
        session,
        event_type=CHECKPOINT_EVENT_TYPE,
        payload={
            "checkpoint_id": checkpoint.id,
            "from_seq": from_seq,
            "to_seq": to_seq,
            "merkle_root": root,
            "prev_checkpoint_root": prev_root,
        },
        actor=CHECKPOINT_ACTOR,
        tenant_id=tenant_id,
        subject_uri=f"ledger://checkpoints/{checkpoint.id}",
    )
    if commit:
        session.commit()
    return CheckpointResult(checkpoint=checkpoint)
