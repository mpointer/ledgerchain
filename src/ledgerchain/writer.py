"""The one code path that appends to the ledger.

``LedgerWriter.append`` runs inside the caller's SQLAlchemy transaction and
never calls ``session.commit()``. The caller's commit or rollback decides
whether the ledger entry and the state change it documents land together.
That is the atomicity guarantee: there is no fire-and-forget mode, and a
write failure propagates to the caller's transaction.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .canonical import sha256_hex
from .models import DecisionLedgerEntry, LedgerHead

GENESIS_PREV_HASH = "0" * 64
"""The genesis entry chains from this sentinel: 64 zero hex digits, never a
real SHA-256 output."""

GENESIS_EVENT_TYPE = "genesis"
"""Reserved. The writer creates exactly one genesis entry per ledger."""

CHECKPOINT_EVENT_TYPE = "checkpoint"
"""Reserved for entries written by :func:`ledgerchain.build_checkpoint`."""

GENESIS_ACTOR: dict[str, Any] = {"kind": "system", "sub": "ledger-writer"}


def rfc3339_utc(ts: datetime) -> str:
    """``2026-10-18T12:00:00.123456Z`` form used inside the entry hash."""
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def compute_entry_hash(
    *,
    prev_hash: str,
    payload_sha256: str,
    seq: int,
    event_type: str,
    ts: datetime,
    tenant_id: str,
) -> str:
    """``sha256(prev_hash \\n payload_sha256 \\n seq \\n event_type \\n ts \\n tenant_id)``.

    Fields are joined with a newline, timestamps are RFC 3339 in UTC, and
    every digest is a full 64-hex string. No truncation anywhere.
    """
    material = "\n".join(
        [prev_hash, payload_sha256, str(seq), event_type, rfc3339_utc(ts), tenant_id]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class LedgerWriter:
    """Namespace for the single append entry point."""

    @staticmethod
    def append(
        session: Session,
        *,
        event_type: str,
        payload: Mapping[str, Any],
        actor: Mapping[str, Any],
        tenant_id: str,
        subject_uri: str | None = None,
        ts: datetime | None = None,
    ) -> DecisionLedgerEntry:
        """Append one entry to the hash chain.

        Locks ``ledger_head`` (``SELECT ... FOR UPDATE``; on SQLite this
        degrades to the file writer lock), lazily creates the genesis entry
        on a cold ledger, then inserts the requested entry chained onto the
        current head.

        ``event_type`` is caller-defined, except ``"genesis"`` and
        ``"checkpoint"``, which are reserved: the verifier trusts every
        ``checkpoint`` entry as the record of a checkpoint row.
        ``payload`` and ``actor`` must be JSON-serializable per
        RFC 8785; a ``set`` or a non-string key raises
        :class:`ledgerchain.CanonicalizationError` before anything is
        written. ``ts`` defaults to now and must be timezone-aware if given.

        Returns the flushed, not committed, entry so callers can read the
        assigned ``seq`` and ``entry_hash`` immediately.
        """
        if event_type in (GENESIS_EVENT_TYPE, CHECKPOINT_EVENT_TYPE):
            raise ValueError(f"event_type {event_type!r} is reserved for ledgerchain")
        return _append(
            session,
            event_type=event_type,
            payload=payload,
            actor=actor,
            tenant_id=tenant_id,
            subject_uri=subject_uri,
            ts=ts,
        )


def _append(
    session: Session,
    *,
    event_type: str,
    payload: Mapping[str, Any],
    actor: Mapping[str, Any],
    tenant_id: str,
    subject_uri: str | None = None,
    ts: datetime | None = None,
) -> DecisionLedgerEntry:
    """``LedgerWriter.append`` without the reserved-type check, for this package."""
    if ts is not None and ts.tzinfo is None:
        raise ValueError("ts must be timezone-aware")

    # populate_existing: a head already in the identity map (e.g. read
    # unlocked earlier in this session) would otherwise keep its stale
    # last_seq even though FOR UPDATE just returned the current row.
    head = session.execute(
        select(LedgerHead).with_for_update().execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if head is None:
        head = _create_genesis(session, tenant_id=tenant_id)

    entry = _build_entry(
        seq=head.last_seq + 1,
        prev_hash=head.last_hash,
        event_type=event_type,
        payload=payload,
        actor=actor,
        tenant_id=tenant_id,
        subject_uri=subject_uri,
        ts=ts,
    )
    session.add(entry)
    head.last_seq = entry.seq
    head.last_hash = entry.entry_hash
    session.flush()
    return entry


def _build_entry(
    *,
    seq: int,
    prev_hash: str,
    event_type: str,
    payload: Mapping[str, Any],
    actor: Mapping[str, Any],
    tenant_id: str,
    subject_uri: str | None,
    ts: datetime | None = None,
) -> DecisionLedgerEntry:
    when = ts if ts is not None else datetime.now(timezone.utc)
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a JSON object (mapping), got " + type(payload).__name__)
    if not isinstance(actor, Mapping):
        raise TypeError("actor must be a JSON object (mapping), got " + type(actor).__name__)
    payload_dict = dict(payload)
    actor_dict = dict(actor)
    payload_sha256 = sha256_hex(payload_dict)
    # Canonicalize the actor too so a non-serializable actor fails before
    # the row is added, not at flush time inside the JSON type.
    sha256_hex(actor_dict)
    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        payload_sha256=payload_sha256,
        seq=seq,
        event_type=event_type,
        ts=when,
        tenant_id=tenant_id,
    )
    return DecisionLedgerEntry(
        seq=seq,
        tenant_id=tenant_id,
        ts=when,
        event_type=event_type,
        actor=actor_dict,
        subject_uri=subject_uri,
        payload=payload_dict,
        payload_sha256=payload_sha256,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )


def _create_genesis(session: Session, *, tenant_id: str) -> LedgerHead:
    """First-ever append: seed the ``seq=1`` genesis entry and the head row.

    There is no head row to lock yet, so two processes racing their very
    first append could both reach this. The primary key on ``ledger_head``
    and the unique ``entry_hash`` turn that race into an ``IntegrityError``
    for the loser rather than a silent double genesis.
    """
    genesis = _build_entry(
        seq=1,
        prev_hash=GENESIS_PREV_HASH,
        event_type=GENESIS_EVENT_TYPE,
        payload={},
        actor=GENESIS_ACTOR,
        tenant_id=tenant_id,
        subject_uri=None,
    )
    session.add(genesis)
    head = LedgerHead(id=True, last_seq=genesis.seq, last_hash=genesis.entry_hash)
    session.add(head)
    session.flush()
    return head
