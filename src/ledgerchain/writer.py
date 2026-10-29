"""The one code path that appends to the ledger.

``LedgerWriter.append`` runs inside the caller's SQLAlchemy transaction and
never calls ``session.commit()``. The caller's commit or rollback decides
whether the ledger entry and the state change it documents land together.
That is the atomicity guarantee: there is no fire-and-forget mode, and a
write failure propagates to the caller's transaction.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, select, update
from sqlalchemy.orm import Session

from .canonical import canonicalize, sha256_hex
from .models import DecisionLedgerEntry, LedgerHead

GENESIS_PREV_HASH = "0" * 64
"""The genesis entry chains from this sentinel: 64 zero hex digits, never a
real SHA-256 output."""

GENESIS_EVENT_TYPE = "genesis"
"""Reserved. The writer creates exactly one genesis entry per ledger."""

CHECKPOINT_EVENT_TYPE = "checkpoint"
"""Reserved for entries written by :func:`ledgerchain.build_checkpoint`."""

REDACTION_EVENT_TYPE = "redaction"
"""Reserved for entries written by :meth:`LedgerWriter.redact`."""

RESERVED_EVENT_TYPES = (GENESIS_EVENT_TYPE, CHECKPOINT_EVENT_TYPE, REDACTION_EVENT_TYPE)

GENESIS_ACTOR: dict[str, Any] = {"kind": "system", "sub": "ledger-writer"}

HASH_VERSION = 2
"""Entry hash layout the writer stamps on new rows. Version 1 rows still verify."""


def rfc3339_utc(ts: datetime) -> str:
    """``2026-10-18T12:00:00.123456Z`` form used inside the entry hash."""
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def payload_digest(payload: Mapping[str, Any], salt: str | None) -> str:
    """``payload_sha256`` for a payload.

    With a salt (hash version 2) it is ``sha256(RFC8785({"payload": payload,
    "salt": salt}))``. Without one (version 1 rows) it is
    ``sha256(RFC8785(payload))``.
    """
    if salt is None:
        return sha256_hex(dict(payload))
    return sha256_hex({"payload": dict(payload), "salt": salt})


def compute_entry_hash(
    *,
    prev_hash: str,
    payload_sha256: str,
    seq: int,
    event_type: str,
    ts: datetime,
    tenant_id: str,
    actor: Mapping[str, Any] | None = None,
    subject_uri: str | None = None,
    hash_version: int = 1,
) -> str:
    """The entry hash for ``hash_version``. Timestamps are RFC 3339 in UTC and
    every digest is a full 64-hex string; nothing is truncated.

    Version 2 (what the writer stamps today) is ``sha256(RFC8785([...]))`` over
    ``["ledgerchain/v2", prev_hash, payload_sha256, seq, event_type, ts,
    tenant_id, actor, subject_uri]``. It covers who acted and on what, and a
    JSON array cannot be re-split the way joined strings can.

    Version 1 is ``sha256(prev_hash \\n payload_sha256 \\n seq \\n event_type
    \\n ts \\n tenant_id)``. It leaves ``actor`` and ``subject_uri``
    unprotected and lets a newline inside a field shift content into its
    neighbour. Only verify old rows with it.
    """
    if hash_version == 1:
        material = "\n".join(
            [prev_hash, payload_sha256, str(seq), event_type, rfc3339_utc(ts), tenant_id]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()
    if hash_version == 2:
        if actor is None:
            raise ValueError("hash_version 2 covers the actor; pass actor=")
        fields = [
            "ledgerchain/v2",
            prev_hash,
            payload_sha256,
            seq,
            event_type,
            rfc3339_utc(ts),
            tenant_id,
            dict(actor),
            subject_uri,
        ]
        return hashlib.sha256(canonicalize(fields)).hexdigest()
    raise ValueError(f"unknown hash_version {hash_version}")


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

        ``event_type`` is caller-defined, except ``"genesis"``,
        ``"checkpoint"`` and ``"redaction"``, which are reserved: the
        verifier trusts those entries as records of what ledgerchain did.
        ``payload`` and ``actor`` must be JSON-serializable per
        RFC 8785; a ``set`` or a non-string key raises
        :class:`ledgerchain.CanonicalizationError` before anything is
        written. ``ts`` defaults to now and must be timezone-aware if given.

        Returns the flushed, not committed, entry so callers can read the
        assigned ``seq`` and ``entry_hash`` immediately.
        """
        if event_type in RESERVED_EVENT_TYPES:
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

    @staticmethod
    def redact(
        session: Session,
        seq: int,
        *,
        actor: Mapping[str, Any],
        tenant_id: str,
        reason: str,
    ) -> DecisionLedgerEntry:
        """Erase entry ``seq``'s payload for good, keeping the chain intact.

        Sets the payload to JSON null and deletes its salt; every hashed
        column stays as it was, so ``entry_hash``, checkpoints and anchors
        still verify. Then appends a ``redaction`` entry recording ``seq``,
        ``reason`` and ``actor``, so the erasure is itself on the record.
        ``verify_chain`` reports redacted seqs and fails on a payload that
        was removed without such an entry.

        Runs inside the caller's transaction and never commits, like
        :meth:`append`. Deciding who may redact is the caller's job.
        Version 1 rows have no salt: their remaining ``payload_sha256`` is a
        plain hash and a guessable payload could be recovered from it.
        """
        entry = session.get(DecisionLedgerEntry, seq)
        if entry is None:
            raise LookupError(f"no ledger entry at seq={seq}")
        if entry.event_type in RESERVED_EVENT_TYPES:
            raise ValueError(f"{entry.event_type!r} entries cannot be redacted")
        if entry.payload is None:
            raise ValueError(f"entry seq={seq} is already redacted")
        session.execute(
            update(DecisionLedgerEntry)
            .where(DecisionLedgerEntry.seq == seq)
            .values(payload=JSON.NULL, payload_salt=None)
        )
        session.expire(entry, ["payload", "payload_salt"])
        return _append(
            session,
            event_type=REDACTION_EVENT_TYPE,
            payload={"seq": seq, "reason": reason},
            actor=actor,
            tenant_id=tenant_id,
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
    salt = secrets.token_hex(32)
    payload_sha256 = payload_digest(payload_dict, salt)
    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        payload_sha256=payload_sha256,
        seq=seq,
        event_type=event_type,
        ts=when,
        tenant_id=tenant_id,
        actor=actor_dict,
        subject_uri=subject_uri,
        hash_version=HASH_VERSION,
    )
    return DecisionLedgerEntry(
        seq=seq,
        hash_version=HASH_VERSION,
        tenant_id=tenant_id,
        ts=when,
        event_type=event_type,
        actor=actor_dict,
        subject_uri=subject_uri,
        payload=payload_dict,
        payload_salt=salt,
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
