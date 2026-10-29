"""SQLAlchemy models for the hash-chained ledger.

Three tables:

``decision_ledger``
    One append-only, hash-chained row per event. ``seq`` is assigned by
    the writer, not by the database, because the entry hash includes
    ``str(seq)`` and must be computable before the row is inserted.

``ledger_head``
    A single-row pointer to the latest entry. Locking it with
    ``SELECT ... FOR UPDATE`` is what serializes concurrent appends.

``ledger_checkpoint``
    Merkle checkpoints over contiguous ``seq`` ranges, chained to each
    other via ``prev_checkpoint_root``, optionally anchored to external
    storage.

The models live on their own ``Base`` so the package does not depend on
the host application's declarative base. Add ``ledgerchain.metadata`` to
your Alembic ``target_metadata`` (a list is accepted) or call
``ledgerchain.create_all`` directly.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import CHAR, TypeDecorator


class Base(DeclarativeBase):
    """Declarative base owned by this package."""


metadata = Base.metadata

# JSONB on PostgreSQL, generic JSON everywhere else.
JSONType = JSON().with_variant(JSONB(), "postgresql")

# SQLite only auto-increments a column declared exactly ``INTEGER PRIMARY
# KEY``. A BIGINT primary key never gets rowid-aliased there, so the
# checkpoint id must be a plain INTEGER on SQLite and BIGINT elsewhere.
CheckpointId = BigInteger().with_variant(Integer(), "sqlite")


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware DateTime that round-trips through SQLite.

    SQLite has no TIMESTAMPTZ. Naive datetimes read back from it are
    assumed UTC, so callers never see a tz-naive value from one dialect
    and a tz-aware value from another. Binding a naive datetime raises.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("ledger timestamps must be timezone-aware")
        return value

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None or value.tzinfo is not None:
            return value
        return value.replace(tzinfo=timezone.utc)


class DecisionLedgerEntry(Base):
    """One append-only, hash-chained ledger row."""

    __tablename__ = "decision_ledger"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    # server_default 1: rows written before the column existed are version 1.
    hash_version: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=1, server_default=text("1")
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    subject_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    # JSON null (Python None) once redacted; the SQL column stays NOT NULL.
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    # Random per-entry salt inside the payload commitment (hash version 2).
    # Erased with the payload on redaction, so the hash left behind cannot be
    # brute-forced back to low-entropy content.
    payload_salt: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False, unique=True)

    __table_args__ = (
        Index("ix_decision_ledger_tenant_subject_seq", "tenant_id", "subject_uri", "seq"),
        Index("ix_decision_ledger_tenant_event_ts", "tenant_id", "event_type", "ts"),
    )

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON view of the row. Hashes are full 64-hex digests."""
        return {
            "seq": self.seq,
            "hash_version": self.hash_version,
            "tenant_id": self.tenant_id,
            "ts": self.ts.isoformat(),
            "event_type": self.event_type,
            "actor": self.actor,
            "subject_uri": self.subject_uri,
            "payload": self.payload,
            "redacted": self.payload is None,
            "payload_sha256": self.payload_sha256,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<DecisionLedgerEntry(seq={self.seq}, event_type={self.event_type!r})>"


class LedgerHead(Base):
    """Single-row writer-serialization pointer.

    ``id`` is always ``True``. The CHECK constraint plus the primary key
    make a second row impossible.
    """

    __tablename__ = "ledger_head"

    id: Mapped[bool] = mapped_column(Boolean, primary_key=True, default=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_hash: Mapped[str] = mapped_column(CHAR(64), nullable=False)

    __table_args__ = (CheckConstraint("id = true", name="ck_ledger_head_singleton"),)


class LedgerCheckpoint(Base):
    """Merkle checkpoint over a ``seq`` range.

    ``prev_checkpoint_root`` carries the previous checkpoint's
    ``merkle_root`` (``None`` for the first), so the anchor payload is
    self-describing without a join back to the previous row.
    """

    __tablename__ = "ledger_checkpoint"

    id: Mapped[int] = mapped_column(CheckpointId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        UTCDateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    from_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    to_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    merkle_root: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    prev_checkpoint_root: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    anchor_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    anchor_status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")

    __table_args__ = (
        CheckConstraint(
            "anchor_status in ('pending','anchored','failed')",
            name="ck_ledger_checkpoint_anchor_status",
        ),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts.isoformat() if self.ts is not None else None,
            "from_seq": self.from_seq,
            "to_seq": self.to_seq,
            "merkle_root": self.merkle_root,
            "prev_checkpoint_root": self.prev_checkpoint_root,
            "anchor_status": self.anchor_status,
            "anchor_uri": self.anchor_uri,
        }
