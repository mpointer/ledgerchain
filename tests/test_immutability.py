"""The append-only triggers block UPDATE and DELETE at the database layer,
and the verifier still catches a rewrite once a superuser removes them."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text

from ledgerchain import (
    LedgerWriter,
    create_all,
    drop_immutability,
    install_immutability,
    verify_chain,
)
from ledgerchain.models import DecisionLedgerEntry


def _append(session, payload):
    entry = LedgerWriter.append(
        session, event_type="hitl.approval", payload=payload, actor={}, tenant_id="acme"
    )
    session.commit()
    return entry


def test_create_all_makes_the_three_tables(immutable_db):
    names = {
        row[0]
        for row in immutable_db.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
    }
    assert {"decision_ledger", "ledger_head", "ledger_checkpoint"} <= names


def test_update_is_blocked_by_the_trigger(immutable_db):
    entry = _append(immutable_db, {"x": 1})
    with pytest.raises(Exception, match="append-only"):
        immutable_db.execute(
            DecisionLedgerEntry.__table__.update()
            .where(DecisionLedgerEntry.seq == entry.seq)
            .values(payload={"x": "HACKED"})
        )
        immutable_db.commit()
    immutable_db.rollback()
    assert immutable_db.get(DecisionLedgerEntry, entry.seq).payload == {"x": 1}


def test_delete_is_blocked_by_the_trigger(immutable_db):
    entry = _append(immutable_db, {"x": 1})
    with pytest.raises(Exception, match="append-only"):
        immutable_db.execute(
            DecisionLedgerEntry.__table__.delete().where(DecisionLedgerEntry.seq == entry.seq)
        )
        immutable_db.commit()
    immutable_db.rollback()
    assert immutable_db.get(DecisionLedgerEntry, entry.seq) is not None


def test_install_is_idempotent(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'x.db'}")
    create_all(engine)
    assert install_immutability(engine) is True
    assert install_immutability(engine) is True
    with engine.connect() as conn:
        triggers = {
            r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'"))
        }
    assert triggers == {"trg_decision_ledger_no_update", "trg_decision_ledger_no_delete"}


def test_drop_then_verify_still_catches_the_rewrite(immutable_db):
    """The Phase 0 exit demo: a superuser drops the triggers, edits a row,
    and verification still points at it."""
    for i in range(3):
        _append(immutable_db, {"i": i})
    assert verify_chain(immutable_db).valid is True

    assert drop_immutability(immutable_db.connection()) is True
    immutable_db.commit()

    immutable_db.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == 2)
        .values(payload={"i": "HACKED"})
    )
    immutable_db.commit()

    result = verify_chain(immutable_db)
    assert result.valid is False and result.first_bad_seq == 2


def test_unsupported_dialect_returns_false():
    class FakeDialect:
        name = "oracle"

    class FakeEngine:
        dialect = FakeDialect()

    assert install_immutability(FakeEngine()) is False  # type: ignore[arg-type]
    assert drop_immutability(FakeEngine()) is False  # type: ignore[arg-type]
