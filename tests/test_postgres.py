"""PostgreSQL run of the core guarantees: JSONB columns, FOR UPDATE on the
head row, the plpgsql immutability trigger, and the verifier after a
superuser drops it.

Skipped unless ``LEDGERCHAIN_TEST_DATABASE_URL`` points at a database the
test may create and drop tables in. CI provides one.
"""

from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ledgerchain import (
    LedgerWriter,
    build_checkpoint,
    create_all,
    drop_immutability,
    metadata,
    verify_chain,
)
from ledgerchain.models import DecisionLedgerEntry

_URL = os.environ.get("LEDGERCHAIN_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(not _URL, reason="LEDGERCHAIN_TEST_DATABASE_URL not set")


@pytest.fixture
def pg():
    assert _URL is not None
    # Each test gets its own schema so runs never collide.
    schema = f"lc_{uuid.uuid4().hex[:8]}"
    admin = create_engine(_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        _URL, connect_args={"options": f"-csearch_path={schema}"}, pool_pre_ping=True
    )
    create_all(engine, immutable=True)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _append(session, payload):
    entry = LedgerWriter.append(
        session, event_type="hitl.approval", payload=payload, actor={"kind": "human"}, tenant_id="t"
    )
    session.commit()
    return entry


def test_tables_exist_with_jsonb(pg):
    assert set(metadata.tables) == {"decision_ledger", "ledger_head", "ledger_checkpoint"}
    row = pg.execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name = 'decision_ledger' AND column_name = 'payload'"
        )
    ).scalar_one()
    assert row == "jsonb"


def test_append_verify_and_checkpoint(pg):
    for i in range(3):
        _append(pg, {"i": i, "nested": {"b": [1, 2.5, "x"], "a": None}})
    assert verify_chain(pg).valid is True
    cp = build_checkpoint(pg).checkpoint
    assert cp is not None and cp.to_seq == 4
    result = verify_chain(pg)
    assert result.valid and result.checkpoints[0]["root_valid"] is True


def test_trigger_blocks_update_and_delete(pg):
    entry = _append(pg, {"x": 1})
    with pytest.raises(Exception, match="append-only"):
        pg.execute(
            DecisionLedgerEntry.__table__.update()
            .where(DecisionLedgerEntry.seq == entry.seq)
            .values(payload={"x": 2})
        )
        pg.commit()
    pg.rollback()
    with pytest.raises(Exception, match="append-only"):
        pg.execute(
            DecisionLedgerEntry.__table__.delete().where(DecisionLedgerEntry.seq == entry.seq)
        )
        pg.commit()
    pg.rollback()
    assert pg.get(DecisionLedgerEntry, entry.seq).payload == {"x": 1}


def test_superuser_rewrite_after_dropping_trigger_is_detected(pg):
    for i in range(3):
        _append(pg, {"i": i})
    assert drop_immutability(pg.connection()) is True
    pg.commit()
    pg.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == 2)
        .values(payload={"i": "HACKED"})
    )
    pg.commit()
    result = verify_chain(pg)
    assert result.valid is False and result.first_bad_seq == 2
