"""Hash layout versions: v1 rows from 0.1/0.2 keep verifying after the
upgrade, new rows are v2, and a row can never be walked back to v1."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from conftest import seed
from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.orm import sessionmaker

from ledgerchain import (
    GENESIS_PREV_HASH,
    LedgerWriter,
    compute_entry_hash,
    create_all,
    install_immutability,
    sha256_hex,
    verify_chain,
)
from ledgerchain.models import DecisionLedgerEntry, JSONType, LedgerHead, UTCDateTime

UPGRADE_SQL = [
    "ALTER TABLE decision_ledger ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1",
    "ALTER TABLE decision_ledger ADD COLUMN payload_salt CHAR(64)",
]
"""The documented upgrade from 0.2.x (see CHANGELOG), before re-running
install_immutability."""

_LEGACY_TRIGGERS = {
    # 0.2.x's unconditional append-only triggers, which reference no new column.
    "postgresql": [
        "CREATE OR REPLACE FUNCTION decision_ledger_immutable() RETURNS trigger AS $$"
        " BEGIN RAISE EXCEPTION 'decision_ledger is append-only'; END; $$ LANGUAGE plpgsql",
        "CREATE TRIGGER trg_decision_ledger_no_update BEFORE UPDATE ON decision_ledger"
        " FOR EACH ROW EXECUTE FUNCTION decision_ledger_immutable()",
    ],
    "sqlite": [
        "CREATE TRIGGER trg_decision_ledger_no_update BEFORE UPDATE ON decision_ledger"
        " BEGIN SELECT RAISE(ABORT, 'decision_ledger is append-only'); END",
    ],
}

_PG_URL = os.environ.get("LEDGERCHAIN_TEST_DATABASE_URL")

_INSERT_V1 = text(
    "INSERT INTO decision_ledger (seq, tenant_id, ts, event_type, actor, subject_uri,"
    " payload, payload_sha256, prev_hash, entry_hash) VALUES (:seq, :tenant_id, :ts,"
    " :event_type, :actor, :subject_uri, :payload, :payload_sha256, :prev_hash, :entry_hash)"
).bindparams(
    bindparam("actor", type_=JSONType),
    bindparam("payload", type_=JSONType),
    bindparam("ts", type_=UTCDateTime(timezone=True)),
)


def _legacy_ledger(engine, n=3):
    """A 0.2.x-shaped ledger: no hash_version or payload_salt column, v1
    hashes, and 0.2.x's append-only trigger on."""
    create_all(engine, immutable=False)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE decision_ledger DROP COLUMN hash_version"))
        conn.execute(text("ALTER TABLE decision_ledger DROP COLUMN payload_salt"))
        for stmt in _LEGACY_TRIGGERS[engine.dialect.name]:
            conn.execute(text(stmt))
        prev = GENESIS_PREV_HASH
        for seq in range(1, n + 1):
            row = {
                "seq": seq,
                "tenant_id": "acme",
                "ts": datetime(2026, 10, 1, 12, 0, seq, tzinfo=timezone.utc),
                "event_type": "genesis" if seq == 1 else "hitl.approval",
                "actor": {"kind": "human", "sub": "alice"},
                "subject_uri": None if seq == 1 else f"/claims/{seq}",
                "payload": {} if seq == 1 else {"i": seq},
                "prev_hash": prev,
            }
            row["payload_sha256"] = sha256_hex(row["payload"])
            row["entry_hash"] = compute_entry_hash(
                prev_hash=prev,
                payload_sha256=row["payload_sha256"],
                seq=seq,
                event_type=row["event_type"],
                ts=row["ts"],
                tenant_id="acme",
            )
            conn.execute(_INSERT_V1, row)
            prev = row["entry_hash"]
        conn.execute(LedgerHead.__table__.insert().values(id=True, last_seq=n, last_hash=prev))


def _upgrade_then_append_and_verify(engine):
    _legacy_ledger(engine)
    with engine.begin() as conn:  # the ALTERs must not trip the legacy row trigger
        for stmt in UPGRADE_SQL:
            conn.execute(text(stmt))
    install_immutability(engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        assert verify_chain(session).valid
        LedgerWriter.append(
            session, event_type="hitl.approval", payload={"i": 4}, actor={}, tenant_id="acme"
        )
        session.commit()
        result = verify_chain(session)
        assert result.valid, result.reason
        versions = [e.hash_version for e in session.query(DecisionLedgerEntry).order_by("seq")]
        assert versions == [1, 1, 1, 2]


def test_upgrading_a_v1_ledger_keeps_it_valid_sqlite(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    _upgrade_then_append_and_verify(engine)
    engine.dispose()


@pytest.mark.skipif(not _PG_URL, reason="LEDGERCHAIN_TEST_DATABASE_URL not set")
def test_upgrading_a_v1_ledger_keeps_it_valid_postgres():
    # The ALTER must not trip the BEFORE UPDATE trigger on existing rows.
    schema = f"lc_{uuid.uuid4().hex[:8]}"
    admin = create_engine(_PG_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(_PG_URL, connect_args={"options": f"-csearch_path={schema}"})
    try:
        _upgrade_then_append_and_verify(engine)
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def _rewrite_last_entry_as(db, version):
    last = db.query(DecisionLedgerEntry).order_by(DecisionLedgerEntry.seq.desc()).first()
    new_hash = compute_entry_hash(
        prev_hash=last.prev_hash,
        payload_sha256=last.payload_sha256,
        seq=last.seq,
        event_type=last.event_type,
        ts=last.ts,
        tenant_id=last.tenant_id,
        actor=last.actor,
        subject_uri=last.subject_uri,
        hash_version=min(version, 2),
    )
    db.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == last.seq)
        .values(hash_version=version, entry_hash=new_hash)
    )
    db.execute(LedgerHead.__table__.update().values(last_hash=new_hash))
    db.commit()
    return last.seq


def test_rewriting_a_v2_row_as_v1_is_detected(db):
    """With a consistent v1 rehash (head updated too) the actor would be
    unprotected again; the version may only move forward along the chain."""
    seed(db)
    seq = _rewrite_last_entry_as(db, 1)
    result = verify_chain(db)
    assert result.valid is False and result.first_bad_seq == seq
    assert "hash_version" in result.reason


def test_unknown_hash_version_is_invalid(db):
    seed(db)
    seq = _rewrite_last_entry_as(db, 3)
    result = verify_chain(db)
    assert result.valid is False and result.first_bad_seq == seq


def test_partial_range_inherits_the_version_floor(db):
    seed(db)
    seq = _rewrite_last_entry_as(db, 1)
    assert verify_chain(db, from_seq=seq).valid is False


def test_v1_lets_fields_shift_and_v2_does_not():
    ts = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    other_ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ts_text, other_text = "2026-10-18T12:00:00Z", "2026-01-01T00:00:00Z"
    common = dict(prev_hash="0" * 64, payload_sha256="1" * 64, seq=2)
    honest = dict(event_type=f"a\n{other_text}", ts=ts, tenant_id="t")
    shifted = dict(event_type="a", ts=other_ts, tenant_id=f"{ts_text}\nt")

    v1 = [compute_entry_hash(**common, **f) for f in (honest, shifted)]
    assert v1[0] == v1[1]
    v2 = [compute_entry_hash(**common, **f, actor={}, hash_version=2) for f in (honest, shifted)]
    assert v2[0] != v2[1]
