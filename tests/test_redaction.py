"""Redaction erases a payload for good while the chain, its checkpoints and
anchors keep verifying, and the erasure is itself on the record."""

from __future__ import annotations

import pytest
from conftest import seed
from sqlalchemy import JSON, create_engine
from test_hash_version import UPGRADE_SQL, _legacy_ledger

from ledgerchain import (
    REDACTION_EVENT_TYPE,
    LedgerWriter,
    build_checkpoint,
    install_immutability,
    verify_chain,
)
from ledgerchain.models import DecisionLedgerEntry

DPO = {"kind": "human", "sub": "dpo-1", "roles": ["privacy"]}


def _redact(db, seq, reason="GDPR art. 17 request #42"):
    record = LedgerWriter.redact(db, seq, actor=DPO, tenant_id="acme", reason=reason)
    db.commit()
    return record


def _raw_update(db, seq, **values):
    db.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == seq)
        .values(**values)
    )
    db.commit()


def test_redacted_payload_is_gone_and_the_chain_still_verifies(immutable_db):
    entries = seed(immutable_db)
    build_checkpoint(immutable_db)
    target = entries[1]
    record = _redact(immutable_db, target.seq)

    immutable_db.expire_all()
    row = immutable_db.get(DecisionLedgerEntry, target.seq)
    assert row.payload is None and row.payload_salt is None and row.to_dict()["redacted"]
    assert record.event_type == REDACTION_EVENT_TYPE and record.actor == DPO
    assert record.payload == {"seq": target.seq, "reason": "GDPR art. 17 request #42"}

    result = verify_chain(immutable_db)
    assert result.valid, result.reason
    assert result.redacted == [target.seq] and result.checkpoints[0]["root_valid"]


@pytest.mark.parametrize(
    "values",
    [
        {"payload": {"i": "rewritten"}},
        {"payload": JSON.NULL, "actor": {"sub": "someone-else"}},
        {"payload": JSON.NULL, "payload_sha256": "0" * 64},
        {"payload_salt": None},
    ],
    ids=["edit-payload", "redact-and-change-actor", "redact-and-change-hash", "strip-salt"],
)
def test_trigger_still_refuses_everything_but_a_redaction(immutable_db, values):
    seq = seed(immutable_db)[1].seq
    with pytest.raises(Exception, match="append-only"):
        _raw_update(immutable_db, seq, **values)
    immutable_db.rollback()


def test_nulling_a_payload_without_a_redaction_record_is_detected(immutable_db):
    """The trigger lets the app role null a payload; the verifier insists the
    erasure was recorded."""
    seq = seed(immutable_db)[1].seq
    _raw_update(immutable_db, seq, payload=JSON.NULL, payload_salt=None)
    result = verify_chain(immutable_db)
    assert result.valid is False and result.first_bad_seq == seq
    assert result.reason == "payload removed without a redaction entry"


def test_reserved_and_repeat_redactions_are_refused(db):
    seed(db)
    checkpoint_entry = build_checkpoint(db, tenant_id="acme").checkpoint.to_seq + 1
    record = _redact(db, 3)
    for seq in (1, checkpoint_entry, record.seq):  # genesis, checkpoint, redaction
        with pytest.raises(ValueError, match="cannot be redacted"):
            LedgerWriter.redact(db, seq, actor=DPO, tenant_id="acme", reason="x")
    with pytest.raises(ValueError, match="already redacted"):
        LedgerWriter.redact(db, 3, actor=DPO, tenant_id="acme", reason="again")
    with pytest.raises(LookupError):
        LedgerWriter.redact(db, 999, actor=DPO, tenant_id="acme", reason="x")


def test_redacted_checkpoint_entry_fails_verification_cleanly(db):
    seed(db)
    cp = build_checkpoint(db).checkpoint
    _raw_update(db, cp.to_seq + 1, payload=JSON.NULL, payload_salt=None)
    result = verify_chain(db)
    assert result.valid is False and result.first_bad_seq == cp.to_seq + 1


def test_stripping_the_salt_from_a_live_payload_is_detected(db):
    seq = seed(db)[1].seq
    _raw_update(db, seq, payload_salt=None)
    result = verify_chain(db)
    assert result.valid is False and result.first_bad_seq == seq


def test_legacy_v1_rows_can_be_redacted(tmp_path):
    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    _legacy_ledger(engine)
    with engine.begin() as conn:
        for stmt in UPGRADE_SQL:
            conn.execute(text(stmt))
    install_immutability(engine)
    with sessionmaker(bind=engine)() as session:
        _redact(session, 2)
        result = verify_chain(session)
        assert result.valid, result.reason
        assert result.redacted == [2]
    engine.dispose()


def test_redacting_another_tenants_entry_is_refused(db):
    LedgerWriter.append(db, event_type="e", payload={"pii": "x"}, actor={}, tenant_id="globex")
    db.commit()
    with pytest.raises(PermissionError, match="does not belong to tenant 'acme'"):
        LedgerWriter.redact(db, 2, actor=DPO, tenant_id="acme", reason="x")
    db.rollback()
    assert db.get(DecisionLedgerEntry, 2).payload == {"pii": "x"}


def test_a_redaction_record_from_another_tenant_does_not_count(db):
    from ledgerchain.writer import _append

    seq = seed(db)[1].seq  # tenant "acme"
    _raw_update(db, seq, payload=JSON.NULL, payload_salt=None)
    _append(
        db,
        event_type=REDACTION_EVENT_TYPE,
        payload={"seq": seq, "reason": "x"},
        actor=DPO,
        tenant_id="globex",
    )
    db.commit()
    result = verify_chain(db)
    assert result.valid is False and result.first_bad_seq == seq


def test_partial_range_finds_the_record_beyond_its_end(db):
    seq = seed(db)[1].seq
    record = _redact(db, seq)
    result = verify_chain(db, to_seq=record.seq - 1)
    assert result.valid, result.reason
    assert result.redacted == [seq]


def test_redact_rereads_a_row_another_session_already_redacted(tmp_path):
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(f"sqlite:///{tmp_path / 'r.db'}")
    from ledgerchain import create_all

    create_all(engine)
    Session = sessionmaker(bind=engine)
    with Session() as setup:
        seq = seed(setup)[1].seq
    stale = Session()
    cached = stale.get(DecisionLedgerEntry, seq)
    assert cached.payload is not None
    with Session() as other:
        _redact(other, seq)
    with pytest.raises(ValueError, match="already redacted"):
        LedgerWriter.redact(stale, seq, actor=DPO, tenant_id="acme", reason="again")
    stale.close()
    engine.dispose()
