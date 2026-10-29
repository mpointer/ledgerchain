from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from ledgerchain import (
    GENESIS_PREV_HASH,
    CanonicalizationError,
    LedgerWriter,
    compute_entry_hash,
    sha256_hex,
    verify_chain,
)
from ledgerchain.models import DecisionLedgerEntry, LedgerHead


def test_first_append_creates_genesis_then_the_requested_entry(db):
    entry = LedgerWriter.append(
        db,
        event_type="hitl.approval",
        payload={"claim_id": "c1"},
        actor={"kind": "human", "sub": "u1"},
        tenant_id="acme",
    )
    db.commit()

    genesis = db.get(DecisionLedgerEntry, 1)
    assert genesis.event_type == "genesis"
    assert genesis.prev_hash == GENESIS_PREV_HASH
    assert genesis.payload == {}

    assert entry.seq == 2
    assert entry.prev_hash == genesis.entry_hash
    assert entry.event_type == "hitl.approval"


def test_genesis_only_created_once(db):
    LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    db.commit()
    rows = db.execute(
        select(DecisionLedgerEntry).where(DecisionLedgerEntry.event_type == "genesis")
    ).all()
    assert len(rows) == 1


def test_genesis_event_type_is_reserved(db):
    with pytest.raises(ValueError, match="reserved"):
        LedgerWriter.append(db, event_type="genesis", payload={}, actor={}, tenant_id="acme")


def test_seq_is_global_not_per_tenant(db):
    e1 = LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    e2 = LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="globex")
    db.commit()
    assert e2.seq == e1.seq + 1
    assert e2.prev_hash == e1.entry_hash


def test_payload_sha256_is_canonical_json_hash(db):
    entry = LedgerWriter.append(
        db, event_type="e", payload={"b": 1, "a": 2}, actor={}, tenant_id="acme"
    )
    db.commit()
    assert entry.payload_sha256 == sha256_hex({"a": 2, "b": 1})


def test_entry_hash_matches_the_documented_formula(db):
    entry = LedgerWriter.append(db, event_type="e", payload={"x": 1}, actor={}, tenant_id="acme")
    db.commit()
    expected = compute_entry_hash(
        prev_hash=entry.prev_hash,
        payload_sha256=entry.payload_sha256,
        seq=entry.seq,
        event_type=entry.event_type,
        ts=entry.ts,
        tenant_id=entry.tenant_id,
    )
    assert entry.entry_hash == expected
    assert len(entry.entry_hash) == 64


def test_head_row_tracks_the_latest_entry(db):
    entry = LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    db.commit()
    head = db.execute(select(LedgerHead)).scalar_one()
    assert head.last_seq == entry.seq
    assert head.last_hash == entry.entry_hash


def test_writer_does_not_commit_rollback_leaves_nothing(db):
    LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    db.rollback()
    assert db.execute(select(DecisionLedgerEntry)).all() == []
    assert db.execute(select(LedgerHead)).all() == []


def test_unserializable_payload_fails_before_anything_is_written(db):
    LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    with pytest.raises(CanonicalizationError):
        LedgerWriter.append(db, event_type="e", payload={"s": {1, 2}}, actor={}, tenant_id="acme")
    db.rollback()
    assert db.execute(select(DecisionLedgerEntry)).all() == []


def test_non_mapping_payload_is_a_type_error(db):
    with pytest.raises(TypeError, match="mapping"):
        LedgerWriter.append(db, event_type="e", payload=[1, 2], actor={}, tenant_id="acme")


def test_unserializable_actor_fails_too(db):
    with pytest.raises(CanonicalizationError):
        LedgerWriter.append(db, event_type="e", payload={}, actor={"s": {1}}, tenant_id="acme")


def test_explicit_timestamp_is_used_and_must_be_aware(db):
    when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    entry = LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme", ts=when)
    db.commit()
    db.expire_all()
    assert db.get(DecisionLedgerEntry, entry.seq).ts == when

    with pytest.raises(ValueError, match="timezone-aware"):
        LedgerWriter.append(
            db, event_type="e", payload={}, actor={}, tenant_id="acme", ts=datetime(2026, 1, 1)
        )


def test_timestamps_round_trip_as_utc_aware(db):
    entry = LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    db.commit()
    db.expire_all()
    reloaded = db.get(DecisionLedgerEntry, entry.seq)
    assert reloaded.ts.tzinfo is not None
    assert verify_chain(db).valid


def test_to_dict_serializes_full_hashes(db):
    entry = LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    db.commit()
    d = entry.to_dict()
    assert len(d["entry_hash"]) == len(d["prev_hash"]) == len(d["payload_sha256"]) == 64
    assert d["seq"] == entry.seq


def test_verify_empty_ledger_is_valid(db):
    result = verify_chain(db)
    assert result.valid is True
    assert result.checked_entries == 0


def test_verify_clean_chain_and_partial_range(db):
    for i in range(5):
        LedgerWriter.append(db, event_type="e", payload={"i": i}, actor={}, tenant_id="acme")
    db.commit()

    result = verify_chain(db)
    assert result.valid and result.head_valid and result.first_bad_seq is None
    assert result.checked_entries == 6  # genesis + 5

    partial = verify_chain(db, from_seq=3, to_seq=4)
    assert partial.valid and partial.checked_entries == 2


def test_hash_format_is_frozen():
    # Changing either constant breaks every existing ledger: a new hash
    # layout needs a version marker, not an edit here.
    payload_sha256 = sha256_hex({"b": [1, 2.5, "é"], "a": None, "n": 1e21})
    assert payload_sha256 == "390eb6ae38e31c31c01ea28d3ddd84f97c2a2bdadb1147e9e3f6bc61e4f4e628"
    entry_hash = compute_entry_hash(
        prev_hash=GENESIS_PREV_HASH,
        payload_sha256=payload_sha256,
        seq=2,
        event_type="hitl.approval",
        ts=datetime(2026, 10, 18, 12, 0, 0, 123456, tzinfo=timezone.utc),
        tenant_id="acme",
    )
    assert entry_hash == "a78122020eff42b15708b45245a867c5edc628a6ead54f4e2cde64c4a82828b5"
