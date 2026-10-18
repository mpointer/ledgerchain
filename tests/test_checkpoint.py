from __future__ import annotations

import hashlib

import pytest
from conftest import make_checkpoint_row, seed

from ledgerchain import LedgerWriter, build_checkpoint, merkle_root, verify_chain
from ledgerchain import checkpoint as checkpoint_module
from ledgerchain.models import DecisionLedgerEntry, LedgerCheckpoint, LedgerHead


def _h(s: bytes) -> str:
    return hashlib.sha256(s).hexdigest()


def _pair(a: str, b: str) -> str:
    return hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()


def test_merkle_root_single_leaf_is_itself():
    leaf = _h(b"x")
    assert merkle_root([leaf]) == leaf


def test_merkle_root_two_leaves():
    a, b = _h(b"a"), _h(b"b")
    assert merkle_root([a, b]) == _pair(a, b)


def test_merkle_root_odd_count_promotes_last_node_unchanged():
    a, b, c = _h(b"a"), _h(b"b"), _h(b"c")
    assert merkle_root([a, b, c]) == _pair(_pair(a, b), c)


def test_merkle_root_four_leaves():
    a, b, c, d = (_h(x) for x in (b"a", b"b", b"c", b"d"))
    assert merkle_root([a, b, c, d]) == _pair(_pair(a, b), _pair(c, d))


def test_merkle_root_empty_raises():
    with pytest.raises(ValueError):
        merkle_root([])


def test_merkle_root_is_order_sensitive():
    a, b = _h(b"a"), _h(b"b")
    assert merkle_root([a, b]) != merkle_root([b, a])


def test_skips_on_empty_ledger(db):
    result = build_checkpoint(db)
    assert result.checkpoint is None and "empty" in result.skipped_reason


def test_builds_checkpoint_over_all_entries_since_genesis(db):
    seed(db, 2)
    cp = build_checkpoint(db).checkpoint
    assert cp is not None
    assert (cp.from_seq, cp.to_seq) == (1, 3)
    assert cp.prev_checkpoint_root is None
    assert cp.anchor_status == "pending"
    assert len(cp.merkle_root) == 64

    entry = db.query(DecisionLedgerEntry).filter_by(event_type="checkpoint").one()
    assert entry.payload["from_seq"] == 1
    assert entry.payload["to_seq"] == 3
    assert entry.payload["merkle_root"] == cp.merkle_root
    assert entry.subject_uri == f"ledger://checkpoints/{cp.id}"
    assert verify_chain(db).valid is True


def test_second_checkpoint_chains_via_prev_checkpoint_root(db):
    seed(db, 1)
    first = build_checkpoint(db).checkpoint
    LedgerWriter.append(db, event_type="e", payload={"a": 2}, actor={}, tenant_id="acme")
    db.commit()
    second = build_checkpoint(db).checkpoint

    assert second.from_seq == first.to_seq + 1
    assert second.prev_checkpoint_root == first.merkle_root
    assert second.merkle_root != first.merkle_root


def test_no_op_when_nothing_new_since_last_checkpoint(db):
    seed(db, 1)
    head = db.query(LedgerHead).one()
    make_checkpoint_row(db, from_seq=1, to_seq=head.last_seq, merkle_root="a" * 64)

    result = build_checkpoint(db)
    assert result.checkpoint is None and "nothing new" in result.skipped_reason
    assert db.query(LedgerCheckpoint).count() == 1


def test_commit_false_leaves_the_caller_in_control(db):
    seed(db, 1)
    result = build_checkpoint(db, commit=False)
    assert result.checkpoint is not None
    db.rollback()
    assert db.query(LedgerCheckpoint).count() == 0
    assert db.query(DecisionLedgerEntry).filter_by(event_type="checkpoint").count() == 0


def test_forced_ledger_append_failure_leaves_no_checkpoint_row(db, monkeypatch):
    seed(db, 1)

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated ledger append failure")

    monkeypatch.setattr(checkpoint_module.LedgerWriter, "append", staticmethod(_boom))
    with pytest.raises(RuntimeError):
        build_checkpoint(db)
    db.rollback()
    assert db.query(LedgerCheckpoint).count() == 0


def test_verify_chain_surfaces_and_validates_checkpoint(db):
    seed(db, 1)
    cp = build_checkpoint(db).checkpoint

    result = verify_chain(db)
    assert result.valid is True
    assert len(result.checkpoints) == 1
    summary = result.checkpoints[0]
    assert summary["id"] == cp.id
    assert summary["merkle_root"] == cp.merkle_root
    assert summary["anchor_status"] == "pending"
    assert summary["root_valid"] is True
    assert result.to_dict()["checkpoints_valid"] is True


def test_rewritten_checkpoint_root_is_detected(db):
    seed(db, 2)
    cp = build_checkpoint(db).checkpoint
    db.execute(
        LedgerCheckpoint.__table__.update()
        .where(LedgerCheckpoint.id == cp.id)
        .values(merkle_root="b" * 64)
    )
    db.commit()

    result = verify_chain(db)
    assert result.valid is False
    assert result.head_valid is True
    assert result.first_bad_seq is None
    assert result.checkpoints[0]["root_valid"] is False
    assert "checkpoint" in result.reason


def test_checkpoint_range_pointing_past_the_ledger_is_detected(db):
    seed(db, 2)
    make_checkpoint_row(db, from_seq=1, to_seq=50, merkle_root="c" * 64)
    result = verify_chain(db)
    assert result.valid is False
    assert result.checkpoints[0]["root_valid"] is False
    assert "exist" in result.checkpoints[0]["root_reason"]


def test_check_checkpoints_can_be_disabled(db):
    seed(db, 2)
    make_checkpoint_row(db, from_seq=1, to_seq=50, merkle_root="c" * 64)
    result = verify_chain(db, check_checkpoints=False)
    assert result.valid is True
    assert result.checkpoints == []
