"""Every tamper case named in the design is detected with the right seq:
payload edit, row delete, reorder, forged head, broken anchor link."""

from __future__ import annotations

from conftest import seed

from ledgerchain import verify_chain
from ledgerchain.models import DecisionLedgerEntry, LedgerHead


def _update(db, target_seq, **values):
    db.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == target_seq)
        .values(**values)
    )
    db.commit()


def test_clean_chain_is_valid(db):
    seed(db)
    result = verify_chain(db)
    assert result.valid is True and result.first_bad_seq is None


def test_modified_payload_detected(db):
    entries = seed(db)
    target = entries[2]
    _update(db, target.seq, payload={"i": "HACKED"})

    result = verify_chain(db)
    assert result.valid is False
    assert result.first_bad_seq == target.seq
    assert "payload" in result.reason


def test_modified_event_type_detected(db):
    entries = seed(db)
    target = entries[1]
    _update(db, target.seq, event_type="hitl.rejection")

    result = verify_chain(db)
    assert result.valid is False
    assert result.first_bad_seq == target.seq
    assert "entry_hash" in result.reason


def test_modified_tenant_detected(db):
    entries = seed(db)
    target = entries[1]
    _update(db, target.seq, tenant_id="mallory")
    assert verify_chain(db).first_bad_seq == target.seq


def test_deleted_row_detected_at_the_following_seq(db):
    entries = seed(db)
    victim, survivor = entries[2], entries[3]
    db.execute(DecisionLedgerEntry.__table__.delete().where(DecisionLedgerEntry.seq == victim.seq))
    db.commit()

    result = verify_chain(db)
    assert result.valid is False
    assert result.first_bad_seq == survivor.seq
    assert "gap" in result.reason


def test_reordered_seq_detected(db):
    entries = seed(db)
    a_seq, b_seq = entries[2].seq, entries[3].seq
    db.expunge_all()  # work with raw rows from here; identities are about to move
    _update(db, a_seq, seq=9001)
    _update(db, b_seq, seq=a_seq)
    _update(db, 9001, seq=b_seq)

    result = verify_chain(db)
    assert result.valid is False
    assert result.first_bad_seq == a_seq


def test_forged_head_hash_detected_even_when_entries_are_untouched(db):
    seed(db)
    db.execute(LedgerHead.__table__.update().values(last_hash="f" * 64))
    db.commit()

    result = verify_chain(db)
    assert result.valid is False
    assert result.head_valid is False
    assert result.first_bad_seq is None
    assert "head" in result.reason.lower()


def test_forged_head_seq_detected(db):
    seed(db)
    db.execute(LedgerHead.__table__.update().values(last_seq=999))
    db.commit()
    result = verify_chain(db)
    assert result.valid is False and result.head_valid is False


def test_truncated_tail_detected_via_head(db):
    """Deleting the newest rows leaves a contiguous chain; only the head
    row knows entries are missing."""
    entries = seed(db)
    for e in entries[-2:]:
        db.execute(DecisionLedgerEntry.__table__.delete().where(DecisionLedgerEntry.seq == e.seq))
    db.commit()
    result = verify_chain(db)
    assert result.valid is False and result.head_valid is False


def test_partial_range_verify_catches_a_broken_link_at_the_anchor(db):
    entries = seed(db)
    _update(db, entries[0].seq, entry_hash="e" * 64)

    later = entries[1]
    result = verify_chain(db, from_seq=later.seq)
    assert result.valid is False
    assert result.first_bad_seq == later.seq
    assert "prev_hash" in result.reason


def test_partial_range_verify_fails_closed_when_anchor_is_missing(db):
    entries = seed(db)
    victim_seq = entries[2].seq
    db.execute(DecisionLedgerEntry.__table__.delete().where(DecisionLedgerEntry.seq == victim_seq))
    db.commit()

    result = verify_chain(db, from_seq=victim_seq + 1)
    assert result.valid is False
    assert result.checked_entries == 0
    assert "anchor" in result.reason
