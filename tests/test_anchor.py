from __future__ import annotations

import json
from datetime import timezone

import pytest
from conftest import FakeS3, make_checkpoint_row, seed

from ledgerchain import (
    AnchorConfig,
    AnchorResult,
    LedgerWriter,
    anchor_checkpoint,
    build_checkpoint,
    compute_entry_hash,
    merkle_root,
    retry_failed_anchors,
    sha256_hex,
    verify_anchor,
    verify_chain,
)
from ledgerchain.anchor import anchor_key, parse_anchor_uri
from ledgerchain.models import DecisionLedgerEntry


@pytest.fixture
def s3():
    return FakeS3()


@pytest.fixture
def config():
    return AnchorConfig(bucket="my-bucket", prefix="checkpoints/")


def test_from_env_reads_every_knob():
    cfg = AnchorConfig.from_env(
        {
            "LEDGER_ANCHOR_BUCKET": " b ",
            "LEDGER_ANCHOR_PREFIX": "p/",
            "LEDGER_ANCHOR_ENDPOINT_URL": "http://minio:9000",
            "LEDGER_ANCHOR_OBJECT_LOCK_MODE": "governance",
        }
    )
    assert cfg == AnchorConfig(
        bucket="b", prefix="p/", endpoint_url="http://minio:9000", object_lock_mode="GOVERNANCE"
    )


def test_from_env_defaults():
    cfg = AnchorConfig.from_env({})
    assert cfg.bucket is None
    assert cfg.prefix == "ledger-checkpoints/"
    assert cfg.object_lock_mode == "COMPLIANCE"


def test_from_env_empty_lock_mode_disables_object_lock():
    assert AnchorConfig.from_env({"LEDGER_ANCHOR_OBJECT_LOCK_MODE": ""}).object_lock_mode is None


def test_skips_when_bucket_not_configured(db, s3):
    cp = make_checkpoint_row(db)
    result = anchor_checkpoint(db, cp, config=AnchorConfig(bucket=None), client=s3)
    assert result == AnchorResult(
        ok=False, skipped=True, error="LEDGER_ANCHOR_BUCKET not configured"
    )
    assert s3.put_calls == [] and cp.anchor_status == "pending"


def test_successful_anchor_updates_status_and_uri(db, s3, config):
    cp = make_checkpoint_row(db, from_seq=1, to_seq=5, merkle_root="b" * 64)
    result = anchor_checkpoint(db, cp, config=config, client=s3)

    assert result.ok is True
    assert result.anchor_uri == f"s3://my-bucket/{anchor_key(config, cp)}"
    assert cp.anchor_status == "anchored" and cp.anchor_uri == result.anchor_uri

    put = s3.put_calls[0]
    assert put["Bucket"] == "my-bucket" and put["Key"].startswith("checkpoints/")
    payload = json.loads(put["Body"])
    assert payload == {
        "from_seq": 1,
        "to_seq": 5,
        "merkle_root": "b" * 64,
        "prev_checkpoint_root": None,
        "ts": cp.ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def test_object_lock_on_by_default_and_off_when_disabled(db, s3):
    cp = make_checkpoint_row(db)
    anchor_checkpoint(db, cp, config=AnchorConfig(bucket="b"), client=s3)
    assert s3.put_calls[-1]["ObjectLockMode"] == "COMPLIANCE"
    assert "ObjectLockRetainUntilDate" in s3.put_calls[-1]

    cp2 = make_checkpoint_row(db, from_seq=6, to_seq=7)
    anchor_checkpoint(db, cp2, config=AnchorConfig(bucket="b", object_lock_mode=None), client=s3)
    assert "ObjectLockMode" not in s3.put_calls[-1]


def test_storage_failure_sets_status_failed_and_never_raises(db, config):
    cp = make_checkpoint_row(db)
    result = anchor_checkpoint(db, cp, config=config, client=FakeS3(fail=True))
    assert result.ok is False and "simulated S3 outage" in result.error
    assert cp.anchor_status == "failed" and cp.anchor_uri is None


def test_retry_picks_up_pending_and_failed_only(db, s3, config):
    pending = make_checkpoint_row(db, from_seq=1, to_seq=1, anchor_status="pending")
    failed = make_checkpoint_row(db, from_seq=2, to_seq=2, anchor_status="failed")
    make_checkpoint_row(db, from_seq=3, to_seq=3, anchor_status="anchored")

    results = retry_failed_anchors(db, config=config, client=s3)
    assert len(results) == 2 and all(r.ok for r in results)
    db.refresh(pending)
    db.refresh(failed)
    assert pending.anchor_status == failed.anchor_status == "anchored"


def test_retry_recovers_after_transient_failure(db, config):
    cp = make_checkpoint_row(db)
    anchor_checkpoint(db, cp, config=config, client=FakeS3(fail=True))
    assert cp.anchor_status == "failed"

    results = retry_failed_anchors(db, config=config, client=FakeS3())
    assert len(results) == 1 and results[0].ok
    db.refresh(cp)
    assert cp.anchor_status == "anchored"


def test_parse_anchor_uri():
    assert parse_anchor_uri("s3://bucket/a/b.json") == ("bucket", "a/b.json")
    for bad in ("http://x/y", "s3://", "s3://bucket", "s3://bucket/"):
        with pytest.raises(ValueError):
            parse_anchor_uri(bad)


def test_verify_anchor_round_trip(db, s3, config):
    seed(db, 2)
    cp = build_checkpoint(db).checkpoint
    anchor_checkpoint(db, cp, config=config, client=s3)

    report = verify_anchor(cp, config=config, client=s3)
    assert report.ok and report.matched is True
    assert report.anchored["merkle_root"] == cp.merkle_root


def test_verify_anchor_without_uri_or_object_reports_error(db, s3, config):
    cp = make_checkpoint_row(db)
    assert verify_anchor(cp, config=config, client=s3).error == "checkpoint has no anchor_uri"

    cp.anchor_uri = "s3://my-bucket/missing.json"
    report = verify_anchor(cp, config=config, client=s3)
    assert report.ok is False and report.matched is None and "NoSuchKey" in report.error


def test_anchored_root_proves_a_later_rewrite_postdated_it(db, s3, config):
    """The exit demo, end to end, with the bucket as an independent witness.

    1. clean chain verifies
    2. checkpoint and anchor it; the root lands in the fake bucket
    3. a superuser edits a payload (no trigger in this fixture)
    4. verify_chain fails at that seq
    5. a consistent rewrite of the checkpoint row (root recomputed from the
       tampered payloads) fools verify_chain's local root check but not
       verify_anchor, because the anchored copy did not change
    """
    seed(db, 2)
    assert verify_chain(db).valid

    cp = build_checkpoint(db).checkpoint
    assert anchor_checkpoint(db, cp, config=config, client=s3).ok
    anchored_root = s3.stored_json("my-bucket", anchor_key(config, cp))["merkle_root"]
    assert anchored_root == cp.merkle_root

    target_seq = cp.from_seq + 1
    db.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == target_seq)
        .values(payload={"i": "TAMPERED"})
    )
    db.commit()

    result = verify_chain(db)
    assert result.valid is False and result.first_bad_seq == target_seq

    # A DBA rewriting consistently would recompute every hash from the
    # tampered payloads and store the matching checkpoint root.
    rows = (
        db.query(DecisionLedgerEntry)
        .filter(DecisionLedgerEntry.seq >= cp.from_seq, DecisionLedgerEntry.seq <= cp.to_seq)
        .order_by(DecisionLedgerEntry.seq)
        .all()
    )
    rewritten = [
        compute_entry_hash(
            prev_hash=e.prev_hash,
            payload_sha256=sha256_hex(e.payload),
            seq=e.seq,
            event_type=e.event_type,
            ts=e.ts,
            tenant_id=e.tenant_id,
        )
        for e in rows
    ]
    rewritten_root = merkle_root(rewritten)
    assert rewritten_root != anchored_root
    cp.merkle_root = rewritten_root
    db.commit()

    report = verify_anchor(cp, config=config, client=s3)
    assert report.ok is False and report.matched is False
    assert report.anchored["merkle_root"] == anchored_root


def test_verify_anchor_uses_prev_checkpoint_root(db, s3, config):
    seed(db, 1)
    first = build_checkpoint(db).checkpoint
    anchor_checkpoint(db, first, config=config, client=s3)
    LedgerWriter.append(db, event_type="e", payload={}, actor={}, tenant_id="acme")
    db.commit()
    second = build_checkpoint(db).checkpoint
    anchor_checkpoint(db, second, config=config, client=s3)
    assert verify_anchor(second, config=config, client=s3).ok

    second.prev_checkpoint_root = "0" * 64
    db.commit()
    assert verify_anchor(second, config=config, client=s3).matched is False
