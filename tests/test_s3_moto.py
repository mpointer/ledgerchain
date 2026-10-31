"""The anchoring code against the real boto3 client and moto's S3.

FakeS3 checks the logic; this checks the wire shapes it assumes: the 412
error from IfNoneMatch, Object Lock on a versioned bucket, version listing
and its pagination, delete markers, and default_client itself.
"""

from __future__ import annotations

import json

import pytest
from conftest import seed

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")

from ledgerchain import (  # noqa: E402
    AnchorConfig,
    anchor_checkpoint,
    build_checkpoint,
    create_all,
    verify_anchors,
)
from ledgerchain.anchor import anchor_key, anchor_versions  # noqa: E402
from ledgerchain.cli import main  # noqa: E402

BUCKET = "ledger-anchors"
CONFIG = AnchorConfig(bucket=BUCKET)  # COMPLIANCE lock, client from default_client


@pytest.fixture
def s3(monkeypatch):
    for name, value in {
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with moto.mock_aws():
        client = boto3.client("s3")
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        yield client


def _anchored(db, n=1):
    checkpoints = []
    for _ in range(n):
        seed(db, 2)
        cp = build_checkpoint(db).checkpoint
        assert anchor_checkpoint(db, cp, config=CONFIG).ok
        checkpoints.append(cp)
    return checkpoints


def test_anchor_is_write_once_and_idempotent(db, s3):
    (cp,) = _anchored(db)
    assert verify_anchors([cp], config=CONFIG)[0]

    # A lost status commit: the retry hits a real 412 and accepts the match.
    cp.anchor_status = "failed"
    db.commit()
    assert anchor_checkpoint(db, cp, config=CONFIG).ok

    # A forged checkpoint gets the same 412 and is refused.
    cp.merkle_root = "f" * 64
    db.commit()
    result = anchor_checkpoint(db, cp, config=CONFIG)
    assert result.ok is False and "already holds a different anchor" in result.error
    versions = s3.list_object_versions(Bucket=BUCKET, Prefix=CONFIG.prefix)["Versions"]
    assert len(versions) == 1


def test_shadowing_version_is_caught_against_the_original(db, s3):
    first, second = _anchored(db, 2)
    key = anchor_key(CONFIG, second)
    original = json.loads(s3.get_object(Bucket=BUCKET, Key=key)["Body"].read())
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(dict(original, merkle_root="f" * 64)))
    second.merkle_root = "f" * 64
    db.commit()

    ok, reports = verify_anchors([first, second], config=CONFIG)
    assert ok is False
    assert {
        "range": [second.from_seq, second.to_seq],
        "ok": False,
        "error": "anchor was overwritten or deleted after writing",
    } in reports
    row = next(r for r in reports if r.get("id") == second.id)
    assert row["matched"] is False


def test_delete_marker_hides_from_the_object_listing_but_not_from_verification(db, s3):
    (cp,) = _anchored(db)
    s3.delete_object(Bucket=BUCKET, Key=anchor_key(CONFIG, cp))
    cp.anchor_status = "pending"
    db.commit()

    assert "Contents" not in s3.list_objects_v2(Bucket=BUCKET, Prefix=CONFIG.prefix)
    ok, reports = verify_anchors([cp], config=CONFIG)
    assert ok is False
    assert any(r.get("error") == "anchor was overwritten or deleted after writing" for r in reports)


def test_version_listing_pages_past_one_thousand(s3):
    for i in range(1, 1006):
        s3.put_object(Bucket=BUCKET, Key=f"{CONFIG.prefix}{i:020d}-{i:020d}.json", Body=b"{}")
    s3.put_object(Bucket=BUCKET, Key=f"{CONFIG.prefix}notes.txt", Body=b"not an anchor")
    found = anchor_versions(CONFIG, s3)
    assert len(found) == 1005 and not any(v["rewritten"] for v in found.values())


def test_cli_check_anchors_end_to_end(tmp_path, s3, monkeypatch, capsys):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    url = f"sqlite:///{tmp_path / 'cli.db'}"
    engine = create_engine(url)
    create_all(engine)
    with sessionmaker(bind=engine)() as db:
        (cp,) = _anchored(db)
        key = anchor_key(CONFIG, cp)
    engine.dispose()
    monkeypatch.setenv("LEDGER_ANCHOR_BUCKET", BUCKET)

    assert main(["verify", "--database-url", url, "--check-anchors"]) == 0
    assert json.loads(capsys.readouterr().out)["anchors_valid"] is True

    s3.put_object(Bucket=BUCKET, Key=key, Body=b"{}")
    assert main(["verify", "--database-url", url, "--check-anchors"]) == 1
    assert json.loads(capsys.readouterr().out)["anchors_valid"] is False
