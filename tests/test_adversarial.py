"""Attacks on the guarantees themselves, not just on single rows.

Each test is one attacker move against the verifier or the anchor witness.
``xfail(strict=True)`` marks a gap that is known and not yet closed: it
documents the attack today and fails loudly once the fix lands, so the
marker has to be removed.
"""

from __future__ import annotations

import json

import pytest
from conftest import FakeS3, seed
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ledgerchain.checkpoint as checkpoint_module
from ledgerchain import (
    AnchorConfig,
    LedgerWriter,
    anchor_checkpoint,
    build_checkpoint,
    create_all,
    verify_anchor,
    verify_chain,
)
from ledgerchain.anchor import anchor_key
from ledgerchain.cli import main
from ledgerchain.models import DecisionLedgerEntry, LedgerCheckpoint

CONFIG = AnchorConfig(bucket="real-bucket")


@pytest.fixture
def s3():
    return FakeS3()


@pytest.mark.xfail(strict=True, reason="actor and subject_uri are not in entry_hash yet")
def test_rewriting_actor_or_subject_is_detected(db):
    seed(db)
    db.execute(
        DecisionLedgerEntry.__table__.update()
        .where(DecisionLedgerEntry.seq == 2)
        .values(actor={"kind": "human", "sub": "mallory"}, subject_uri="/claims/other")
    )
    db.commit()
    assert verify_chain(db).valid is False


def test_repointing_anchor_uri_at_another_bucket_is_ignored(db, s3):
    seed(db)
    cp = build_checkpoint(db).checkpoint
    assert anchor_checkpoint(db, cp, config=CONFIG, client=s3).ok
    original = s3.stored_json("real-bucket", anchor_key(CONFIG, cp))

    forged = dict(original, merkle_root="f" * 64)
    s3.objects[("evil-bucket", "x.json")] = json.dumps(forged).encode()
    cp.merkle_root = "f" * 64
    cp.anchor_uri = "s3://evil-bucket/x.json"
    db.commit()

    report = verify_anchor(cp, config=CONFIG, client=s3)
    assert report.ok is False and report.matched is False
    assert report.anchored == original


def test_reanchoring_a_forged_checkpoint_cannot_shadow_the_original(db, s3):
    seed(db)
    cp = build_checkpoint(db).checkpoint
    assert anchor_checkpoint(db, cp, config=CONFIG, client=s3).ok
    original = s3.stored_json("real-bucket", anchor_key(CONFIG, cp))

    # Flip the status so `ledgerchain anchor` retries, then forge the root.
    cp.anchor_status = "failed"
    cp.merkle_root = "e" * 64
    db.commit()

    result = anchor_checkpoint(db, cp, config=CONFIG, client=s3)
    assert result.ok is False and "already holds a different anchor" in result.error
    assert cp.anchor_status == "failed"
    assert s3.stored_json("real-bucket", anchor_key(CONFIG, cp)) == original
    assert verify_anchor(cp, config=CONFIG, client=s3).matched is False


@pytest.mark.xfail(strict=True, reason="verify_chain does not check checkpoint chaining yet")
def test_breaking_prev_checkpoint_root_is_detected(db):
    seed(db)
    build_checkpoint(db)
    seed(db, 2)
    second = build_checkpoint(db).checkpoint
    second.prev_checkpoint_root = "d" * 64
    db.commit()
    assert verify_chain(db).valid is False


@pytest.mark.xfail(strict=True, reason="checkpoint rows are not cross-checked against the chain")
def test_deleting_checkpoint_rows_is_detected(db):
    seed(db)
    build_checkpoint(db)
    db.execute(LedgerCheckpoint.__table__.delete())
    db.commit()
    assert verify_chain(db).valid is False


def test_checkpoint_survives_an_append_committed_mid_build(tmp_path, monkeypatch):
    """A head row cached by build_checkpoint's unlocked read must not be reused
    after FOR UPDATE: that assigned an already-taken seq (IntegrityError)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'race.db'}")
    create_all(engine, immutable=False)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        seed(session, 2)

    real_merkle_root = checkpoint_module.merkle_root

    def append_concurrently(hashes):
        with Session() as other:
            LedgerWriter.append(other, event_type="e", payload={}, actor={}, tenant_id="acme")
            other.commit()
        return real_merkle_root(hashes)

    monkeypatch.setattr(checkpoint_module, "merkle_root", append_concurrently)
    with Session() as session:
        cp = build_checkpoint(session).checkpoint
        assert (cp.from_seq, cp.to_seq) == (1, 3)
    with Session() as session:
        assert verify_chain(session).valid
    engine.dispose()


class TestCliCheckAnchors:
    @pytest.fixture
    def url(self, tmp_path, s3, monkeypatch):
        monkeypatch.setenv("LEDGER_ANCHOR_BUCKET", "real-bucket")
        monkeypatch.setattr("ledgerchain.anchor.default_client", lambda cfg: s3)
        url = f"sqlite:///{tmp_path / 'cli.db'}"
        engine = create_engine(url)
        create_all(engine, immutable=False)
        engine.dispose()
        return url

    def _session(self, url):
        return sessionmaker(bind=create_engine(url))()

    def _verify(self, url, capsys):
        code = main(["verify", "--database-url", url, "--check-anchors"])
        return code, json.loads(capsys.readouterr().out)

    def test_flipping_anchor_status_does_not_skip_the_check(self, url, s3, capsys):
        session = self._session(url)
        seed(session)
        cp = build_checkpoint(session).checkpoint
        assert anchor_checkpoint(session, cp, config=CONFIG, client=s3).ok
        cp.anchor_status = "failed"
        cp.merkle_root = "f" * 64
        session.commit()
        session.close()

        code, body = self._verify(url, capsys)
        assert code == 1 and body["anchors_valid"] is False
        assert body["anchors"][0]["matched"] is False

    def test_not_yet_anchored_checkpoint_is_reported_not_failed(self, url, capsys):
        session = self._session(url)
        seed(session)
        build_checkpoint(session)
        session.close()

        code, body = self._verify(url, capsys)
        assert code == 0 and body["anchors_valid"] is True
        assert body["anchors"][0]["unanchored"] is True

    def test_anchored_checkpoint_with_missing_object_fails(self, url, s3, capsys):
        session = self._session(url)
        seed(session)
        cp = build_checkpoint(session).checkpoint
        assert anchor_checkpoint(session, cp, config=CONFIG, client=s3).ok
        session.close()
        s3.objects.clear()

        code, body = self._verify(url, capsys)
        assert code == 1 and body["anchors"][0]["unanchored"] is False
