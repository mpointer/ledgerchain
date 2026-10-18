from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ledgerchain import LedgerWriter, create_all
from ledgerchain.cli import main
from ledgerchain.models import DecisionLedgerEntry, LedgerCheckpoint


@pytest.fixture
def url(tmp_path):
    return f"sqlite:///{tmp_path / 'cli.db'}"


def _seed(url, n=3):
    engine = create_engine(url)
    create_all(engine, immutable=False)
    session = sessionmaker(bind=engine)()
    for i in range(n):
        LedgerWriter.append(session, event_type="e", payload={"i": i}, actor={}, tenant_id="acme")
    session.commit()
    session.close()
    engine.dispose()


def _out(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


def test_init_db_creates_tables_and_triggers(url, capsys):
    assert main(["init-db", "--database-url", url]) == 0
    assert _out(capsys) == {"ok": True, "triggers": True}

    engine = create_engine(url)
    session = sessionmaker(bind=engine)()
    LedgerWriter.append(session, event_type="e", payload={}, actor={}, tenant_id="t")
    session.commit()
    with pytest.raises(Exception, match="append-only"):
        session.execute(DecisionLedgerEntry.__table__.delete())
        session.commit()
    session.rollback()
    session.close()


def test_verify_exits_zero_on_a_clean_chain(url, capsys):
    _seed(url)
    assert main(["verify", "--database-url", url]) == 0
    body = _out(capsys)
    assert body["valid"] is True and body["checked_entries"] == 4


def test_verify_exits_nonzero_on_a_tampered_chain(url, capsys):
    _seed(url)
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            DecisionLedgerEntry.__table__.update()
            .where(DecisionLedgerEntry.seq == 2)
            .values(payload={"i": "HACKED"})
        )
    assert main(["verify", "--database-url", url]) == 1
    body = _out(capsys)
    assert body["valid"] is False and body["first_bad_seq"] == 2


def test_verify_accepts_a_range(url, capsys):
    _seed(url, n=5)
    assert main(["verify", "--database-url", url, "--from-seq", "2", "--to-seq", "3"]) == 0
    assert _out(capsys)["checked_entries"] == 2


def test_database_url_falls_back_to_env(url, monkeypatch, capsys):
    _seed(url)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("LEDGER_DATABASE_URL", url)
    assert main(["verify"]) == 0


def test_missing_database_url_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("LEDGER_DATABASE_URL", raising=False)
    with pytest.raises(SystemExit, match="no database URL"):
        main(["verify"])


def test_checkpoint_command_builds_and_reports(url, capsys):
    _seed(url)
    assert main(["checkpoint", "--database-url", url]) == 0
    body = _out(capsys)
    assert body["checkpoint"]["from_seq"] == 1 and body["checkpoint"]["to_seq"] == 4
    assert body["skipped_reason"] is None

    engine = create_engine(url)
    session = sessionmaker(bind=engine)()
    assert session.query(LedgerCheckpoint).count() == 1
    session.close()


def test_anchor_command_with_no_bucket_skips(url, monkeypatch, capsys):
    _seed(url)
    main(["checkpoint", "--database-url", url])
    capsys.readouterr()
    monkeypatch.delenv("LEDGER_ANCHOR_BUCKET", raising=False)
    assert main(["anchor", "--database-url", url]) == 0
    body = _out(capsys)
    assert body["attempted"] == 1 and body["results"][0]["skipped"] is True
