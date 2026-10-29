from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from ledgerchain import LedgerWriter, create_all, metadata
from ledgerchain.models import LedgerCheckpoint


@pytest.fixture
def db() -> Iterator[Session]:
    """In-memory SQLite with tables only (no triggers), so tamper tests can
    mutate rows through the ORM and exercise the verifier alone."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def immutable_db(tmp_path) -> Iterator[Session]:
    """File-backed SQLite with the append-only triggers installed."""
    engine = create_engine(
        f"sqlite:///{tmp_path / 'immutable.db'}", connect_args={"check_same_thread": False}
    )
    create_all(engine, immutable=True)
    session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def seed(db: Session, n: int = 5, *, event_type: str = "hitl.approval") -> list:
    """Genesis (seq=1) plus n ordinary entries (seq=2..n+1)."""
    entries = []
    for i in range(n):
        entries.append(
            LedgerWriter.append(
                db,
                event_type=event_type,
                payload={"i": i},
                actor={"kind": "human", "sub": "u"},
                tenant_id="acme",
                subject_uri=f"/claims/c{i}",
            )
        )
    db.commit()
    return entries


def make_checkpoint_row(db: Session, **overrides) -> LedgerCheckpoint:
    defaults = dict(from_seq=1, to_seq=5, merkle_root="a" * 64, anchor_status="pending")
    defaults.update(overrides)
    cp = LedgerCheckpoint(**defaults)
    db.add(cp)
    db.commit()
    return cp


class FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data


class FakeClientError(Exception):
    """Shaped like botocore's ClientError: the code lives in ``.response``."""

    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """In-memory stand-in for the boto3 S3 client slice ledgerchain uses.

    Without ``IfNoneMatch`` a put replaces the object, which is what a
    versioned bucket's ``get_object`` sees: the newest version wins.
    """

    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.objects: dict[tuple[str, str], bytes] = {}
        self.put_calls: list[dict] = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        if self.fail:
            raise RuntimeError("simulated S3 outage")
        key = (kwargs["Bucket"], kwargs["Key"])
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise FakeClientError("PreconditionFailed")
        self.objects[key] = kwargs["Body"]
        return {"ETag": '"fake-etag"'}

    def get_object(self, **kwargs):
        key = (kwargs["Bucket"], kwargs["Key"])
        if key not in self.objects:
            raise KeyError(f"NoSuchKey: {key}")
        return {"Body": FakeBody(self.objects[key])}

    def list_objects_v2(self, **kwargs):
        keys = sorted(
            k for b, k in self.objects if b == kwargs["Bucket"] and k.startswith(kwargs["Prefix"])
        )
        return {"Contents": [{"Key": k} for k in keys], "IsTruncated": False}

    def stored_json(self, bucket: str, key: str) -> dict:
        return json.loads(self.objects[(bucket, key)])
