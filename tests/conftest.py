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

    Behaves like a versioned (Object Lock) bucket: every put adds a version,
    ``get_object`` returns the latest unless ``VersionId`` is given, and
    ``delete_object`` adds a delete marker. Nothing is ever really removed.
    """

    def __init__(self, *, fail: bool = False):
        self.fail = fail
        # (bucket, key) -> [(version_id, body or None for a delete marker)]
        self.history: dict[tuple[str, str], list[tuple[str, bytes | None]]] = {}
        self.put_calls: list[dict] = []
        self._next_version = 0

    @property
    def objects(self) -> dict[tuple[str, str], bytes]:
        """Current (latest, not deleted) body per key, as a plain listing sees it."""
        return {k: v[-1][1] for k, v in self.history.items() if v[-1][1] is not None}

    def _add(self, key, body):
        self._next_version += 1
        self.history.setdefault(key, []).append((f"v{self._next_version}", body))

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        if self.fail:
            raise RuntimeError("simulated S3 outage")
        key = (kwargs["Bucket"], kwargs["Key"])
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise FakeClientError("PreconditionFailed")
        self._add(key, kwargs["Body"])
        return {"ETag": '"fake-etag"'}

    def delete_object(self, **kwargs):
        self._add((kwargs["Bucket"], kwargs["Key"]), None)

    def get_object(self, **kwargs):
        key = (kwargs["Bucket"], kwargs["Key"])
        versions = self.history.get(key, [])
        if "VersionId" in kwargs:
            body = dict(versions).get(kwargs["VersionId"])
        else:
            body = versions[-1][1] if versions else None
        if body is None:
            raise KeyError(f"NoSuchKey: {key}")
        return {"Body": FakeBody(body)}

    def list_object_versions(self, **kwargs):
        listing: dict[str, list] = {"Versions": [], "DeleteMarkers": []}
        for (bucket, key), versions in sorted(self.history.items()):
            if bucket != kwargs["Bucket"] or not key.startswith(kwargs["Prefix"]):
                continue
            # Like S3: newest first, and timestamps that tie (same second).
            for version_id, body in reversed(versions):
                kind = "Versions" if body is not None else "DeleteMarkers"
                listing[kind].append({"Key": key, "VersionId": version_id, "LastModified": 0})
        return {**listing, "IsTruncated": False}

    def stored_json(self, bucket: str, key: str) -> dict:
        return json.loads(self.objects[(bucket, key)])
