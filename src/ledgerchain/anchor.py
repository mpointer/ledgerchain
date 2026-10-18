"""External anchoring of checkpoints to S3-compatible object storage.

The hash chain is already tamper-evident. Anchoring defeats a different
threat: a fully privileged database administrator rewriting the whole
chain and its checkpoints consistently. A checkpoint's Merkle root written
to a bucket under Object Lock is an independent witness that the live
database cannot alter.

Anchoring is eventually consistent by design. A storage outage marks the
checkpoint ``failed`` for retry and never blocks or fails the job that
built it.

Configuration comes from :class:`AnchorConfig`, either built explicitly or
read from the environment:

``LEDGER_ANCHOR_BUCKET``
    Target bucket. Anchoring is skipped, not failed, when unset.
``LEDGER_ANCHOR_PREFIX``
    Key prefix. Default ``ledger-checkpoints/``.
``LEDGER_ANCHOR_ENDPOINT_URL``
    S3-compatible endpoint (MinIO and friends). Unset uses AWS defaults.
``LEDGER_ANCHOR_OBJECT_LOCK_MODE``
    ``COMPLIANCE`` (default) or ``GOVERNANCE``. An empty string disables
    Object Lock, for buckets that do not have it enabled.

The S3 client is injectable. Anything with ``put_object(**kwargs)`` and
``get_object(Bucket=..., Key=...)`` works, which keeps the test suite free
of network access and credentials. ``boto3`` is only imported when no
client is supplied (install the ``s3`` extra).
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import LedgerCheckpoint

logger = logging.getLogger(__name__)

DEFAULT_PREFIX = "ledger-checkpoints/"
DEFAULT_RETAIN_UNTIL = datetime(2126, 1, 1, tzinfo=timezone.utc)
"""A fixed far-future retain-until date approximates "keep forever" without
depending on bucket-default retention being configured."""


class ObjectStore(Protocol):
    """The slice of the boto3 S3 client this module uses."""

    def put_object(self, **kwargs: Any) -> Any: ...

    def get_object(self, **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class AnchorConfig:
    bucket: str | None
    prefix: str = DEFAULT_PREFIX
    endpoint_url: str | None = None
    object_lock_mode: str | None = "COMPLIANCE"
    retain_until: datetime = DEFAULT_RETAIN_UNTIL

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> AnchorConfig:
        env = os.environ if environ is None else environ
        bucket = env.get("LEDGER_ANCHOR_BUCKET", "").strip() or None
        prefix = env.get("LEDGER_ANCHOR_PREFIX", DEFAULT_PREFIX)
        endpoint = env.get("LEDGER_ANCHOR_ENDPOINT_URL", "").strip() or None
        lock_mode = env.get("LEDGER_ANCHOR_OBJECT_LOCK_MODE", "COMPLIANCE").strip().upper() or None
        return cls(bucket=bucket, prefix=prefix, endpoint_url=endpoint, object_lock_mode=lock_mode)


@dataclass(frozen=True)
class AnchorResult:
    ok: bool
    anchor_uri: str | None = None
    error: str | None = None
    skipped: bool = False


@dataclass(frozen=True)
class AnchorVerifyResult:
    """Outcome of :func:`verify_anchor`.

    ``ok`` means the anchored copy was read and matches the checkpoint row.
    ``matched=False`` with ``ok=False`` means it was read and disagrees,
    which is the signal that the database copy was rewritten after the
    anchor was taken. ``error`` is set when the copy could not be read.
    """

    ok: bool
    matched: bool | None = None
    anchored: dict[str, Any] | None = None
    error: str | None = None


def anchor_payload(checkpoint: LedgerCheckpoint) -> dict[str, Any]:
    """``{from_seq, to_seq, merkle_root, ts, prev_checkpoint_root}``."""
    return {
        "from_seq": checkpoint.from_seq,
        "to_seq": checkpoint.to_seq,
        "merkle_root": checkpoint.merkle_root,
        "ts": checkpoint.ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "prev_checkpoint_root": checkpoint.prev_checkpoint_root,
    }


def anchor_key(config: AnchorConfig, checkpoint: LedgerCheckpoint) -> str:
    return f"{config.prefix}{checkpoint.from_seq:020d}-{checkpoint.to_seq:020d}.json"


def parse_anchor_uri(uri: str) -> tuple[str, str]:
    """Split ``s3://bucket/key`` into ``(bucket, key)``."""
    if not uri.startswith("s3://"):
        raise ValueError(f"not an s3:// URI: {uri!r}")
    rest = uri[len("s3://") :]
    bucket, sep, key = rest.partition("/")
    if not bucket or not sep or not key:
        raise ValueError(f"malformed s3:// URI: {uri!r}")
    return bucket, key


def default_client(config: AnchorConfig) -> ObjectStore:
    """A boto3 S3 client for ``config``. Requires the ``s3`` extra."""
    import boto3  # imported lazily so the base install has no AWS dependency

    client: ObjectStore = boto3.client("s3", endpoint_url=config.endpoint_url)
    return client


def anchor_checkpoint(
    session: Session,
    checkpoint: LedgerCheckpoint,
    *,
    config: AnchorConfig | None = None,
    client: ObjectStore | None = None,
) -> AnchorResult:
    """Write ``checkpoint``'s anchor payload to the configured bucket.

    Updates ``anchor_status`` and ``anchor_uri`` in place and commits.
    Never raises: any failure (bucket unset, credentials missing, network
    error, Object Lock rejected) is logged and recorded as
    ``anchor_status='failed'`` for a later retry.
    """
    cfg = config if config is not None else AnchorConfig.from_env()
    if cfg.bucket is None:
        return AnchorResult(ok=False, skipped=True, error="LEDGER_ANCHOR_BUCKET not configured")

    key = anchor_key(cfg, checkpoint)
    body = json.dumps(anchor_payload(checkpoint), sort_keys=True).encode("utf-8")
    put_kwargs: dict[str, Any] = {
        "Bucket": cfg.bucket,
        "Key": key,
        "Body": body,
        "ContentType": "application/json",
    }
    if cfg.object_lock_mode:
        put_kwargs["ObjectLockMode"] = cfg.object_lock_mode
        put_kwargs["ObjectLockRetainUntilDate"] = cfg.retain_until

    try:
        store = client if client is not None else default_client(cfg)
        store.put_object(**put_kwargs)
        anchor_uri = f"s3://{cfg.bucket}/{key}"
        checkpoint.anchor_uri = anchor_uri
        checkpoint.anchor_status = "anchored"
        session.commit()
        return AnchorResult(ok=True, anchor_uri=anchor_uri)
    except Exception as exc:  # noqa: BLE001 - anchoring is best-effort and retryable
        logger.error("checkpoint %s anchor failed: %s: %s", checkpoint.id, type(exc).__name__, exc)
        try:
            checkpoint.anchor_status = "failed"
            session.commit()
        except Exception:  # noqa: BLE001
            session.rollback()
        return AnchorResult(ok=False, error=f"{type(exc).__name__}: {exc}")


def retry_failed_anchors(
    session: Session,
    *,
    limit: int = 20,
    config: AnchorConfig | None = None,
    client: ObjectStore | None = None,
) -> list[AnchorResult]:
    """Retry every ``pending`` or ``failed`` checkpoint, oldest first.

    Run this from a periodic job so a transient storage outage self-heals
    without operator intervention.
    """
    rows = (
        session.execute(
            select(LedgerCheckpoint)
            .where(LedgerCheckpoint.anchor_status.in_(["pending", "failed"]))
            .order_by(LedgerCheckpoint.id.asc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [anchor_checkpoint(session, row, config=config, client=client) for row in rows]


def verify_anchor(
    checkpoint: LedgerCheckpoint,
    *,
    config: AnchorConfig | None = None,
    client: ObjectStore | None = None,
) -> AnchorVerifyResult:
    """Read the anchored copy of ``checkpoint`` and compare it to the row.

    This is the independent-witness check: the object in the bucket was
    written when the checkpoint was taken and cannot be changed under
    Object Lock, so a mismatch proves the database row was rewritten after
    anchoring. Never raises.
    """
    if checkpoint.anchor_uri is None:
        return AnchorVerifyResult(ok=False, error="checkpoint has no anchor_uri")
    cfg = config if config is not None else AnchorConfig.from_env()
    try:
        bucket, key = parse_anchor_uri(checkpoint.anchor_uri)
        store = client if client is not None else default_client(cfg)
        response = store.get_object(Bucket=bucket, Key=key)
        raw = response["Body"].read()
        anchored = json.loads(raw)
    except Exception as exc:  # noqa: BLE001 - report, never raise
        return AnchorVerifyResult(ok=False, error=f"{type(exc).__name__}: {exc}")

    matched = (
        anchored.get("from_seq") == checkpoint.from_seq
        and anchored.get("to_seq") == checkpoint.to_seq
        and anchored.get("merkle_root") == checkpoint.merkle_root
        and anchored.get("prev_checkpoint_root") == checkpoint.prev_checkpoint_root
    )
    return AnchorVerifyResult(ok=matched, matched=matched, anchored=anchored)
