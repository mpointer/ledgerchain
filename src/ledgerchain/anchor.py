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

The S3 client is injectable. Anything with ``put_object(**kwargs)``,
``get_object(Bucket=..., Key=..., VersionId=...)`` and
``list_object_versions(**kwargs)`` works, which keeps the test suite free
of network access and credentials. ``boto3`` is only imported when no
client is supplied (install the ``s3`` extra).
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping, Sequence
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

    def list_object_versions(self, **kwargs: Any) -> Any: ...


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


_ANCHOR_NAME = re.compile(r"(\d{20})-(\d{20})\.json")


def anchor_versions(
    config: AnchorConfig, client: ObjectStore
) -> dict[tuple[int, int], dict[str, Any]]:
    """Every anchored ``(from_seq, to_seq)`` under ``config.prefix``, from the
    bucket's version listing.

    Each value holds ``version_id``, the oldest version and so the original
    witness, and ``rewritten``. ``rewritten`` is set when the key has more
    than one version or a delete marker. Anchors are written once, so either
    means someone with write access to the bucket overwrote or hid one;
    Object Lock keeps versions but does not stop either. Listing versions
    rather than objects also sees anchors hidden behind a delete marker.
    """
    found: dict[tuple[int, int], dict[str, Any]] = {}
    kwargs: dict[str, Any] = {"Bucket": config.bucket, "Prefix": config.prefix}
    while True:
        page = client.list_object_versions(**kwargs)
        items = [(v, False) for v in page.get("Versions", [])]
        items += [(m, True) for m in page.get("DeleteMarkers", [])]
        for item, is_marker in items:
            match = _ANCHOR_NAME.fullmatch(item["Key"][len(config.prefix) :])
            if not match:
                continue
            rec = found.setdefault(
                (int(match[1]), int(match[2])), {"versions": [], "marker": False}
            )
            if is_marker:
                rec["marker"] = True
            else:
                rec["versions"].append(item)
        if not page.get("IsTruncated"):
            break
        kwargs["KeyMarker"] = page.get("NextKeyMarker")
        kwargs["VersionIdMarker"] = page.get("NextVersionIdMarker")

    result: dict[tuple[int, int], dict[str, Any]] = {}
    for rng, rec in found.items():
        versions = sorted(rec["versions"], key=lambda v: v["LastModified"])
        result[rng] = {
            "version_id": versions[0]["VersionId"] if versions else None,
            "rewritten": rec["marker"] or len(versions) != 1,
        }
    return result


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
    commit: bool = True,
) -> AnchorResult:
    """Write ``checkpoint``'s anchor payload to the configured bucket.

    Updates ``anchor_status`` and ``anchor_uri`` in place. With
    ``commit=True`` (the default) that is committed along with anything else
    pending in ``session``. Pass ``commit=False`` to leave committing to
    the caller; nothing is rolled back then either.

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
    # Write-once. In a versioned (Object Lock) bucket a plain put would add a
    # newer version that get_object returns, letting a re-anchor of a forged
    # checkpoint shadow the original witness.
    put_kwargs["IfNoneMatch"] = "*"

    anchor_uri = f"s3://{cfg.bucket}/{key}"
    try:
        store = client if client is not None else default_client(cfg)
        try:
            store.put_object(**put_kwargs)
        except Exception as exc:
            if not _precondition_failed(exc):
                raise
            # The key already exists: a retry after a lost commit is fine,
            # anything else is a forged checkpoint or a shared prefix.
            existing = verify_anchor(checkpoint, config=cfg, client=store)
            if not existing.ok:
                raise RuntimeError(
                    f"{anchor_uri} already holds a different anchor for this range"
                ) from exc
        checkpoint.anchor_uri = anchor_uri
        checkpoint.anchor_status = "anchored"
        if commit:
            session.commit()
        return AnchorResult(ok=True, anchor_uri=anchor_uri)
    except Exception as exc:  # noqa: BLE001 - anchoring is best-effort and retryable
        logger.error("checkpoint %s anchor failed: %s: %s", checkpoint.id, type(exc).__name__, exc)
        checkpoint.anchor_status = "failed"
        if commit:
            try:
                session.commit()
            except Exception:  # noqa: BLE001
                session.rollback()
        return AnchorResult(ok=False, error=f"{type(exc).__name__}: {exc}")


def _precondition_failed(exc: Exception) -> bool:
    """S3's 412 answer to ``IfNoneMatch='*'``: the key already exists."""
    response = getattr(exc, "response", None) or {}
    return bool(response.get("Error", {}).get("Code") == "PreconditionFailed")


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
    version_id: str | None = None,
) -> AnchorVerifyResult:
    """Read the anchored copy of ``checkpoint`` and compare it to the row.

    Reads the latest version unless ``version_id`` names one;
    :func:`verify_anchors` passes the oldest, the original witness.

    This is the independent-witness check: the object in the bucket was
    written when the checkpoint was taken and cannot be changed under
    Object Lock, so a mismatch proves the database row was rewritten after
    anchoring. Never raises.

    The object is located from ``config`` (bucket and prefix) and the
    checkpoint's range, never from ``anchor_uri`` or ``anchor_status``:
    those live in the database this check exists to distrust. Verify with
    the same bucket and prefix the anchors were written with.
    """
    cfg = config if config is not None else AnchorConfig.from_env()
    if cfg.bucket is None:
        return AnchorVerifyResult(ok=False, error="LEDGER_ANCHOR_BUCKET not configured")
    try:
        store = client if client is not None else default_client(cfg)
        get_kwargs: dict[str, Any] = {"Bucket": cfg.bucket, "Key": anchor_key(cfg, checkpoint)}
        if version_id not in (None, "null"):  # "null" is an unversioned bucket's id
            get_kwargs["VersionId"] = version_id
        response = store.get_object(**get_kwargs)
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


def verify_anchors(
    checkpoints: Sequence[LedgerCheckpoint],
    *,
    from_seq: int = 1,
    to_seq: int | None = None,
    config: AnchorConfig | None = None,
    client: ObjectStore | None = None,
) -> tuple[bool, list[dict[str, Any]]]:
    """Cross-check checkpoint rows against what the bucket actually holds.

    Pass every checkpoint overlapping ``[from_seq, to_seq]``. Starts from
    the bucket listing, so rows cannot hide from the check:

    - an anchor with no checkpoint row of exactly its range fails: rows
      were deleted, merged, or re-ranged after anchoring;
    - a row whose original anchored copy (the oldest version) disagrees
      with it fails, and so does an anchor key that was overwritten or
      hidden behind a delete marker;
    - a row with no anchor is reported ``unanchored`` (not yet anchored),
      unless its ``anchor_status`` claims otherwise. The status column can
      only make this check stricter, never excuse a failure.

    A missing bucket or a listing error fails. Never raises.
    """
    cfg = config if config is not None else AnchorConfig.from_env()
    if cfg.bucket is None:
        return False, [{"ok": False, "error": "LEDGER_ANCHOR_BUCKET not configured"}]
    try:
        store = client if client is not None else default_client(cfg)
        versions = {
            r: v
            for r, v in anchor_versions(cfg, store).items()
            if r[1] >= from_seq and (to_seq is None or r[0] <= to_seq)
        }
    except Exception as exc:  # noqa: BLE001 - report, never raise
        return False, [{"ok": False, "error": f"cannot list anchors: {type(exc).__name__}: {exc}"}]

    rows = {(cp.from_seq, cp.to_seq) for cp in checkpoints}
    reports: list[dict[str, Any]] = [
        {"range": list(r), "ok": False, "error": "anchor has no checkpoint row with this range"}
        for r in sorted(set(versions) - rows)
    ]
    reports += [
        {"range": list(r), "ok": False, "error": "anchor was overwritten or deleted after writing"}
        for r, v in sorted(versions.items())
        if v["rewritten"]
    ]
    for cp in checkpoints:
        report: dict[str, Any] = {"id": cp.id, "range": [cp.from_seq, cp.to_seq]}
        witness = versions.get((cp.from_seq, cp.to_seq))
        if witness is not None and witness["version_id"] is None:
            report.update(ok=False, error="anchor has only a delete marker")
        elif witness is not None:
            result = verify_anchor(cp, config=cfg, client=store, version_id=witness["version_id"])
            report.update(ok=result.ok, matched=result.matched, error=result.error)
        elif cp.anchor_status == "anchored":
            report.update(ok=False, error="row claims anchored but the bucket has no anchor")
        else:
            report.update(ok=True, unanchored=True)
        reports.append(report)
    return all(r["ok"] for r in reports), reports
