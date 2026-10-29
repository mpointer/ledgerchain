"""``ledgerchain`` command line.

Built for auditors and operators, not for the application: every
subcommand opens its own engine from ``--database-url`` (or
``LEDGER_DATABASE_URL``, then ``DATABASE_URL``), does one thing, prints
JSON, and exits non-zero on a failed verification so it composes in
scripts and CI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .anchor import AnchorConfig, anchor_checkpoint, retry_failed_anchors, verify_anchors
from .checkpoint import build_checkpoint
from .immutability import create_all
from .models import LedgerCheckpoint
from .verify import verify_chain


def resolve_database_url(explicit: str | None) -> str:
    url = explicit or os.environ.get("LEDGER_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not url:
        raise SystemExit(
            "no database URL: pass --database-url or set LEDGER_DATABASE_URL / DATABASE_URL"
        )
    return url


def _session(url: str) -> tuple[Any, Session]:
    engine = create_engine(url)
    return engine, sessionmaker(bind=engine)()


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, default=str))


def cmd_init_db(args: argparse.Namespace) -> int:
    engine = create_engine(resolve_database_url(args.database_url))
    try:
        create_all(engine, immutable=not args.no_triggers)
    finally:
        engine.dispose()
    _emit({"ok": True, "triggers": not args.no_triggers})
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    engine, session = _session(resolve_database_url(args.database_url))
    try:
        result = verify_chain(session, from_seq=args.from_seq, to_seq=args.to_seq)
        body = result.to_dict()
        anchors_ok = True
        if args.check_anchors:
            rows = [session.get(LedgerCheckpoint, s["id"]) for s in result.checkpoints]
            anchors_ok, anchor_reports = verify_anchors(
                [cp for cp in rows if cp is not None],
                from_seq=args.from_seq or 1,
                to_seq=args.to_seq,
                config=AnchorConfig.from_env(),
            )
            body["anchors"] = anchor_reports
            body["anchors_valid"] = anchors_ok
    finally:
        session.close()
        engine.dispose()
    _emit(body)
    return 0 if result.valid and anchors_ok else 1


def cmd_checkpoint(args: argparse.Namespace) -> int:
    engine, session = _session(resolve_database_url(args.database_url))
    try:
        result = build_checkpoint(session, tenant_id=args.tenant_id)
        body: dict[str, Any] = {
            "checkpoint": result.checkpoint.to_dict() if result.checkpoint else None,
            "skipped_reason": result.skipped_reason,
        }
        if args.anchor and result.checkpoint is not None:
            anchored = anchor_checkpoint(session, result.checkpoint, config=AnchorConfig.from_env())
            body["anchor"] = anchored.__dict__
    finally:
        session.close()
        engine.dispose()
    _emit(body)
    # Asking for --anchor and not getting one (failed or unconfigured) is a failure.
    return 0 if "anchor" not in body or body["anchor"]["ok"] else 1


def cmd_anchor(args: argparse.Namespace) -> int:
    engine, session = _session(resolve_database_url(args.database_url))
    try:
        results = retry_failed_anchors(session, limit=args.limit, config=AnchorConfig.from_env())
    finally:
        session.close()
        engine.dispose()
    _emit({"attempted": len(results), "results": [r.__dict__ for r in results]})
    return 0 if all(r.ok or r.skipped for r in results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ledgerchain", description="Tamper-evident decision ledger tools."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_db(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--database-url",
            default=None,
            help="SQLAlchemy URL. Overrides LEDGER_DATABASE_URL and DATABASE_URL.",
        )

    p = sub.add_parser("init-db", help="Create the ledger tables and immutability triggers.")
    add_db(p)
    p.add_argument("--no-triggers", action="store_true", help="Create tables only.")
    p.set_defaults(func=cmd_init_db)

    p = sub.add_parser("verify", help="Recompute the chain and report the first bad seq.")
    add_db(p)
    p.add_argument("--from-seq", type=int, default=None)
    p.add_argument("--to-seq", type=int, default=None)
    p.add_argument(
        "--check-anchors",
        action="store_true",
        help="Also read each anchored checkpoint back from object storage and compare.",
    )
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("checkpoint", help="Build a Merkle checkpoint over new entries.")
    add_db(p)
    p.add_argument("--tenant-id", default="default")
    p.add_argument("--anchor", action="store_true", help="Anchor it immediately.")
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("anchor", help="Retry pending and failed anchors.")
    add_db(p)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_anchor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code: int = args.func(args)
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
