# ledgerchain

A hash-chained, tamper-evident decision ledger on SQLAlchemy. Append-only
rows, a verifier that recomputes everything, Merkle checkpoints, and
external anchoring to object storage as an independent witness.

Built for one job: recording the determinations an AI-assisted system makes,
and the human approvals, verdicts, and corrections around them, in a form an
auditor can check without trusting the application. Extracted from a
production decision-integrity platform where this code records HITL
approvals, signed attestations, guardrail verdicts, and correction
dispatches.

No blockchain, no ledger database, no sidecar. Three tables in the
PostgreSQL or SQLite you already run, and about 1,300 lines of Python you
can read in an afternoon.

```
pip install ledgerchain          # core: sqlalchemy + rfc8785
pip install "ledgerchain[s3]"    # adds boto3 for checkpoint anchoring
```

The short background on why this exists and what it deliberately does not
do is in [docs/why-ledgerchain.md](docs/why-ledgerchain.md).

## What it guarantees

| Threat | Mechanism | Detected by |
|---|---|---|
| A payload is edited in place | `payload_sha256` over RFC 8785 canonical JSON | `verify_chain` names the seq |
| A row is deleted or reordered | strictly contiguous `seq`, each `entry_hash` includes `str(seq)` | `verify_chain` names the seq after the gap |
| The head pointer is forged | `ledger_head` compared against the last recomputed hash | `verify_chain(head_valid=False)` |
| A checkpoint row is rewritten | Merkle root recomputed over the entries it covers | `verify_chain` marks `root_valid=False` |
| The app role updates or deletes | BEFORE UPDATE/DELETE triggers raise | the write fails |
| A superuser rewrites the whole chain consistently | checkpoint roots anchored under Object Lock | `verify_anchor` compares the live row to the anchored copy |

What it does not do: sign entries (the chain proves integrity and order, not
authorship; sign payloads before appending if you need that), or trust the
clock (timestamps are hashed as given). See `SECURITY.md`.

## Quickstart

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import ledgerchain
from ledgerchain import LedgerWriter, verify_chain

engine = create_engine("sqlite:///ledger.db")
ledgerchain.create_all(engine)  # tables + append-only triggers
Session = sessionmaker(bind=engine)

with Session() as session:
    # Append inside the transaction that holds the state change the entry
    # documents. The writer flushes but never commits.
    entry = LedgerWriter.append(
        session,
        event_type="hitl.approval",
        payload={"claim_id": "c-17", "decision": "approve", "model_score": 0.91},
        actor={"kind": "human", "sub": "reviewer-42", "roles": ["approver"]},
        tenant_id="acme",
        subject_uri="/claims/c-17/decision",
    )
    session.commit()
    print(entry.seq, entry.entry_hash)  # 2 <64 hex chars>; seq 1 is genesis

with Session() as session:
    result = verify_chain(session)
    assert result.valid, result.reason
```

Tamper with it and the verifier tells you where:

```
$ sqlite3 ledger.db "DROP TRIGGER trg_decision_ledger_no_update;
                     UPDATE decision_ledger SET payload='{\"x\":1}' WHERE seq=2"
$ ledgerchain verify --database-url sqlite:///ledger.db
{
  "valid": false,
  "checked_entries": 2,
  "first_bad_seq": 2,
  "reason": "payload_sha256 mismatch: payload was modified",
  ...
}
$ echo $?
1
```

## How the chain is built

```
payload_sha256 = sha256( RFC8785(payload) )
entry_hash     = sha256( prev_hash \n payload_sha256 \n seq \n event_type \n ts_rfc3339_utc \n tenant_id )
```

- `seq` is assigned by the writer under a `SELECT ... FOR UPDATE` on the
  single `ledger_head` row, so it is known before insert and concurrent
  appends serialize. On SQLite this degrades to the file writer lock.
- The genesis entry (`seq=1`, `event_type="genesis"`) chains from
  `"0" * 64`. The writer creates it lazily on the first append.
- Every digest is a full 64-hex string. Nothing is truncated anywhere.
- `event_type` is yours to define. Only `"genesis"` is reserved;
  `"checkpoint"` is what `build_checkpoint` writes.

## Checkpoints and anchoring

```python
from ledgerchain import AnchorConfig, anchor_checkpoint, build_checkpoint, verify_anchor

with Session() as session:
    result = build_checkpoint(session)  # Merkle root over new entries
    cp = result.checkpoint  # None if nothing new; see skipped_reason

    config = AnchorConfig(bucket="ledger-anchors", endpoint_url="http://minio:9000")
    anchor_checkpoint(session, cp, config=config)  # never raises; failed => retried later
    assert cp.anchor_status == "anchored"

    report = verify_anchor(cp, config=config)  # reads the object back and compares
    assert report.ok
```

A checkpoint covers `(last_checkpoint.to_seq, head.last_seq]`, is chained to
the previous checkpoint via `prev_checkpoint_root`, and is itself appended to
the ledger. Anchoring writes
`{from_seq, to_seq, merkle_root, ts, prev_checkpoint_root}` to
`s3://<bucket>/<prefix><from>-<to>.json` with Object Lock in COMPLIANCE mode
by default. Run `retry_failed_anchors` from a periodic job; storage outages
self-heal.

Configuration can also come from the environment via `AnchorConfig.from_env()`:
`LEDGER_ANCHOR_BUCKET`, `LEDGER_ANCHOR_PREFIX`, `LEDGER_ANCHOR_ENDPOINT_URL`,
`LEDGER_ANCHOR_OBJECT_LOCK_MODE` (set to an empty string to disable Object
Lock on buckets without it).

The S3 client is injectable: anything with `put_object(**kw)`,
`get_object(Bucket=, Key=)` and `list_objects_v2(**kw)`. The test suite uses an in-memory fake and never
touches the network.

## CLI

```
ledgerchain init-db    --database-url postgresql://...   # tables + triggers
ledgerchain verify     --database-url ... [--from-seq N --to-seq M] [--check-anchors]
ledgerchain checkpoint --database-url ... [--anchor]
ledgerchain anchor     --database-url ... [--limit 20]   # retry pending/failed
```

`verify` prints JSON and exits 1 on any failure, so it drops into cron or
CI. `--database-url` falls back to `LEDGER_DATABASE_URL`, then
`DATABASE_URL`. `python -m ledgerchain` works too.

## Fitting it into an existing app

**Schema.** The models live on their own declarative base. In Alembic:

```python
# env.py
import ledgerchain

target_metadata = [app_metadata, ledgerchain.metadata]

# in the migration that creates the tables
from ledgerchain import install_immutability


def upgrade():
    ...  # autogenerated create_table calls
    install_immutability(op.get_bind())
```

Table names are `decision_ledger`, `ledger_head`, `ledger_checkpoint`.

**Writes.** Call `LedgerWriter.append` inside the same session and
transaction as the state change you are recording, then commit once. If
the state lives in a different database, use a transactional outbox on that
side and relay into the ledger; the outbox row is the evidence that a relay
is pending.

**Reads.** Expose `verify_chain(...).to_dict()` behind whatever auth your
auditors use, and page `DecisionLedgerEntry` by `subject_uri` or
`event_type` for receipts. There is no write endpoint to expose.

**Workers.** Schedule `build_checkpoint` hourly and `retry_failed_anchors`
every few minutes, or run the CLI from cron.

## Design notes

- Canonical JSON is delegated to the [`rfc8785`](https://pypi.org/project/rfc8785/)
  package. Number formatting and key ordering are easy to get subtly wrong
  and every hash depends on them.
- The Merkle tree promotes an odd node unchanged rather than duplicating it,
  which avoids the second-preimage weakness of the duplicate-last-node
  variant.
- `anchor_checkpoint` and `verify_anchor` never raise. Anchoring is
  eventually consistent on purpose; the chain is already tamper-evident
  without it.
- Hashing cost is microseconds per entry. The head-row lock serializes
  appends, which is fine at back-office determination volumes. Shard the
  head per tenant if you ever need more.

## Development

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && mypy && pytest
```

The suite runs on in-memory and file-backed SQLite and needs no services.
The PostgreSQL trigger SQL is the same text the origin application runs in
CI against a real Postgres.

## Releasing

1. Bump `version` in `pyproject.toml` and add a `CHANGELOG.md` entry.
2. Commit, then publish a GitHub release whose tag is `vX.Y.Z` (a bare
   `X.Y.Z` also works) targeting `main`, or push such a tag by hand. The
   release workflow checks the tag against the version, re-runs the suite,
   builds, and publishes to PyPI through trusted publishing (no stored
   token). A release saved as a draft creates no tag and runs nothing.

## Provenance

Extracted from `mpointer/rmfx-v2` (`packages/ledgerchain`), where the same
code is consumed by the application that produced it. The history here is
the `git subtree split` of that directory.

## License

MIT.
