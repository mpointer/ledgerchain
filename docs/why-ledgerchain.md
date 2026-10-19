# ledgerchain: a tamper-evident decision ledger in three tables

This is the companion to the [typesafe-gates](https://github.com/mpointer/typesafe-gates)
write-up, and the opposite kind of component. `typesafe-gates` is about
making decisions. `ledgerchain` is about proving, later, what was decided,
by whom, and that nobody edited the record.

It came out of a decision-integrity platform where an AI-assisted system
makes determinations and humans approve, attest, and correct them. The
auditor's question is not "was the model right" but "is this the record,
and has it been touched". The answer has to hold without trusting the
application that wrote it.

## What it is

Three tables in the PostgreSQL or SQLite you already run, about 1,300
lines of Python, and no blockchain, ledger database, or sidecar.

Each entry's payload is hashed over its RFC 8785 canonical JSON form, so
key order and whitespace cannot produce a different digest for the same
content. The entry hash chains the previous hash, the payload hash, the
sequence number, the event type, the timestamp, and the tenant. Sequence
numbers are assigned under a row lock on a single head row, so concurrent
appends serialize and every gap is detectable. The writer flushes inside
the caller's transaction and never commits, so the ledger entry and the
state change it documents land together or not at all.

Database triggers refuse updates and deletes from the application role.
A verifier recomputes every hash from genesis, compares the head pointer
to the last recomputed hash, and names the first bad sequence number and
why. Periodic checkpoints build a Merkle root over new entries and can be
anchored to object storage under Object Lock, so that a superuser who
rewrites the whole chain consistently is still caught when the anchored
copy disagrees with the live row.

## What it does not do

It does not sign entries. The chain proves integrity and order, not
authorship; sign payloads before appending if you need that. It does not
trust the clock; timestamps are hashed as given. And it does not stop a
database superuser from dropping the triggers. That is what the anchor is
for, and the anchor only helps if the bucket's retention is set by
someone other than the application.

## Why extract it

The ledger code had lived inside the application for most of a year. It
had tests, but they ran only when the app's suite ran, and the writer
quietly depended on the app's ORM base. Pulling it out forced the
boundary: the package exposes its own metadata and the app copies the
tables onto its own base. Two verifier checks got added in the process
that the in-tree code never had: recomputing checkpoint roots, and
reading an anchored copy back for comparison. The package suite is 81
tests on SQLite and PostgreSQL, and the app that produced it now installs
it from PyPI like anyone else.

```sh
pip install ledgerchain
```

Source and the 81-test suite are in this repository. MIT.
