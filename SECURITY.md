# Security policy

## What this library does and does not defend against

`ledgerchain` makes a ledger tamper-evident, not tamper-proof.

- A row edited, deleted, or reordered by anyone who lacks the ability to
  rewrite the entire chain is detected by `verify_chain`, which names the
  first bad sequence number.
- The immutability triggers stop the application database role from
  updating or deleting ledger rows, including through application bugs.
  The one exception is a redaction, which erases a payload and must be
  recorded by a `redaction` entry, or `verify_chain` fails. That entry
  names the actor who asked. Deciding who may redact is the application's
  job.
- A fully privileged database administrator can drop the triggers and
  rewrite the whole chain consistently. That is what checkpoint anchoring
  is for: a Merkle root written to object storage under Object Lock is an
  independent witness, and `verify_anchor` compares the live chain against
  it. Anchoring is eventually consistent by design, so the window between a
  checkpoint and its anchor is not covered.
- Entries are not signed. The chain proves integrity and order, not
  authorship. Sign the payloads you care about before appending them.
- Timestamps come from the application clock and are hashed as given. A
  hostile application clock can backdate an entry at write time; the chain
  still fixes its order relative to every other entry.

## Supported versions

Only the latest minor release receives fixes.

## Reporting a vulnerability

Email mpointer@gmail.com with "ledgerchain security" in the subject. Do not
open a public issue for an unpatched vulnerability. You will get an
acknowledgement within five business days. Coordinated disclosure is
preferred: a fix and a release first, then a public advisory crediting the
reporter.
