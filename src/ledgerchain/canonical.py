"""RFC 8785 (JSON Canonicalization Scheme) helpers.

Every hash in this package is computed over the canonical byte form of a
JSON value: ``payload_sha256`` for ledger entries, and anything a caller
chooses to sign before appending. Two dicts with the same content but a
different key order, or the same number written two ways, hash the same.

Canonicalization is delegated to the ``rfc8785`` package rather than
hand-rolled. ECMAScript shortest-round-trip number formatting and UTF-16
code-unit key ordering are easy to get subtly wrong, and every hash in the
chain depends on them being exact.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

CanonicalizationError = rfc8785.CanonicalizationError
"""Raised when a value cannot be canonicalized (for example, a ``set``)."""


def canonicalize(value: Any) -> bytes:
    """Serialize ``value`` to canonical JSON bytes per RFC 8785."""
    return rfc8785.dumps(value)


def sha256_hex(value: Any) -> str:
    """SHA-256 of the canonical JSON serialization, as lowercase hex."""
    return hashlib.sha256(canonicalize(value)).hexdigest()
