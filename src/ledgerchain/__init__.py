"""ledgerchain: a hash-chained, tamper-evident decision ledger on SQLAlchemy.

Append events inside your own transaction, verify the whole chain by
recomputation, checkpoint it with Merkle roots, and anchor those roots to
object storage as an independent witness.
"""

from .anchor import (
    AnchorConfig,
    AnchorResult,
    AnchorVerifyResult,
    anchor_checkpoint,
    anchor_payload,
    retry_failed_anchors,
    verify_anchor,
    verify_anchors,
)
from .canonical import CanonicalizationError, canonicalize, sha256_hex
from .checkpoint import CheckpointResult, build_checkpoint, merkle_root
from .immutability import create_all, drop_immutability, install_immutability
from .models import Base, DecisionLedgerEntry, LedgerCheckpoint, LedgerHead, metadata
from .verify import VerifyResult, verify_chain
from .writer import (
    CHECKPOINT_EVENT_TYPE,
    GENESIS_EVENT_TYPE,
    GENESIS_PREV_HASH,
    LedgerWriter,
    compute_entry_hash,
)

__version__ = "0.1.0"

__all__ = [
    "AnchorConfig",
    "AnchorResult",
    "AnchorVerifyResult",
    "Base",
    "CHECKPOINT_EVENT_TYPE",
    "CanonicalizationError",
    "CheckpointResult",
    "DecisionLedgerEntry",
    "GENESIS_EVENT_TYPE",
    "GENESIS_PREV_HASH",
    "LedgerCheckpoint",
    "LedgerHead",
    "LedgerWriter",
    "VerifyResult",
    "anchor_checkpoint",
    "anchor_payload",
    "build_checkpoint",
    "canonicalize",
    "compute_entry_hash",
    "create_all",
    "drop_immutability",
    "install_immutability",
    "merkle_root",
    "metadata",
    "retry_failed_anchors",
    "sha256_hex",
    "verify_anchor",
    "verify_anchors",
    "verify_chain",
    "__version__",
]
