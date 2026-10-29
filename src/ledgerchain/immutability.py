"""Database-level immutability for ``decision_ledger`` and ``ledger_checkpoint``.

On ``decision_ledger`` a BEFORE UPDATE/DELETE trigger raises
unconditionally: the ledger has no legitimate update or delete path. On
``ledger_checkpoint`` deletes are refused and updates may only touch
``anchor_status`` and ``anchor_uri``, which anchoring has to write. This is
defense in depth against application bugs and against anyone holding only
the application's database role. It is not a defense against a superuser, who can drop the
trigger. That case is what :mod:`ledgerchain.anchor` exists for.

Supported dialects: PostgreSQL and SQLite. Other dialects are left alone
and :func:`install_immutability` returns ``False`` so callers can decide
whether that is acceptable.
"""

from __future__ import annotations

from sqlalchemy import Connection, Engine, text

from .models import metadata

PG_INSTALL_SQL = [
    """
    CREATE OR REPLACE FUNCTION decision_ledger_immutable() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'decision_ledger is append-only: % not permitted (seq=%)', TG_OP, OLD.seq;
    END;
    $$ LANGUAGE plpgsql;
    """,
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_update ON decision_ledger;",
    """
    CREATE TRIGGER trg_decision_ledger_no_update
      BEFORE UPDATE ON decision_ledger
      FOR EACH ROW EXECUTE FUNCTION decision_ledger_immutable();
    """,
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_delete ON decision_ledger;",
    """
    CREATE TRIGGER trg_decision_ledger_no_delete
      BEFORE DELETE ON decision_ledger
      FOR EACH ROW EXECUTE FUNCTION decision_ledger_immutable();
    """,
    """
    CREATE OR REPLACE FUNCTION ledger_checkpoint_guard() RETURNS trigger AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'ledger_checkpoint is append-only: DELETE not permitted (id=%)', OLD.id;
      END IF;
      IF (NEW.id, NEW.ts, NEW.from_seq, NEW.to_seq, NEW.merkle_root, NEW.prev_checkpoint_root)
         IS DISTINCT FROM
         (OLD.id, OLD.ts, OLD.from_seq, OLD.to_seq, OLD.merkle_root, OLD.prev_checkpoint_root)
      THEN
        RAISE EXCEPTION
          'ledger_checkpoint is append-only: only anchor_status and anchor_uri may change (id=%)',
          OLD.id;
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """,
    "DROP TRIGGER IF EXISTS trg_ledger_checkpoint_guard ON ledger_checkpoint;",
    """
    CREATE TRIGGER trg_ledger_checkpoint_guard
      BEFORE UPDATE OR DELETE ON ledger_checkpoint
      FOR EACH ROW EXECUTE FUNCTION ledger_checkpoint_guard();
    """,
]

PG_DROP_SQL = [
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_update ON decision_ledger;",
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_delete ON decision_ledger;",
    "DROP FUNCTION IF EXISTS decision_ledger_immutable() CASCADE;",
    "DROP TRIGGER IF EXISTS trg_ledger_checkpoint_guard ON ledger_checkpoint;",
    "DROP FUNCTION IF EXISTS ledger_checkpoint_guard() CASCADE;",
]

SQLITE_INSTALL_SQL = [
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_update;",
    """
    CREATE TRIGGER trg_decision_ledger_no_update
    BEFORE UPDATE ON decision_ledger
    BEGIN
      SELECT RAISE(ABORT, 'decision_ledger is append-only: UPDATE not permitted');
    END;
    """,
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_delete;",
    """
    CREATE TRIGGER trg_decision_ledger_no_delete
    BEFORE DELETE ON decision_ledger
    BEGIN
      SELECT RAISE(ABORT, 'decision_ledger is append-only: DELETE not permitted');
    END;
    """,
    "DROP TRIGGER IF EXISTS trg_ledger_checkpoint_no_delete;",
    """
    CREATE TRIGGER trg_ledger_checkpoint_no_delete
    BEFORE DELETE ON ledger_checkpoint
    BEGIN
      SELECT RAISE(ABORT, 'ledger_checkpoint is append-only: DELETE not permitted');
    END;
    """,
    "DROP TRIGGER IF EXISTS trg_ledger_checkpoint_frozen;",
    """
    CREATE TRIGGER trg_ledger_checkpoint_frozen
    BEFORE UPDATE OF id, ts, from_seq, to_seq, merkle_root, prev_checkpoint_root
    ON ledger_checkpoint
    BEGIN
      SELECT RAISE(
        ABORT, 'ledger_checkpoint is append-only: only anchor_status and anchor_uri may change'
      );
    END;
    """,
]

SQLITE_DROP_SQL = [
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_update;",
    "DROP TRIGGER IF EXISTS trg_decision_ledger_no_delete;",
    "DROP TRIGGER IF EXISTS trg_ledger_checkpoint_no_delete;",
    "DROP TRIGGER IF EXISTS trg_ledger_checkpoint_frozen;",
]


def _statements(dialect: str, *, install: bool) -> list[str] | None:
    if dialect == "postgresql":
        return PG_INSTALL_SQL if install else PG_DROP_SQL
    if dialect == "sqlite":
        return SQLITE_INSTALL_SQL if install else SQLITE_DROP_SQL
    return None


def _run(target: Connection | Engine, statements: list[str]) -> None:
    # Each statement is its own execute() call: DBAPI drivers reject
    # multi-statement strings.
    if isinstance(target, Engine):
        with target.begin() as conn:
            for stmt in statements:
                conn.execute(text(stmt))
    else:
        for stmt in statements:
            target.execute(text(stmt))


def install_immutability(target: Connection | Engine) -> bool:
    """Install the append-only triggers. Idempotent.

    Returns ``True`` when the dialect is supported and the triggers were
    installed, ``False`` when the dialect is unsupported and nothing was
    done. Inside an Alembic migration pass ``op.get_bind()``.
    """
    statements = _statements(target.dialect.name, install=True)
    if statements is None:
        return False
    _run(target, statements)
    return True


def drop_immutability(target: Connection | Engine) -> bool:
    """Remove the triggers. Returns ``False`` on an unsupported dialect."""
    statements = _statements(target.dialect.name, install=False)
    if statements is None:
        return False
    _run(target, statements)
    return True


def create_all(engine: Engine, *, immutable: bool = True) -> None:
    """Create the three ledger tables and, by default, the triggers.

    Convenience for scripts, tests, and demo databases. Production schemas
    normally go through the host's migration tool with
    ``ledgerchain.metadata`` added to ``target_metadata`` and
    :func:`install_immutability` called from the migration.
    """
    metadata.create_all(engine)
    if immutable:
        install_immutability(engine)
