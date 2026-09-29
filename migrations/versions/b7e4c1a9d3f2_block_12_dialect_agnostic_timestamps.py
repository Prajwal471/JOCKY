"""block 12: dialect-agnostic timestamp defaults

Revision ID: b7e4c1a9d3f2
Revises: c41a7e2f9b10
Create Date: 2026-09-29

The Block 0 and Block 10 migrations wrote ``server_default=sa.text('now()')``,
which is a PostgreSQL function. The ORM models declare the same intent as
``func.now()``, which SQLAlchemy renders per dialect -- so tables created from
the ORM (``Base.metadata.create_all``, used by the test suite) work on SQLite,
while tables created by ``alembic upgrade head`` (used by the demo) do not.

The symptom was sharp: on a SQLite-backed demo every read route worked, but
``POST /missions`` failed with ``sqlite3.OperationalError: unknown function:
now()`` as soon as SQLAlchemy asked the database to return the server-generated
``created_at``.

``CURRENT_TIMESTAMP`` is the standard spelling understood by both PostgreSQL and
SQLite, so this revision restates the default rather than changing behaviour.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7e4c1a9d3f2'
down_revision: Union[str, Sequence[str], None] = 'c41a7e2f9b10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: ``(table, column)`` pairs whose server default is PostgreSQL-specific.
TIMESTAMP_COLUMNS = (
    ('missions', 'created_at'),
    ('endpoints', 'created_at'),
    ('artifacts', 'compiled_at'),
    ('capability_decisions', 'decided_at'),
    ('evidence_records', 'received_at'),
    ('eval_baseline_runs', 'ran_at'),
)


def upgrade() -> None:
    """Restate every timestamp default in standard SQL.

    ``batch_alter_table`` is required rather than a bare ``alter_column``:
    SQLite cannot ``ALTER COLUMN``, so batch mode rebuilds the table there and
    emits the ordinary statement everywhere else.
    """
    for table, column in TIMESTAMP_COLUMNS:
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column(
                column,
                server_default=sa.text('CURRENT_TIMESTAMP'),
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=False,
            )


def downgrade() -> None:
    """Return to the PostgreSQL-only spelling."""
    for table, column in TIMESTAMP_COLUMNS:
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column(
                column,
                server_default=sa.text('now()'),
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=False,
            )
