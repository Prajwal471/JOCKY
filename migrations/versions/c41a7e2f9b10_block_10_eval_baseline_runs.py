"""block 10: eval baseline runs

Revision ID: c41a7e2f9b10
Revises: d796ad1b9ceb
Create Date: 2026-09-29

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c41a7e2f9b10'
down_revision: Union[str, Sequence[str], None] = 'd796ad1b9ceb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('eval_baseline_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('baseline_id', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('mode', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('property', sa.String(length=128), nullable=False),
    sa.Column('capabilities', sa.JSON(), nullable=False),
    sa.Column('expectations_total', sa.Integer(), nullable=False),
    sa.Column('expectations_passed', sa.Integer(), nullable=False),
    sa.Column('evidence_count', sa.Integer(), nullable=False),
    sa.Column('steps', sa.Integer(), nullable=False),
    sa.Column('proofs_hold', sa.Boolean(), nullable=False),
    sa.Column('determinism_hold', sa.Boolean(), nullable=False),
    sa.Column('bounds_hold', sa.Boolean(), nullable=False),
    sa.Column('no_mutation_hold', sa.Boolean(), nullable=False),
    sa.Column('citation', sa.JSON(), nullable=False),
    sa.Column('provenance', sa.JSON(), nullable=False),
    sa.Column('detail', sa.JSON(), nullable=False),
    sa.Column('ran_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_eval_baseline_runs_baseline_id'), 'eval_baseline_runs', ['baseline_id'], unique=False)
    op.create_index(op.f('ix_eval_baseline_runs_mode'), 'eval_baseline_runs', ['mode'], unique=False)
    op.create_index(op.f('ix_eval_baseline_runs_status'), 'eval_baseline_runs', ['status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_eval_baseline_runs_status'), table_name='eval_baseline_runs')
    op.drop_index(op.f('ix_eval_baseline_runs_mode'), table_name='eval_baseline_runs')
    op.drop_index(op.f('ix_eval_baseline_runs_baseline_id'), table_name='eval_baseline_runs')
    op.drop_table('eval_baseline_runs')
