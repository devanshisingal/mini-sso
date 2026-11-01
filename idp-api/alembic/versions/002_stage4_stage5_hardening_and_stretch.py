"""stage4 and stage5 hardening and stretch features

Revision ID: 002_hardening_stretch
Revises: 001_initial
Create Date: 2026-11-01 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = '002_hardening_stretch'
down_revision: Union[str, None] = '001_initial'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Recovery codes table for MFA backup codes
    op.create_table(
        'recovery_codes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('code_hash', sa.String(length=64), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_recovery_codes_user_id'), 'recovery_codes', ['user_id'], unique=False)

    # 2. Key rotation column on signing_keys
    op.add_column('signing_keys', sa.Column('retired_at', sa.DateTime(timezone=True), nullable=True))

    # 3. Tamper-evident hash chain columns on audit_log
    op.add_column('audit_log', sa.Column('prev_hash', sa.String(length=64), nullable=True))
    op.add_column('audit_log', sa.Column('entry_hash', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('audit_log', 'entry_hash')
    op.drop_column('audit_log', 'prev_hash')
    op.drop_column('signing_keys', 'retired_at')
    op.drop_index(op.f('ix_recovery_codes_user_id'), table_name='recovery_codes')
    op.drop_table('recovery_codes')
