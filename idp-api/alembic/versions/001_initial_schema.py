"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-10-31 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    op.create_table(
        'totp_credentials',
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('secret', sa.Text(), nullable=False),
        sa.Column('confirmed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_step', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id')
    )

    op.create_table(
        'clients',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('client_id', sa.String(length=100), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('redirect_uris', sa.JSON(), nullable=False),
        sa.Column('allowed_cidrs', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_clients_client_id'), 'clients', ['client_id'], unique=True)

    op.create_table(
        'authorization_codes',
        sa.Column('code_hash', sa.String(length=64), nullable=False),
        sa.Column('client_id', sa.String(length=100), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('redirect_uri', sa.String(length=512), nullable=False),
        sa.Column('code_challenge', sa.String(length=128), nullable=False),
        sa.Column('nonce', sa.String(length=255), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('code_hash')
    )
    op.create_index(op.f('ix_authorization_codes_client_id'), 'authorization_codes', ['client_id'])

    op.create_table(
        'sessions',
        sa.Column('id_hash', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('mfa_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id_hash')
    )
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'])

    op.create_table(
        'signing_keys',
        sa.Column('kid', sa.String(length=64), nullable=False),
        sa.Column('private_key', sa.Text(), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('kid')
    )

    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('client_id', sa.String(length=100), nullable=True),
        sa.Column('event', sa.String(length=50), nullable=False),
        sa.Column('outcome', sa.String(length=20), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=512), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_log_timestamp'), 'audit_log', ['timestamp'])
    op.create_index(op.f('ix_audit_log_user_id'), 'audit_log', ['user_id'])
    op.create_index(op.f('ix_audit_log_client_id'), 'audit_log', ['client_id'])


def downgrade() -> None:
    op.drop_table('audit_log')
    op.drop_table('signing_keys')
    op.drop_table('sessions')
    op.drop_table('authorization_codes')
    op.drop_table('clients')
    op.drop_table('totp_credentials')
    op.drop_table('users')
