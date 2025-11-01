"""Switch to Google OAuth authentication

Revision ID: 002
Revises: 001
Create Date: 2025-11-01

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Switch users table from password-based to Google OAuth authentication.

    WARNING: This migration will drop the hashed_password column.
    If you have existing users, you will need to migrate them manually.
    """
    # Add new Google OAuth columns
    op.add_column('users', sa.Column('google_id', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('avatar_url', sa.String(length=500), nullable=True))

    # Create unique index on google_id
    op.create_index('ix_users_google_id', 'users', ['google_id'], unique=True)

    # Drop hashed_password column
    op.drop_column('users', 'hashed_password')

    # Update is_verified default to True (Google users are pre-verified)
    # Note: This doesn't change existing rows, only new inserts
    op.alter_column('users', 'is_verified',
                    existing_type=sa.Boolean(),
                    nullable=False,
                    server_default='true')

    # Note: After running this migration, you should populate google_id for any existing users
    # or drop and recreate the users table if starting fresh


def downgrade() -> None:
    """
    Rollback to password-based authentication.

    WARNING: This will drop google_id and avatar_url columns.
    """
    # Add back hashed_password column
    op.add_column('users', sa.Column('hashed_password', sa.String(length=255), nullable=True))

    # Drop Google OAuth columns
    op.drop_index('ix_users_google_id', table_name='users')
    op.drop_column('users', 'google_id')
    op.drop_column('users', 'avatar_url')

    # Revert is_verified default
    op.alter_column('users', 'is_verified',
                    existing_type=sa.Boolean(),
                    nullable=False,
                    server_default='false')
