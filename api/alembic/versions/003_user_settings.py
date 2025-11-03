"""Add user_settings table for user-specific configuration

Revision ID: 003
Revises: 002
Create Date: 2025-11-02

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Create user_settings table for storing user-specific AWS and Bedrock configuration.

    Each user can configure their own preferences without requiring application restart.
    """
    op.create_table(
        'user_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('bedrock_model_id', sa.String(length=255), nullable=False, server_default='us.anthropic.claude-3-5-sonnet-20241022-v2:0'),
        sa.Column('bedrock_max_tokens', sa.Integer(), nullable=False, server_default='4096'),
        sa.Column('bedrock_temperature', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('default_aws_region', sa.String(length=50), nullable=False, server_default='us-east-1'),
        sa.Column('default_aws_output_format', sa.String(length=20), nullable=False, server_default='json'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('user_id')
    )

    # Create indexes
    op.create_index('ix_user_settings_id', 'user_settings', ['id'], unique=False)
    op.create_index('ix_user_settings_user_id', 'user_settings', ['user_id'], unique=True)


def downgrade() -> None:
    """
    Drop user_settings table.
    """
    op.drop_index('ix_user_settings_user_id', table_name='user_settings')
    op.drop_index('ix_user_settings_id', table_name='user_settings')
    op.drop_table('user_settings')
