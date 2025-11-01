"""Initial schema

Revision ID: 001
Revises:
Create Date: 2025-10-29

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create policies table
    op.create_table(
        'policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('natural_language_input', sa.Text(), nullable=False),
        sa.Column('policy_json', postgresql.JSON(astext_type=sa.Text()), nullable=False),
        sa.Column('aws_policy_arn', sa.String(length=512), nullable=True),
        sa.Column('aws_account_id', sa.String(length=12), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_policies_name', 'policies', ['name'])
    op.create_index('ix_policies_aws_account_id', 'policies', ['aws_account_id'])

    # Create policy_audits table
    op.create_table(
        'policy_audits',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('policy_id', sa.Integer(), nullable=True),
        sa.Column('aws_account_id', sa.String(length=12), nullable=False),
        sa.Column('role_arn', sa.String(length=512), nullable=True),
        sa.Column('status', sa.Enum('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', name='auditstatus'), nullable=False),
        sa.Column('findings', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('recommendations', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['policy_id'], ['policies.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_policy_audits_aws_account_id', 'policy_audits', ['aws_account_id'])
    op.create_index('ix_policy_audits_status', 'policy_audits', ['status'])

    # Create audit_results table
    op.create_table(
        'audit_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('audit_id', sa.Integer(), nullable=False),
        sa.Column('resource_type', sa.String(length=50), nullable=False),
        sa.Column('resource_arn', sa.String(length=512), nullable=False),
        sa.Column('resource_name', sa.String(length=255), nullable=False),
        sa.Column('unused_permissions', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('permission_reduction_percent', sa.Integer(), nullable=True),
        sa.Column('recommended_policy', postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['audit_id'], ['policy_audits.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_results_resource_arn', 'audit_results', ['resource_arn'])


def downgrade() -> None:
    op.drop_index('ix_audit_results_resource_arn', table_name='audit_results')
    op.drop_table('audit_results')
    op.drop_index('ix_policy_audits_status', table_name='policy_audits')
    op.drop_index('ix_policy_audits_aws_account_id', table_name='policy_audits')
    op.drop_table('policy_audits')
    op.drop_index('ix_policies_aws_account_id', table_name='policies')
    op.drop_index('ix_policies_name', table_name='policies')
    op.drop_table('policies')
