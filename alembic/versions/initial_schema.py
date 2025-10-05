"""Initial schema migration.

Revision ID: initial_schema
Revises:
Create Date: 2024-01-15 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial database schema."""
    # Create enum types
    user_role_enum = postgresql.ENUM('admin', 'manager', 'user', 'viewer', name='userrole', create_type=False)
    grant_status_enum = postgresql.ENUM('draft', 'published', 'active', 'closed', 'archived', name='grantstatus', create_type=False)
    application_status_enum = postgresql.ENUM('draft', 'submitted', 'under_review', 'approved', 'rejected', 'withdrawn', name='applicationstatus', create_type=False)
    audit_action_enum = postgresql.ENUM('create', 'update', 'delete', 'login', 'logout', 'view', name='auditactions', create_type=False)

    # Create users table
    op.create_table('users',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('username', sa.String(50), nullable=False),
        sa.Column('first_name', sa.String(100), nullable=False),
        sa.Column('last_name', sa.String(100), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('role', user_role_enum, nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_superuser', sa.Boolean(), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    # Create grants table
    op.create_table('grants',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('short_description', sa.String(1000), nullable=True),
        sa.Column('grant_number', sa.String(100), nullable=True),
        sa.Column('funding_agency', sa.String(255), nullable=False),
        sa.Column('opportunity_number', sa.String(100), nullable=True),
        sa.Column('cfda_number', sa.String(50), nullable=True),
        sa.Column('min_amount', sa.Float(), nullable=True),
        sa.Column('max_amount', sa.Float(), nullable=True),
        sa.Column('total_funding', sa.Float(), nullable=True),
        sa.Column('open_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('close_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('award_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', grant_status_enum, nullable=False),
        sa.Column('eligibility_criteria', sa.Text(), nullable=True),
        sa.Column('requirements', sa.Text(), nullable=True),
        sa.Column('contact_info', sa.Text(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('created_by', sa.String(36), nullable=False),
        sa.Column('updated_by', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_grants_cfda_number'), 'grants', ['cfda_number'], unique=False)
    op.create_index(op.f('ix_grants_grant_number'), 'grants', ['grant_number'], unique=False)
    op.create_index(op.f('ix_grants_opportunity_number'), 'grants', ['opportunity_number'], unique=False)

    # Create applications table
    op.create_table('applications',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('grant_id', sa.String(36), nullable=False),
        sa.Column('applicant_id', sa.String(36), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('project_summary', sa.Text(), nullable=False),
        sa.Column('project_description', sa.Text(), nullable=False),
        sa.Column('budget_narrative', sa.Text(), nullable=True),
        sa.Column('timeline', sa.Text(), nullable=True),
        sa.Column('requested_amount', sa.Float(), nullable=True),
        sa.Column('matching_funds', sa.Float(), nullable=True),
        sa.Column('other_funding_sources', sa.Text(), nullable=True),
        sa.Column('status', application_status_enum, nullable=False),
        sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('decision_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reviewer_notes', sa.Text(), nullable=True),
        sa.Column('review_score', sa.Integer(), nullable=True),
        sa.Column('funding_recommended', sa.Float(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('created_by', sa.String(36), nullable=False),
        sa.Column('updated_by', sa.String(36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['applicant_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['grant_id'], ['grants.id'], ),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create grant_attachments table
    op.create_table('grant_attachments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('grant_id', sa.String(36), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('original_filename', sa.String(255), nullable=False),
        sa.Column('file_path', sa.String(500), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(100), nullable=False),
        sa.Column('description', sa.String(500), nullable=True),
        sa.Column('uploaded_by', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['grant_id'], ['grants.id'], ),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create application_attachments table
    op.create_table('application_attachments',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('application_id', sa.String(36), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('original_filename', sa.String(255), nullable=False),
        sa.Column('file_path', sa.String(500), nullable=False),
        sa.Column('file_size', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(100), nullable=False),
        sa.Column('description', sa.String(500), nullable=True),
        sa.Column('uploaded_by', sa.String(36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )

    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=True),
        sa.Column('grant_id', sa.String(36), nullable=True),
        sa.Column('application_id', sa.String(36), nullable=True),
        sa.Column('action', audit_action_enum, nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=False),
        sa.Column('resource_id', sa.String(100), nullable=False),
        sa.Column('old_values', sa.JSON(), nullable=True),
        sa.Column('new_values', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['application_id'], ['applications.id'], ),
        sa.ForeignKeyConstraint(['grant_id'], ['grants.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Drop initial database schema."""
    op.drop_table('audit_logs')
    op.drop_table('application_attachments')
    op.drop_table('grant_attachments')
    op.drop_table('applications')
    op.drop_table('grants')
    op.drop_table('users')

    # Drop enum types
    user_role_enum = postgresql.ENUM(name='userrole')
    user_role_enum.drop(op.get_bind(), checkfirst=True)

    grant_status_enum = postgresql.ENUM(name='grantstatus')
    grant_status_enum.drop(op.get_bind(), checkfirst=True)

    application_status_enum = postgresql.ENUM(name='applicationstatus')
    application_status_enum.drop(op.get_bind(), checkfirst=True)

    audit_action_enum = postgresql.ENUM(name='auditactions')
    audit_action_enum.drop(op.get_bind(), checkfirst=True)