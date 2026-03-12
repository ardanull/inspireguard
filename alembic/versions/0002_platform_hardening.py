"""platform hardening

Revision ID: 0002_platform_hardening
Revises: 0001_enterprise_baseline
Create Date: 2026-03-12 00:00:00
"""
from alembic import op
import sqlalchemy as sa

revision = '0002_platform_hardening'
down_revision = '0001_enterprise_baseline'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('tenants', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()), sa.Column('name', sa.String(length=120), nullable=False), sa.Column('slug', sa.String(length=120), nullable=False), sa.Column('is_active', sa.Boolean(), nullable=False), sa.Column('settings_json', sa.Text(), nullable=False))
    op.create_table('audit_logs', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime()), sa.Column('tenant_id', sa.Integer()), sa.Column('actor_user_id', sa.Integer()), sa.Column('actor_email', sa.String(length=255)), sa.Column('action', sa.String(length=120)), sa.Column('resource_type', sa.String(length=80)), sa.Column('resource_id', sa.String(length=120)), sa.Column('outcome', sa.String(length=20)), sa.Column('details_json', sa.Text()), sa.Column('ip_address', sa.String(length=64)))
    op.create_table('rule_definitions', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()), sa.Column('tenant_id', sa.Integer()), sa.Column('rule_id', sa.String(length=120)), sa.Column('title', sa.String(length=255)), sa.Column('version', sa.Integer()), sa.Column('level', sa.String(length=20)), sa.Column('status', sa.String(length=20)), sa.Column('is_active', sa.Boolean()), sa.Column('rule_yaml', sa.Text()), sa.Column('notes', sa.Text()))
    op.create_table('agent_certificates', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()), sa.Column('tenant_id', sa.Integer()), sa.Column('agent_id', sa.String(length=120)), sa.Column('serial_number', sa.String(length=120)), sa.Column('fingerprint_sha256', sa.String(length=128)), sa.Column('certificate_pem', sa.Text()), sa.Column('private_key_pem', sa.Text()), sa.Column('issued_by', sa.String(length=120)), sa.Column('expires_at', sa.DateTime()), sa.Column('revoked_at', sa.DateTime()), sa.Column('is_active', sa.Boolean()))
    op.create_table('sso_providers', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime()), sa.Column('updated_at', sa.DateTime()), sa.Column('tenant_id', sa.Integer()), sa.Column('name', sa.String(length=120)), sa.Column('protocol', sa.String(length=20)), sa.Column('issuer', sa.String(length=255)), sa.Column('client_id', sa.String(length=255)), sa.Column('client_secret', sa.String(length=255)), sa.Column('metadata_json', sa.Text()), sa.Column('is_enabled', sa.Boolean()))
    for table in ['users','alerts','assets','incidents','agent_nodes','threat_indicators']:
        op.add_column(table, sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.add_column('agent_nodes', sa.Column('policy_json', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('agent_nodes', 'policy_json')
    for table in ['threat_indicators','agent_nodes','incidents','assets','alerts','users']:
        op.drop_column(table, 'tenant_id')
    op.drop_table('sso_providers')
    op.drop_table('agent_certificates')
    op.drop_table('rule_definitions')
    op.drop_table('audit_logs')
    op.drop_table('tenants')
