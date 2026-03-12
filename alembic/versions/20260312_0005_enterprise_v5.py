"""enterprise v5 features"""
from alembic import op
import sqlalchemy as sa
revision = '20260312_0005'
down_revision = '20260312_0004'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('cases', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime(), nullable=False), sa.Column('updated_at', sa.DateTime(), nullable=False), sa.Column('tenant_id', sa.Integer(), nullable=True), sa.Column('incident_id', sa.Integer(), nullable=True), sa.Column('title', sa.String(length=200), nullable=False), sa.Column('status', sa.String(length=40), nullable=False), sa.Column('priority', sa.String(length=20), nullable=False), sa.Column('assignee_user_id', sa.Integer(), nullable=True), sa.Column('playbook_json', sa.Text(), nullable=False), sa.Column('notes', sa.Text(), nullable=False))
    op.create_table('evidence', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime(), nullable=False), sa.Column('tenant_id', sa.Integer(), nullable=True), sa.Column('case_id', sa.Integer(), nullable=True), sa.Column('filename', sa.String(length=255), nullable=False), sa.Column('content_type', sa.String(length=120), nullable=False), sa.Column('sha256', sa.String(length=128), nullable=False), sa.Column('storage_path', sa.Text(), nullable=False), sa.Column('chain_of_custody_json', sa.Text(), nullable=False))
    op.create_table('sla_policies', sa.Column('id', sa.Integer(), primary_key=True), sa.Column('created_at', sa.DateTime(), nullable=False), sa.Column('updated_at', sa.DateTime(), nullable=False), sa.Column('tenant_id', sa.Integer(), nullable=True), sa.Column('severity', sa.String(length=20), nullable=False), sa.Column('acknowledge_minutes', sa.Integer(), nullable=False), sa.Column('contain_minutes', sa.Integer(), nullable=False), sa.Column('resolve_minutes', sa.Integer(), nullable=False), sa.Column('is_active', sa.Boolean(), nullable=False))
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        for table in ['alerts', 'incidents', 'assets', 'audit_logs', 'agent_nodes', 'agent_certificates', 'rule_definitions', 'users', 'cases', 'evidence', 'sla_policies']:
            op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;')
            op.execute(f"CREATE POLICY tenant_isolation_{table} ON {table} USING (tenant_id::text = current_setting('app.current_tenant_id', true));")

def downgrade():
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        for table in ['alerts', 'incidents', 'assets', 'audit_logs', 'agent_nodes', 'agent_certificates', 'rule_definitions', 'users', 'cases', 'evidence', 'sla_policies']:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation_{table} ON {table};')
    op.drop_table('sla_policies'); op.drop_table('evidence'); op.drop_table('cases')
