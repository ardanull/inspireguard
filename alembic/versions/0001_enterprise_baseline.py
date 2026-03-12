"""enterprise baseline schema"""

from alembic import op
import sqlalchemy as sa

revision = "0001_enterprise_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("users", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("updated_at", sa.DateTime()), sa.Column("email", sa.String(length=255), nullable=False), sa.Column("full_name", sa.String(length=255), nullable=False), sa.Column("password_hash", sa.String(length=255), nullable=False), sa.Column("role", sa.String(length=50)), sa.Column("is_active", sa.Boolean()), sa.Column("permissions_json", sa.Text()))
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table("assets", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("ip_address", sa.String(length=64), nullable=False), sa.Column("hostname", sa.String(length=128)), sa.Column("owner", sa.String(length=128)), sa.Column("criticality", sa.String(length=20)), sa.Column("environment", sa.String(length=30)), sa.Column("tags_json", sa.Text()))
    op.create_index("ix_assets_ip_address", "assets", ["ip_address"], unique=True)
    op.create_table("incidents", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("updated_at", sa.DateTime()), sa.Column("status", sa.String(length=32)), sa.Column("severity", sa.String(length=20)), sa.Column("title", sa.String(length=200)), sa.Column("summary", sa.Text()), sa.Column("source_key", sa.String(length=120), nullable=False), sa.Column("src_ip", sa.String(length=64)), sa.Column("alert_count", sa.Integer()), sa.Column("first_seen_at", sa.DateTime()), sa.Column("last_seen_at", sa.DateTime()), sa.Column("tags_json", sa.Text()), sa.Column("assigned_user_id", sa.Integer()), sa.Column("triage_status", sa.String(length=40)), sa.Column("runbook_json", sa.Text()))
    op.create_index("ix_incidents_source_key", "incidents", ["source_key"], unique=True)
    op.create_table("alerts", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("detector", sa.String(length=100)), sa.Column("severity", sa.String(length=20)), sa.Column("status", sa.String(length=20)), sa.Column("src_ip", sa.String(length=64)), sa.Column("dst_ip", sa.String(length=64)), sa.Column("title", sa.String(length=200)), sa.Column("description", sa.Text()), sa.Column("fingerprint", sa.String(length=120)), sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id")), sa.Column("metadata_json", sa.Text()), sa.Column("sensor_id", sa.String(length=120)), sa.Column("raw_event_json", sa.Text()))
    op.create_table("threat_indicators", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("type", sa.String(length=30)), sa.Column("value", sa.String(length=255), nullable=False), sa.Column("severity", sa.String(length=20)), sa.Column("confidence", sa.Integer()), sa.Column("source", sa.String(length=100)), sa.Column("description", sa.Text()), sa.Column("tags_json", sa.Text()))
    op.create_index("ix_threat_indicators_value", "threat_indicators", ["value"], unique=True)
    op.create_table("agent_nodes", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("updated_at", sa.DateTime()), sa.Column("agent_id", sa.String(length=120), nullable=False), sa.Column("hostname", sa.String(length=255)), sa.Column("ip_address", sa.String(length=64)), sa.Column("version", sa.String(length=40)), sa.Column("status", sa.String(length=30)), sa.Column("capabilities_json", sa.Text()), sa.Column("labels_json", sa.Text()), sa.Column("last_seen_at", sa.DateTime()), sa.Column("enrollment_token", sa.String(length=128)), sa.Column("is_approved", sa.Boolean()))
    op.create_index("ix_agent_nodes_agent_id", "agent_nodes", ["agent_id"], unique=True)
    op.create_table("incident_comments", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("created_at", sa.DateTime()), sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id")), sa.Column("author_user_id", sa.Integer(), sa.ForeignKey("users.id")), sa.Column("comment", sa.Text()))


def downgrade() -> None:
    op.drop_table("incident_comments")
    op.drop_index("ix_agent_nodes_agent_id", table_name="agent_nodes")
    op.drop_table("agent_nodes")
    op.drop_index("ix_threat_indicators_value", table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_table("alerts")
    op.drop_index("ix_incidents_source_key", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_assets_ip_address", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
