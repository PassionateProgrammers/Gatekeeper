from alembic import op
import sqlalchemy as sa

revision = "b782786cf01b"
down_revision = "4957c860742e"
branch_labels = None
depends_on = None


def upgrade():
    # drop FKs first
    op.drop_constraint("usage_events_api_key_id_fkey", "usage_events", type_="foreignkey")
    op.drop_constraint("usage_events_tenant_id_fkey", "usage_events", type_="foreignkey")

    # make nullable
    op.alter_column("usage_events", "tenant_id", existing_type=sa.dialects.postgresql.UUID(), nullable=True)
    op.alter_column("usage_events", "api_key_id", existing_type=sa.dialects.postgresql.UUID(), nullable=True)

    # re-add FKs (nullable columns are fine)
    op.create_foreign_key(
        "usage_events_tenant_id_fkey",
        "usage_events",
        "tenants",
        ["tenant_id"],
        ["id"],
        ondelete=None,
    )
    op.create_foreign_key(
        "usage_events_api_key_id_fkey",
        "usage_events",
        "api_keys",
        ["api_key_id"],
        ["id"],
        ondelete=None,
    )


def downgrade():
    op.drop_constraint("usage_events_api_key_id_fkey", "usage_events", type_="foreignkey")
    op.drop_constraint("usage_events_tenant_id_fkey", "usage_events", type_="foreignkey")

    op.alter_column("usage_events", "api_key_id", existing_type=sa.dialects.postgresql.UUID(), nullable=False)
    op.alter_column("usage_events", "tenant_id", existing_type=sa.dialects.postgresql.UUID(), nullable=False)

    op.create_foreign_key("usage_events_tenant_id_fkey", "usage_events", "tenants", ["tenant_id"], ["id"])
    op.create_foreign_key("usage_events_api_key_id_fkey", "usage_events", "api_keys", ["api_key_id"], ["id"])
