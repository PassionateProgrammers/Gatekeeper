from alembic import op
import sqlalchemy as sa

revision = "4957c860742e"
down_revision = "8a7b808d0aaf"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "api_keys",
        sa.Column("rate_limit", sa.Integer(), nullable=False, server_default="10"),
    )
    op.add_column(
        "api_keys",
        sa.Column("rate_window", sa.Integer(), nullable=False, server_default="60"),
    )
    op.alter_column("api_keys", "rate_limit", server_default=None)
    op.alter_column("api_keys", "rate_window", server_default=None)


def downgrade():
    op.drop_column("api_keys", "rate_window")
    op.drop_column("api_keys", "rate_limit")
