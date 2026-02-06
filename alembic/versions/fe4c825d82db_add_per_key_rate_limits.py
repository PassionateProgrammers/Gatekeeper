"""add per-key rate limits

Revision ID: fe4c825d82db
Revises: add_rate_limit_to_api_keys
Create Date: 2026-02-06 20:37:25.065469

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fe4c825d82db'
down_revision: Union[str, None] = 'add_rate_limit_to_api_keys'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
