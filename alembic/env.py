from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool

from gatekeeper.config import settings
from gatekeeper.models.base import Base

# Import models so Alembic sees metadata
from gatekeeper.models.tenant import Tenant  # noqa: F401
from gatekeeper.models.api_key import ApiKey  # noqa: F401
from gatekeeper.models.usage_event import UsageEvent  # noqa: F401

config = context.config
fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    # Use psycopg (v3) for Alembic sync migrations
    return settings.postgres_dsn.replace("postgresql+asyncpg", "postgresql+psycopg")


def run_migrations_offline():
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
