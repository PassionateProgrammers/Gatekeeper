from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_env: str = "local"
    app_host: str = "0.0.0.0"
    app_port: int = 8080
    log_level: str = "INFO"

    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "gatekeeper"
    postgres_user: str = "gatekeeper"
    postgres_password: str = "gatekeeper"

    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0

    @property
    def postgres_dsn(self) -> str:
        # asyncpg DSN
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


settings = Settings()  # reads from environment
