import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gatekeeper.models.base import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)

    # store hashed key only
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # optional for display/debug (no secret)
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)

    # NEW: per-key rate limit config
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=10)   # requests
    rate_window: Mapped[int] = mapped_column(Integer, nullable=False, default=60) # seconds

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    tenant = relationship("Tenant")
