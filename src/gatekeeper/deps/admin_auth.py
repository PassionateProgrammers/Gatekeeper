from fastapi import Header, HTTPException, status
from gatekeeper.config import settings


async def require_admin(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")):
    if not x_admin_token or x_admin_token != settings.admin_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
