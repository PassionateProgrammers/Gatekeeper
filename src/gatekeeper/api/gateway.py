from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.deps.client_auth import require_client_key
from gatekeeper.deps.db import get_db
from gatekeeper.models.api_key import ApiKey

router = APIRouter(tags=["gateway"])


@router.get("/protected")
async def protected(api_key: ApiKey = Depends(require_client_key)):
    return {"ok": True, "tenant_id": str(api_key.tenant_id), "api_key_id": str(api_key.id)}


@router.get("/whoami")
async def whoami(
    request: Request,
    api_key: ApiKey = Depends(require_client_key),
    db: AsyncSession = Depends(get_db),
):
    return {
        "tenant_id": str(api_key.tenant_id),
        "api_key_id": str(api_key.id),
        "rate_limit": getattr(api_key, "rate_limit", None),
        "rate_window": getattr(api_key, "rate_window", None),
        "client_ip": getattr(request.state, "client_ip", None),
        "request_id": getattr(request.state, "request_id", None),
    }
