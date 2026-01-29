from fastapi import APIRouter, Depends, Request

from gatekeeper.deps.client_auth import require_client_key
from gatekeeper.models.api_key import ApiKey

router = APIRouter(tags=["gateway"])


@router.get("/protected")
async def protected(request: Request, api_key: ApiKey = Depends(require_client_key)):
    return {
        "ok": True,
        "tenant_id": str(request.state.tenant_id),
        "api_key_id": str(request.state.api_key_id),
    }
