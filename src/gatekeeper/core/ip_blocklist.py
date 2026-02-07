from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from gatekeeper.deps.redis import get_redis

BLOCK_IP_PREFIX = "blk:ip:"


class IPBlocklistMiddleware(BaseHTTPMiddleware):
    """
    Fast fail on blocked IPs using Redis TTL keys.

    Redis key:
      blk:ip:<client_ip> -> string reason (optional), with EX ttl
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else None
        if not client_ip:
            return await call_next(request)

        r = await get_redis()
        key = f"{BLOCK_IP_PREFIX}{client_ip}"

        reason = await r.get(key)
        if reason is None:
            return await call_next(request)

        ttl = await r.ttl(key)  # seconds; -1 no ttl, -2 not found
        retry_after = ttl if ttl and ttl > 0 else None

        payload = {
            "detail": "IP temporarily blocked",
            "client_ip": client_ip,
            "reason": reason,
            "retry_after_seconds": retry_after,
        }

        headers = {}
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)

        return JSONResponse(status_code=403, content=payload, headers=headers)
