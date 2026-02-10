from __future__ import annotations

import json
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from gatekeeper.deps.redis import get_redis

BLOCK_IP_PREFIX = "blk:ip:"


def _safe_json_loads(raw: Any) -> dict:
    if raw is None:
        return {}
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except Exception:
            # Backward compat: old value was a plain string reason
            return {"reason": raw, "reason_code": "manual"}
    return {}


class IPBlocklistMiddleware(BaseHTTPMiddleware):
    """
    Fast fail on blocked IPs using Redis TTL keys.

    Redis key:
      blk:ip:<client_ip> -> JSON string:
        {
          "block_id": "...uuid...",
          "reason_code": "manual" | "auto_unauth_401_surge" | "one_click_suspects" | "operator_action",
          "reason": "...",
          "created_at_epoch": 123,
          "expires_at_epoch": 456
        }
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else None
        if not client_ip:
            return await call_next(request)

        r = await get_redis()
        key = f"{BLOCK_IP_PREFIX}{client_ip}"

        raw = await r.get(key)
        if raw is None:
            return await call_next(request)

        meta = _safe_json_loads(raw)

        ttl = await r.ttl(key)  # seconds; -1 no ttl, -2 not found
        retry_after = ttl if ttl and ttl > 0 else None

        payload = {
            "detail": "IP temporarily blocked",
            "client_ip": client_ip,
            "block_id": meta.get("block_id"),
            "reason_code": meta.get("reason_code") or "manual",
            "reason": meta.get("reason"),
            "retry_after_seconds": retry_after,
            "expires_at_epoch": meta.get("expires_at_epoch"),
        }

        headers = {}
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)

        return JSONResponse(status_code=403, content=payload, headers=headers)
