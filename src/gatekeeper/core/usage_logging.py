import time
from datetime import datetime, timezone
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from gatekeeper.deps.db import SessionLocal
from gatekeeper.models.usage_event import UsageEvent


def _get_client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return ""


class UsageLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        start = time.perf_counter()
        response: Response | None = None

        try:
            response = await call_next(request)
            return response
        finally:
            latency_ms = int((time.perf_counter() - start) * 1000)

            path = request.url.path
            if path in ("/health",):
                # skip logging, but do not return from finally
                pass
            else:
                tenant_id = getattr(request.state, "tenant_id", None)
                api_key_id = getattr(request.state, "api_key_id", None)
                status_code = response.status_code if response else 500

                request_id = getattr(request.state, "request_id", None) or ""
                user_agent = request.headers.get("user-agent") or ""
                client_ip = _get_client_ip(request)

                async with SessionLocal() as db:
                    db.add(
                        UsageEvent(
                            tenant_id=tenant_id,
                            api_key_id=api_key_id,
                            method=request.method,
                            path=path,
                            status_code=status_code,
                            latency_ms=latency_ms,
                            ts=datetime.now(timezone.utc),
                            request_id=request_id,
                            client_ip=client_ip,
                            user_agent=user_agent,
                        )
                    )
                    await db.commit()
