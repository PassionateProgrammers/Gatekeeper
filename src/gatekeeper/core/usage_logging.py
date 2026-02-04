import time
from datetime import datetime, timezone
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from gatekeeper.deps.db import SessionLocal
from gatekeeper.models.usage_event import UsageEvent


class UsageLoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs usage for requests that have tenant/api_key context attached
    (set by require_client_key).
    """

    async def dispatch(self, request: Request, call_next: Callable):
        start = time.perf_counter()
        response: Response | None = None

        try:
            response = await call_next(request)
            return response
        finally:
            # latency in ms
            latency_ms = int((time.perf_counter() - start) * 1000)

            tenant_id = getattr(request.state, "tenant_id", None)
            api_key_id = getattr(request.state, "api_key_id", None)

            # Only log requests that successfully resolved a key (or were rate-limited after resolving it)
            if not tenant_id or not api_key_id:
                return

            status_code = response.status_code if response is not None else 500

            # Optional: don’t log admin/health endpoints
            # (you can tweak this list however you want)
            path = request.url.path
            if path.startswith("/admin") or path.startswith("/health") or path.startswith("/docs") or path.startswith("/openapi.json"):
                return

            event = UsageEvent(
                tenant_id=tenant_id,
                api_key_id=api_key_id,
                method=request.method,
                path=path,
                status_code=status_code,
                latency_ms=latency_ms,
                ts=datetime.now(timezone.utc),
            )

            # Write it using a fresh session (middleware can't use Depends(get_db))
            async with SessionLocal() as session:
                session.add(event)
                await session.commit()
