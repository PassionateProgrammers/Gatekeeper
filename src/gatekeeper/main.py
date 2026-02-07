import logging
from fastapi import FastAPI, Request
from gatekeeper.config import settings
from gatekeeper.logging import setup_logging
from gatekeeper.core.request_id import RequestIdMiddleware
from gatekeeper.core.usage_logging import UsageLoggingMiddleware
from gatekeeper.api.health import router as health_router
from gatekeeper.api.admin import router as admin_router
from gatekeeper.api.gateway import router as gateway_router
from gatekeeper.deps.redis import close_redis


setup_logging(settings.log_level)
logger = logging.getLogger("gatekeeper")

app = FastAPI(title="Gatekeeper", version="0.1.0")

app.add_middleware(UsageLoggingMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(IPBlocklistMiddleware)
app.include_router(health_router)
app.include_router(admin_router)
app.include_router(gateway_router)

@app.on_event("shutdown")
async def shutdown():
    await close_redis()
