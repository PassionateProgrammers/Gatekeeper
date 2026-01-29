import logging
from fastapi import FastAPI, Request
from gatekeeper.config import settings
from gatekeeper.logging import setup_logging
from gatekeeper.core.request_id import RequestIdMiddleware
from gatekeeper.api.health import router as health_router
from gatekeeper.api.admin import router as admin_router
from gatekeeper.api.gateway import router as gateway_router
from gatekeeper.deps.redis import close_redis


setup_logging(settings.log_level)
logger = logging.getLogger("gatekeeper")

app = FastAPI(title="Gatekeeper", version="0.1.0")

app.add_middleware(RequestIdMiddleware)
app.include_router(health_router)
app.include_router(admin_router)
app.include_router(gateway_router)

@app.on_event("shutdown")
async def shutdown():
    await close_redis()

@app.middleware("http")
async def inject_request_id_into_logs(request: Request, call_next):
    # Add request_id field to logs via extra dict
    request_id = getattr(request.state, "request_id", None)

    # Put it on request for handlers; logger adapter pattern is another option
    response = await call_next(request)

    # Note: we’re not logging per-request here yet; that comes later in usage logging
    if request_id:
        logger.info("request_completed", extra={"request_id": request_id})

    return response
