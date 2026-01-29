from fastapi import APIRouter
from sqlalchemy import text
from gatekeeper.deps.db import engine
from gatekeeper.deps.redis import get_redis

router = APIRouter()


@router.get("/health")
async def health():
    # Check Postgres
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))

    # Check Redis
    r = await get_redis()
    pong = await r.ping()

    return {
        "status": "ok",
        "postgres": "ok",
        "redis": "ok" if pong else "unknown",
    }
