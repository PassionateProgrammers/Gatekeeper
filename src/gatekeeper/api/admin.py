import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func, case
from sqlalchemy.ext.asyncio import AsyncSession

from gatekeeper.deps.admin_auth import require_admin
from gatekeeper.deps.db import get_db
from gatekeeper.models.tenant import Tenant
from gatekeeper.models.api_key import ApiKey
from gatekeeper.models.usage_event import UsageEvent
from gatekeeper.core.keys import generate_plaintext_key, hash_key, key_prefix

router = APIRouter(prefix="/admin", tags=["admin"])


class TenantCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class TenantOut(BaseModel):
    id: uuid.UUID
    name: str


class ApiKeyCreateOut(BaseModel):
    key_id: uuid.UUID
    tenant_id: uuid.UUID
    key_prefix: str
    api_key: str


@router.post("/tenants", response_model=TenantOut, dependencies=[Depends(require_admin)])
async def create_tenant(payload: TenantCreateIn, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)

    existing = await db.execute(select(Tenant).where(Tenant.name == payload.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Tenant name already exists")

    tenant = Tenant(name=payload.name, created_at=now)
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return TenantOut(id=tenant.id, name=tenant.name)


@router.post("/tenants/{tenant_id}/keys", response_model=ApiKeyCreateOut, dependencies=[Depends(require_admin)])
async def create_api_key(tenant_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)

    tenant = await db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    plain = generate_plaintext_key()
    hashed = hash_key(plain)
    prefix = key_prefix(plain)

    existing = await db.execute(select(ApiKey).where(ApiKey.key_hash == hashed))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=500, detail="Key generation collision, retry")

    api_key = ApiKey(
        tenant_id=tenant_id,
        key_hash=hashed,
        key_prefix=prefix,
        created_at=now,
        revoked_at=None,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return ApiKeyCreateOut(
        key_id=api_key.id,
        tenant_id=tenant_id,
        key_prefix=prefix,
        api_key=plain,
    )


@router.post("/keys/{key_id}/revoke", dependencies=[Depends(require_admin)])
async def revoke_api_key(key_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)

    api_key = await db.get(ApiKey, key_id)
    if not api_key:
        raise HTTPException(status_code=404, detail="Key not found")

    if api_key.revoked_at is not None:
        return {"status": "already_revoked", "key_id": str(api_key.id)}

    api_key.revoked_at = now
    await db.commit()
    return {"status": "revoked", "key_id": str(api_key.id)}


# ---------------- NEW ----------------

@router.get("/tenants/{tenant_id}/keys", dependencies=[Depends(require_admin)])
async def list_api_keys(tenant_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ApiKey).where(ApiKey.tenant_id == tenant_id)
    )
    keys = result.scalars().all()

    return [
        {
            "id": k.id,
            "key_prefix": k.key_prefix,
            "revoked_at": k.revoked_at,
            "created_at": k.created_at,
        }
        for k in keys
    ]


@router.get("/tenants/{tenant_id}/usage/summary", dependencies=[Depends(require_admin)])
async def usage_summary(
    tenant_id: uuid.UUID,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
):
    if not to_ts:
        to_ts = datetime.now(timezone.utc)
    if not from_ts:
        from_ts = to_ts - timedelta(hours=24)

    result = await db.execute(
        select(
            UsageEvent.status_code,
            func.count().label("count"),
            func.avg(UsageEvent.latency_ms).label("avg_latency"),
        )
        .where(
            UsageEvent.tenant_id == tenant_id,
            UsageEvent.ts >= from_ts,
            UsageEvent.ts <= to_ts,
        )
        .group_by(UsageEvent.status_code)
    )

    rows = result.all()

    return {
        "from_ts": from_ts,
        "to_ts": to_ts,
        "by_status": {str(r.status_code): r.count for r in rows},
        "avg_latency_ms": round(
            sum((r.avg_latency or 0) for r in rows) / max(len(rows), 1), 2
        ),
    }

@router.get("/tenants/{tenant_id}/usage/top-endpoints", dependencies=[Depends(require_admin)])
async def top_endpoints(
    tenant_id: uuid.UUID,
    limit: int = 10,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
):
    if not to_ts:
        to_ts = datetime.now(timezone.utc)
    if not from_ts:
        from_ts = to_ts - timedelta(hours=24)

    result = await db.execute(
        select(
            UsageEvent.path,
            func.count().label("count"),
            func.sum(
                case((UsageEvent.status_code >= 400, 1), else_=0)
            ).label("errors"),
        )
        .where(
            UsageEvent.tenant_id == tenant_id,
            UsageEvent.ts >= from_ts,
            UsageEvent.ts <= to_ts,
        )
        .group_by(UsageEvent.path)
        .order_by(func.count().desc())
        .limit(limit)
    )

    rows = result.all()

    return [
        {
            "path": r.path,
            "count": r.count,
            "error_rate": round((r.errors or 0) / r.count, 2),
        }
        for r in rows
    ]
    
@router.get("/tenants/{tenant_id}/usage/by-key", dependencies=[Depends(require_admin)])
async def usage_by_key(
    tenant_id: uuid.UUID,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
):
    if not to_ts:
        to_ts = datetime.now(timezone.utc)
    if not from_ts:
        from_ts = to_ts - timedelta(hours=24)

    result = await db.execute(
        select(
            UsageEvent.api_key_id,
            func.count().label("count"),
            func.sum(
                case((UsageEvent.status_code >= 400, 1), else_=0)
            ).label("errors"),
        )
        .where(
            UsageEvent.tenant_id == tenant_id,
            UsageEvent.ts >= from_ts,
            UsageEvent.ts <= to_ts,
        )
        .group_by(UsageEvent.api_key_id)
        .order_by(func.count().desc())
    )

    rows = result.all()

    return [
        {
            "api_key_id": str(r.api_key_id),
            "count": r.count,
            "error_rate": round((r.errors or 0) / r.count, 2),
        }
        for r in rows
    ]
