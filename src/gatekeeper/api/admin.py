import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, func, case, desc
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


class ApiKeyLimitsIn(BaseModel):
    rate_limit: int = Field(ge=1, le=1_000_000)
    rate_window: int = Field(ge=1, le=86_400)


# NEW
class ApiKeyTierIn(BaseModel):
    tier: str = Field(min_length=1, max_length=32)


TIERS = {
    "free": {"rate_limit": 10, "rate_window": 60},
    "pro": {"rate_limit": 120, "rate_window": 60},
    "enterprise": {"rate_limit": 600, "rate_window": 60},
}


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


@router.post(
    "/tenants/{tenant_id}/keys",
    response_model=ApiKeyCreateOut,
    dependencies=[Depends(require_admin)],
)
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
        raise HTTPException(status_code=500, detail="Key generation collision")

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

    if api_key.revoked_at:
        return {"status": "already_revoked", "key_id": str(api_key.id)}

    api_key.revoked_at = now
    await db.commit()
    return {"status": "revoked", "key_id": str(api_key.id)}


@router.get("/tenants/{tenant_id}/keys", dependencies=[Depends(require_admin)])
async def list_api_keys(tenant_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ApiKey).where(ApiKey.tenant_id == tenant_id))
    keys = result.scalars().all()

    return [
        {
            "id": str(k.id),
            "key_prefix": k.key_prefix,
            "created_at": k.created_at,
            "revoked_at": k.revoked_at,
            "rate_limit": getattr(k, "rate_limit", None),
            "rate_window": getattr(k, "rate_window", None),
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
            func.sum(case((UsageEvent.status_code >= 400, 1), else_=0)).label("errors"),
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
            func.sum(case((UsageEvent.status_code >= 400, 1), else_=0)).label("errors"),
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


@router.get("/tenants/{tenant_id}/usage/status-classes", dependencies=[Depends(require_admin)])
async def usage_status_classes(
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
            func.sum(case((UsageEvent.status_code.between(200, 299), 1), else_=0)).label("2xx"),
            func.sum(case((UsageEvent.status_code.between(400, 499), 1), else_=0)).label("4xx"),
            func.sum(case((UsageEvent.status_code >= 500, 1), else_=0)).label("5xx"),
        )
        .where(
            UsageEvent.tenant_id == tenant_id,
            UsageEvent.ts >= from_ts,
            UsageEvent.ts <= to_ts,
        )
    )

    row = result.one()

    return {
        "from_ts": from_ts,
        "to_ts": to_ts,
        "2xx": row[0] or 0,
        "4xx": row[1] or 0,
        "5xx": row[2] or 0,
    }


@router.get("/tenants/{tenant_id}/usage/events", dependencies=[Depends(require_admin)])
async def list_usage_events(
    tenant_id: uuid.UUID,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)

    result = await db.execute(
        select(UsageEvent)
        .where(UsageEvent.tenant_id == tenant_id)
        .order_by(desc(UsageEvent.ts))
        .limit(limit)
        .offset(offset)
    )

    events = result.scalars().all()

    return [
        {
            "id": str(e.id),
            "ts": e.ts,
            "api_key_id": str(e.api_key_id) if e.api_key_id else None,
            "method": e.method,
            "path": e.path,
            "status_code": e.status_code,
            "latency_ms": e.latency_ms,
            "request_id": e.request_id,
            "client_ip": e.client_ip,
            "user_agent": e.user_agent,
        }
        for e in events
    ]


@router.post("/keys/{key_id}/limits", dependencies=[Depends(require_admin)])
async def set_key_limits(key_id: uuid.UUID, payload: ApiKeyLimitsIn, db: AsyncSession = Depends(get_db)):
    api_key = await db.get(ApiKey, key_id)
    if not api_key:
        raise HTTPException(status_code=404, detail="Key not found")

    api_key.rate_limit = payload.rate_limit
    api_key.rate_window = payload.rate_window
    await db.commit()
    await db.refresh(api_key)

    return {"status": "ok", "key_id": str(api_key.id), "rate_limit": api_key.rate_limit, "rate_window": api_key.rate_window}


@router.post("/keys/{key_id}/tier", dependencies=[Depends(require_admin)])
async def set_key_tier(key_id: uuid.UUID, payload: ApiKeyTierIn, db: AsyncSession = Depends(get_db)):
    tier = payload.tier.lower().strip()
    if tier not in TIERS:
        raise HTTPException(status_code=400, detail=f"Unknown tier: {tier}")

    api_key = await db.get(ApiKey, key_id)
    if not api_key:
        raise HTTPException(status_code=404, detail="Key not found")

    if api_key.revoked_at:
        raise HTTPException(status_code=409, detail="Key is revoked")

    api_key.rate_limit = TIERS[tier]["rate_limit"]
    api_key.rate_window = TIERS[tier]["rate_window"]
    await db.commit()
    await db.refresh(api_key)

    return {
        "status": "ok",
        "key_id": str(api_key.id),
        "tier": tier,
        "rate_limit": api_key.rate_limit,
        "rate_window": api_key.rate_window,
    }


def _resolve_timerange(from_ts: datetime | None, to_ts: datetime | None, default_hours: int = 24) -> tuple[datetime, datetime]:
    """Normalize timerange query params (UTC) and apply sane defaults."""
    if not to_ts:
        to_ts = datetime.now(timezone.utc)
    if not from_ts:
        from_ts = to_ts - timedelta(hours=default_hours)
    # Ensure tz-aware
    if from_ts.tzinfo is None:
        from_ts = from_ts.replace(tzinfo=timezone.utc)
    if to_ts.tzinfo is None:
        to_ts = to_ts.replace(tzinfo=timezone.utc)
    if from_ts > to_ts:
        raise HTTPException(status_code=400, detail="from_ts must be <= to_ts")
    return from_ts, to_ts


@router.get("/usage/unauth", dependencies=[Depends(require_admin)])
async def unauth_usage(
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    top_limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """Global view of unauthenticated traffic (tenant_id/api_key_id are NULL)."""
    from_ts, to_ts = _resolve_timerange(from_ts, to_ts, default_hours=24)
    top_limit = min(max(top_limit, 1), 50)

    base_where = (
        UsageEvent.tenant_id.is_(None),
        UsageEvent.ts >= from_ts,
        UsageEvent.ts <= to_ts,
    )

    total_result = await db.execute(select(func.count()).where(*base_where))
    total = int(total_result.scalar() or 0)

    by_status_result = await db.execute(
        select(
            UsageEvent.status_code,
            func.count().label("count"),
            func.avg(UsageEvent.latency_ms).label("avg_latency"),
        )
        .where(*base_where)
        .group_by(UsageEvent.status_code)
        .order_by(UsageEvent.status_code.asc())
    )
    by_status_rows = by_status_result.all()

    top_paths_result = await db.execute(
        select(
            UsageEvent.path,
            func.count().label("count"),
            func.sum(case((UsageEvent.status_code >= 400, 1), else_=0)).label("errors"),
        )
        .where(*base_where)
        .group_by(UsageEvent.path)
        .order_by(func.count().desc())
        .limit(top_limit)
    )
    top_paths_rows = top_paths_result.all()

    top_ips_result = await db.execute(
        select(
            UsageEvent.client_ip,
            func.count().label("count"),
            func.sum(case((UsageEvent.status_code == 401, 1), else_=0)).label("unauth_401"),
        )
        .where(*base_where)
        .group_by(UsageEvent.client_ip)
        .order_by(func.count().desc())
        .limit(top_limit)
    )
    top_ips_rows = top_ips_result.all()

    avg_latency_ms = 0.0
    if by_status_rows:
        avg_latency_ms = round(
            sum((r.avg_latency or 0) for r in by_status_rows) / max(len(by_status_rows), 1), 2
        )

    return {
        "from_ts": from_ts,
        "to_ts": to_ts,
        "total": total,
        "by_status": {str(r.status_code): int(r.count) for r in by_status_rows},
        "avg_latency_ms": avg_latency_ms,
        "top_paths": [
            {
                "path": r.path,
                "count": int(r.count),
                "error_rate": round((int(r.errors or 0)) / max(int(r.count), 1), 2),
            }
            for r in top_paths_rows
        ],
        "top_ips": [
            {
                "client_ip": r.client_ip,
                "count": int(r.count),
                "unauth_401": int(r.unauth_401 or 0),
            }
            for r in top_ips_rows
        ],
    }


@router.get("/abuse/suspects", dependencies=[Depends(require_admin)])
async def abuse_suspects(
    window_minutes: int = 10,
    min_unauth_401: int = 20,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Lightweight abuse detection: IPs with high unauth 401 volume in a rolling window."""
    window_minutes = min(max(window_minutes, 1), 24 * 60)
    min_unauth_401 = min(max(min_unauth_401, 1), 1_000_000)
    limit = min(max(limit, 1), 200)

    to_ts = datetime.now(timezone.utc)
    from_ts = to_ts - timedelta(minutes=window_minutes)

    base_where = (
        UsageEvent.tenant_id.is_(None),
        UsageEvent.status_code == 401,
        UsageEvent.ts >= from_ts,
        UsageEvent.ts <= to_ts,
    )

    suspects_result = await db.execute(
        select(
            UsageEvent.client_ip.label("client_ip"),
            func.count().label("unauth_401_count"),
            func.min(UsageEvent.ts).label("first_seen"),
            func.max(UsageEvent.ts).label("last_seen"),
        )
        .where(*base_where)
        .group_by(UsageEvent.client_ip)
        .having(func.count() >= min_unauth_401)
        .order_by(func.count().desc())
        .limit(limit)
    )
    suspects = suspects_result.all()

    ips = [s.client_ip for s in suspects]
    top_paths_by_ip: dict[str, list[dict]] = {ip: [] for ip in ips}

    if ips:
        paths_result = await db.execute(
            select(
                UsageEvent.client_ip.label("client_ip"),
                UsageEvent.path.label("path"),
                func.count().label("count"),
            )
            .where(*base_where, UsageEvent.client_ip.in_(ips))
            .group_by(UsageEvent.client_ip, UsageEvent.path)
            .order_by(UsageEvent.client_ip.asc(), func.count().desc())
        )
        rows = paths_result.all()

        # Keep top 3 paths per IP
        for r in rows:
            bucket = top_paths_by_ip.get(r.client_ip)
            if bucket is None:
                continue
            if len(bucket) >= 3:
                continue
            bucket.append({"path": r.path, "count": int(r.count)})

    return {
        "window_minutes": window_minutes,
        "from_ts": from_ts,
        "to_ts": to_ts,
        "min_unauth_401": min_unauth_401,
        "suspects": [
            {
                "client_ip": s.client_ip,
                "unauth_401_count": int(s.unauth_401_count),
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
                "top_paths": top_paths_by_ip.get(s.client_ip, []),
            }
            for s in suspects
        ],
    }
    
    
@router.get("/usage/rate-limited", dependencies=[Depends(require_admin)])
async def global_rate_limited_usage(
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    top_limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    from_ts, to_ts = _resolve_timerange(from_ts, to_ts)
    top_limit = min(max(top_limit, 1), 50)

    base_where = (
        UsageEvent.status_code == 429,
        UsageEvent.ts >= from_ts,
        UsageEvent.ts <= to_ts,
    )

    total = await db.scalar(select(func.count()).where(*base_where))

    top_paths = await db.execute(
        select(
            UsageEvent.path,
            func.count().label("count"),
        )
        .where(*base_where)
        .group_by(UsageEvent.path)
        .order_by(func.count().desc())
        .limit(top_limit)
    )

    by_tenant = await db.execute(
        select(
            UsageEvent.tenant_id,
            func.count().label("count"),
        )
        .where(*base_where, UsageEvent.tenant_id.is_not(None))
        .group_by(UsageEvent.tenant_id)
        .order_by(func.count().desc())
        .limit(top_limit)
    )

    return {
        "from_ts": from_ts,
        "to_ts": to_ts,
        "total_429": int(total or 0),
        "top_paths": [
            {"path": r.path, "count": int(r.count)}
            for r in top_paths.all()
        ],
        "by_tenant": [
            {"tenant_id": str(r.tenant_id), "count": int(r.count)}
            for r in by_tenant.all()
        ],
    }

@router.get(
    "/tenants/{tenant_id}/usage/rate-limited",
    dependencies=[Depends(require_admin)],
)
async def tenant_rate_limited_usage(
    tenant_id: uuid.UUID,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    top_limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    from_ts, to_ts = _resolve_timerange(from_ts, to_ts)
    top_limit = min(max(top_limit, 1), 50)

    base_where = (
        UsageEvent.tenant_id == tenant_id,
        UsageEvent.status_code == 429,
        UsageEvent.ts >= from_ts,
        UsageEvent.ts <= to_ts,
    )

    total = await db.scalar(select(func.count()).where(*base_where))

    by_key = await db.execute(
        select(
            UsageEvent.api_key_id,
            func.count().label("count"),
        )
        .where(*base_where, UsageEvent.api_key_id.is_not(None))
        .group_by(UsageEvent.api_key_id)
        .order_by(func.count().desc())
        .limit(top_limit)
    )

    top_paths = await db.execute(
        select(
            UsageEvent.path,
            func.count().label("count"),
        )
        .where(*base_where)
        .group_by(UsageEvent.path)
        .order_by(func.count().desc())
        .limit(top_limit)
    )

    return {
        "tenant_id": str(tenant_id),
        "from_ts": from_ts,
        "to_ts": to_ts,
        "total_429": int(total or 0),
        "by_key": [
            {"api_key_id": str(r.api_key_id), "count": int(r.count)}
            for r in by_key.all()
        ],
        "top_paths": [
            {"path": r.path, "count": int(r.count)}
            for r in top_paths.all()
        ],
    }

@router.get(
    "/tenants/{tenant_id}/keys/near-quota",
    dependencies=[Depends(require_admin)],
)
async def keys_near_quota(
    tenant_id: uuid.UUID,
    threshold: float = 0.8,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    if not (0 < threshold <= 1):
        raise HTTPException(status_code=400, detail="threshold must be (0, 1]")

    limit = min(max(limit, 1), 50)
    now = datetime.now(timezone.utc)

    keys = await db.execute(
        select(ApiKey).where(
            ApiKey.tenant_id == tenant_id,
            ApiKey.revoked_at.is_(None),
        )
    )
    keys = keys.scalars().all()

    results = []

    for key in keys:
        if not key.rate_limit or not key.rate_window:
            continue

        window_start = now - timedelta(seconds=key.rate_window)

        count = await db.scalar(
            select(func.count())
            .where(
                UsageEvent.api_key_id == key.id,
                UsageEvent.ts >= window_start,
            )
        )

        usage_ratio = (count or 0) / key.rate_limit

        if usage_ratio >= threshold:
            results.append(
                {
                    "api_key_id": str(key.id),
                    "key_prefix": key.key_prefix,
                    "requests_in_window": int(count or 0),
                    "rate_limit": key.rate_limit,
                    "utilization": round(usage_ratio, 2),
                }
            )

    results.sort(key=lambda r: r["utilization"], reverse=True)

    return {
        "tenant_id": str(tenant_id),
        "threshold": threshold,
        "keys": results[:limit],
    }
