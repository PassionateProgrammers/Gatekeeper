import os
import time
import uuid
import pytest
import httpx

BASE_URL = os.getenv("BASE_URL", "http://localhost:8080")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

pytestmark = pytest.mark.asyncio


async def admin(client: httpx.AsyncClient, method: str, path: str, **kwargs):
    if not ADMIN_TOKEN:
        raise RuntimeError("Set ADMIN_TOKEN env var for tests.")
    headers = kwargs.pop("headers", {})
    headers["X-Admin-Token"] = ADMIN_TOKEN
    return await client.request(method, f"{BASE_URL}{path}", headers=headers, **kwargs)


@pytest.fixture
async def client():
    async with httpx.AsyncClient(timeout=10.0) as c:
        yield c


@pytest.fixture
async def tenant_and_key(client: httpx.AsyncClient):
    # unique tenant so re-runs never collide
    name = f"test-tenant-{int(time.time())}-{uuid.uuid4().hex[:6]}"

    r = await admin(client, "POST", "/admin/tenants", json={"name": name})
    assert r.status_code == 200, r.text
    tenant_id = r.json()["id"]

    r = await admin(client, "POST", f"/admin/tenants/{tenant_id}/keys")
    assert r.status_code == 200, r.text
    body = r.json()

    return {
        "tenant_id": tenant_id,
        "key_id": body["key_id"],
        "api_key": body["api_key"],
    }


async def test_missing_key_401(client: httpx.AsyncClient):
    r = await client.get(f"{BASE_URL}/protected")
    assert r.status_code == 401
    assert r.json()["detail"] == "Missing API key"


async def test_rate_limit_429(client: httpx.AsyncClient, tenant_and_key):
    key_id = tenant_and_key["key_id"]
    api_key = tenant_and_key["api_key"]

    # set tiny limit: 2 per 60s
    r = await admin(client, "POST", f"/admin/keys/{key_id}/limits", json={"rate_limit": 2, "rate_window": 60})
    assert r.status_code == 200, r.text

    headers = {"Authorization": f"Bearer {api_key}"}

    r1 = await client.get(f"{BASE_URL}/protected", headers=headers)
    r2 = await client.get(f"{BASE_URL}/protected", headers=headers)
    r3 = await client.get(f"{BASE_URL}/protected", headers=headers)

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
    assert r3.json()["detail"] == "Rate limit exceeded"


async def test_usage_summary_contains_200_and_429(client: httpx.AsyncClient, tenant_and_key):
    tenant_id = tenant_and_key["tenant_id"]
    key_id = tenant_and_key["key_id"]
    api_key = tenant_and_key["api_key"]

    # ensure tiny limit
    r = await admin(client, "POST", f"/admin/keys/{key_id}/limits", json={"rate_limit": 2, "rate_window": 60})
    assert r.status_code == 200, r.text

    headers = {"Authorization": f"Bearer {api_key}"}
    await client.get(f"{BASE_URL}/protected", headers=headers)
    await client.get(f"{BASE_URL}/protected", headers=headers)
    await client.get(f"{BASE_URL}/protected", headers=headers)  # should be 429

    # allow usage logging commit to settle (usually immediate, but tiny sleep avoids flake)
    await httpx.AsyncClient().aclose()
    time.sleep(0.2)

    r = await admin(client, "GET", f"/admin/tenants/{tenant_id}/usage/summary")
    assert r.status_code == 200, r.text
    data = r.json()["by_status"]

    # Should have at least one 200 and one 429 in the summary
    assert int(data.get("200", 0)) >= 1
    assert int(data.get("429", 0)) >= 1
