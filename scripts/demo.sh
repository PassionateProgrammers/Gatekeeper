#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-changeme}"

echo "== Health =="
curl -sS "${BASE_URL}/health" | jq .

echo "== Expect 401 (missing API key) =="
curl -i -sS "${BASE_URL}/protected" | head -n 20
echo

echo "== Create tenant =="
TENANT_JSON=$(curl -sS -X POST "${BASE_URL}/admin/tenants" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-tenant"}')
echo "$TENANT_JSON" | jq .
TENANT_ID=$(echo "$TENANT_JSON" | jq -r .id)

echo "== Create API key =="
KEY_JSON=$(curl -sS -X POST "${BASE_URL}/admin/tenants/${TENANT_ID}/keys" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}")
echo "$KEY_JSON" | jq .
API_KEY=$(echo "$KEY_JSON" | jq -r .api_key)

echo "== Expect 200 (valid API key) =="
curl -sS "${BASE_URL}/protected" -H "Authorization: Bearer ${API_KEY}" | jq .

echo "== Set tiny rate limit (3 per 60s) =="
curl -sS -X PATCH "${BASE_URL}/admin/keys/$(echo "$KEY_JSON" | jq -r .id)/limits" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"rate_limit":3,"rate_window":60}' | jq .

echo "== Trigger 429 by calling /protected repeatedly =="
for i in 1 2 3 4 5; do
  echo "--- request $i ---"
  curl -i -sS "${BASE_URL}/protected" -H "Authorization: Bearer ${API_KEY}" | head -n 20
  echo
done

echo "== Check analytics (tenant summary) =="
curl -sS "${BASE_URL}/admin/tenants/${TENANT_ID}/summary?window_seconds=3600" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" | jq .
