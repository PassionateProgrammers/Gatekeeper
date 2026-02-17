#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-${GATEKEEPER_ADMIN_TOKEN:-}}"

if [[ -z "${ADMIN_TOKEN}" ]]; then
  echo "ERROR: Set ADMIN_TOKEN (or GATEKEEPER_ADMIN_TOKEN) env var to your admin token."
  echo "Example: ADMIN_TOKEN=changeme ./scripts/demo.sh"
  exit 1
fi

hdr() { echo; echo "== $* =="; }

hdr "Health"
curl -sS "${BASE_URL}/health"
echo

hdr "Expect 401 (missing API key)"
curl -i -sS "${BASE_URL}/protected" | head -n 20

hdr "Expect 401 (invalid API key)"
curl -i -sS "${BASE_URL}/protected" -H "Authorization: Bearer not-a-real-key" | head -n 20

hdr "Create tenant"
TENANT_JSON=$(curl -sS -X POST "${BASE_URL}/admin/tenants" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"demo-tenant"}')
echo "${TENANT_JSON}"
TENANT_ID=$(python -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "${TENANT_JSON}")

hdr "Create API key"
KEY_JSON=$(curl -sS -X POST "${BASE_URL}/admin/tenants/${TENANT_ID}/keys" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}")
echo "${KEY_JSON}"
KEY_ID=$(python -c "import json,sys; print(json.loads(sys.argv[1])['key_id'])" "${KEY_JSON}")
API_KEY=$(python -c "import json,sys; print(json.loads(sys.argv[1])['api_key'])" "${KEY_JSON}")

hdr "Call /whoami (valid key)"
curl -sS "${BASE_URL}/whoami" -H "Authorization: Bearer ${API_KEY}"
echo

hdr "Set key limits to 3 per 60s"
curl -sS -X POST "${BASE_URL}/admin/keys/${KEY_ID}/limits" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"rate_limit":3,"rate_window":60}'
echo

hdr "Trigger 429 by calling /protected 5 times"
for i in 1 2 3 4 5; do
  echo "--- request ${i} ---"
  curl -i -sS "${BASE_URL}/protected" -H "Authorization: Bearer ${API_KEY}" | head -n 20
  echo
done

hdr "Tenant usage summary (last 24h default)"
curl -sS "${BASE_URL}/admin/tenants/${TENANT_ID}/usage/summary" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Tenant top endpoints"
curl -sS "${BASE_URL}/admin/tenants/${TENANT_ID}/usage/top-endpoints?limit=10" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Tenant usage by key"
curl -sS "${BASE_URL}/admin/tenants/${TENANT_ID}/usage/by-key" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Unauth usage (should show 401s from earlier)"
curl -sS "${BASE_URL}/admin/usage/unauth?top_limit=5" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Global rate-limited usage (should show 429s)"
curl -sS "${BASE_URL}/admin/usage/rate-limited?top_limit=5" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Tenant rate-limited usage"
curl -sS "${BASE_URL}/admin/tenants/${TENANT_ID}/usage/rate-limited?top_limit=5" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Blocklist: block localhost IP (this may be protected)"
echo "NOTE: by default your auto-block endpoints avoid localhost; manual block-ip will still work."
curl -sS -X POST "${BASE_URL}/admin/abuse/block-ip" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"client_ip":"127.0.0.1","ttl_seconds":60,"reason_code":"manual","reason":"demo block"}'
echo

hdr "List blocked IPs"
curl -sS "${BASE_URL}/admin/abuse/blocked?limit=20" -H "X-Admin-Token: ${ADMIN_TOKEN}"
echo

hdr "Unblock localhost IP"
curl -sS -X POST "${BASE_URL}/admin/abuse/unblock-ip" \
  -H "X-Admin-Token: ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"client_ip":"127.0.0.1"}'
echo

hdr "Done"
