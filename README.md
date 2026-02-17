# Gatekeeper

Multi-tenant API gateway with API key authentication, rate limiting, and usage analytics.

## How To Run
docker compose up --build

## new terminal
curl http://localhost:8080/health

## run demo
docker compose down -v
docker compose up --build
ADMIN_TOKEN=dev-admin-token ./scripts/demo.sh

## run tests
ADMIN_TOKEN=dev-admin-token pytest -q
