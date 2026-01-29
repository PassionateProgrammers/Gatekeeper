#!/usr/bin/env sh
set -e

echo "Waiting for database..."
sleep 2

echo "Running database migrations..."
alembic -c /app/alembic.ini upgrade head

echo "Starting Gatekeeper API..."
exec uvicorn gatekeeper.main:app --host 0.0.0.0 --port 8080
