#!/bin/bash
# One-command deploy for wingobingo-proxy. Configuration is validated at start:
# a bad .env makes the container exit with the list of problems (docker compose logs proxy).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -f .env ]; then
  echo "Missing .env — copy .env.example and fill it in first." >&2
  exit 1
fi

echo "=== wingobingo-proxy: build & start ==="
docker compose up -d --build

echo "=== Waiting for health ==="
for _ in $(seq 1 30); do
  state="$(docker inspect -f '{{.State.Health.Status}}' wingobingo-proxy 2>/dev/null || echo starting)"
  if [ "$state" = "healthy" ]; then
    docker compose ps
    echo "=== Done. ==="
    exit 0
  fi
  sleep 2
done

echo "Proxy did not become healthy. Last log lines:" >&2
docker compose logs --tail 50 proxy >&2
exit 1
