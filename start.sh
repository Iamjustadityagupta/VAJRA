#!/usr/bin/env bash
set -euo pipefail

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Review POSTGRES_PASSWORD before production use."
fi

docker compose up --build -d
printf '\nVAJRA is starting.\nFrontend: http://localhost:8080\nBackend:  http://localhost:8000/docs\n\n'
docker compose ps
