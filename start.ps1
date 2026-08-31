$ErrorActionPreference = 'Stop'
if (-not (Test-Path .env)) {
  Copy-Item .env.example .env
  Write-Host "Created .env from .env.example. Review POSTGRES_PASSWORD before production use."
}
docker compose up --build -d
Write-Host ""
Write-Host "VAJRA is starting."
Write-Host "Frontend: http://localhost:8080"
Write-Host "Backend:  http://localhost:8000/docs"
Write-Host ""
docker compose ps
