from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "VAJRA"
    version: str = "1.0.0"
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://vajra:vajra@db:5432/vajra")
    runs_dir: Path = Path(os.getenv("VAJRA_RUNS_DIR", "/app/runs"))
    max_upload_mb: int = int(os.getenv("VAJRA_MAX_UPLOAD_MB", "25"))
    max_archive_files: int = int(os.getenv("VAJRA_MAX_ARCHIVE_FILES", "500"))
    max_code_files: int = int(os.getenv("VAJRA_MAX_CODE_FILES", "200"))
    max_attempts: int = max(1, min(int(os.getenv("VAJRA_MAX_ATTEMPTS", "3")), 5))
    regression_timeout: int = int(os.getenv("VAJRA_REGRESSION_TIMEOUT", "45"))
    scan_timeout: int = int(os.getenv("VAJRA_SCAN_TIMEOUT", "30"))
    fuzz_seconds: int = int(os.getenv("VAJRA_FUZZ_SECONDS", "2"))
    llm_provider: str = os.getenv("LLM_PROVIDER", "demo")
    llm_api_key: str = os.getenv("LLM_API_KEY", "")
    llm_model: str = os.getenv("LLM_MODEL", "gpt-4.1-mini")
    cors_origins: str = os.getenv("VAJRA_CORS_ORIGINS", "http://localhost:8080,http://localhost:5173")


settings = Settings()
settings.runs_dir.mkdir(parents=True, exist_ok=True)
