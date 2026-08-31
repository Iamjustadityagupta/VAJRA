from __future__ import annotations

import json
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from config import settings
from db import get_run, init_db, save_run, update_run
from llm_reasoner import LLMReasoner
from pipeline import execute_run, safe_extract

app = FastAPI(
    title="VAJRA",
    version=settings.version,
    description="Autonomous adversarial vulnerability remediation agent.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="vajra-run")


@app.on_event("startup")
def startup() -> None:
    init_db()


def _prepare_upload(file: UploadFile, run_dir: Path, data: bytes) -> None:
    original = run_dir / "original"
    twin = run_dir / "vajra-twin"
    original.mkdir(parents=True, exist_ok=True)
    twin.mkdir(parents=True, exist_ok=True)
    filename = (file.filename or "").lower()
    upload = run_dir / "upload.bin"
    upload.write_bytes(data)
    if filename.endswith(".zip"):
        safe_extract(upload, original)
    elif filename.endswith(".py"):
        (original / "app.py").write_bytes(data)
    else:
        raise ValueError("Upload a .zip codebase archive or a Python .py file.")
    shutil.copytree(original, twin, dirs_exist_ok=True)


def _background_run(run_id: str, run_dir: Path) -> None:
    try:
        update_run(run_id, status="RUNNING")
        result = execute_run(run_id, run_dir)
        update_run(run_id, status=result.get("status", "FAILED"), evidence=result, completed=True)
    except Exception as exc:
        failure = {
            "run_id": run_id,
            "status": "FAILED",
            "events": [{"stage": "SYSTEM", "status": "fail", "message": f"Unhandled pipeline error: {exc}"}],
            "error": str(exc),
        }
        (run_dir / "evidence.json").write_text(json.dumps(failure, indent=2), encoding="utf-8")
        update_run(run_id, status="FAILED", evidence=failure, completed=True)


@app.get("/api/health")
def health() -> dict:
    db_ok = True
    db_error = None
    try:
        row = get_run("__health_probe__")
        _ = row
    except Exception as exc:
        db_ok = False
        db_error = str(exc)
    reasoner = LLMReasoner()
    return {
        "ok": db_ok,
        "service": settings.app_name,
        "version": settings.version,
        "database": "postgresql" if db_ok else "unavailable",
        "llm_mode": "live" if reasoner.live else "demo",
        "db_error": db_error,
    }


@app.get("/api/tools")
def tools() -> dict:
    return {
        "static_analysis": ["Semgrep", "Tree-sitter", "AST semantic rules"],
        "dependency_analysis": ["Syft SBOM", "OSV-Scanner"],
        "fuzzing": ["Atheris"],
        "reasoning": ["Code-capable LLM API", "Deterministic fallback"],
        "verification": ["pytest", "post-patch rescan", "adversarial replay"],
        "database": "PostgreSQL",
        "isolation": "Docker deployment boundary",
    }


@app.get("/api/llm-status")
def llm_status() -> dict:
    reasoner = LLMReasoner()
    return {
        "provider": reasoner.provider,
        "model": reasoner.model,
        "live": reasoner.live,
        "mode": "live" if reasoner.live else "demo",
    }


@app.post("/api/runs")
async def create_run(file: UploadFile = File(...)) -> dict:
    filename = file.filename or ""
    if not (filename.lower().endswith(".zip") or filename.lower().endswith(".py")):
        raise HTTPException(400, "Upload a .zip codebase archive or a Python .py file.")
    data = await file.read()
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if len(data) > max_bytes:
        raise HTTPException(413, f"Upload exceeds the {settings.max_upload_mb} MB limit.")

    run_id = "VAJRA-" + uuid.uuid4().hex[:8].upper()
    run_dir = settings.runs_dir / run_id
    try:
        _prepare_upload(file, run_dir, data)
        save_run(run_id, filename, "QUEUED", {"run_id": run_id, "status": "QUEUED", "filename": filename})
    except Exception as exc:
        shutil.rmtree(run_dir, ignore_errors=True)
        raise HTTPException(400, f"Invalid codebase: {exc}") from exc

    executor.submit(_background_run, run_id, run_dir)
    return {"run_id": run_id, "status": "QUEUED", "message": "VAJRA run accepted."}


@app.get("/api/runs/{run_id}")
def read_run(run_id: str) -> dict:
    row = get_run(run_id)
    if not row:
        raise HTTPException(404, "Run not found.")
    evidence = row.evidence()
    if evidence:
        return evidence
    return {"run_id": row.run_id, "status": row.status, "filename": row.filename}


@app.get("/api/runs/{run_id}/evidence")
def evidence(run_id: str):
    path = settings.runs_dir / run_id / "evidence.json"
    if not path.exists():
        raise HTTPException(404, "Evidence is not available yet.")
    return FileResponse(path, media_type="application/json", filename="evidence.json")


@app.get("/api/runs/{run_id}/report")
def report(run_id: str):
    path = settings.runs_dir / run_id / "evidence-report.html"
    if not path.exists():
        raise HTTPException(404, "Evidence report is not available yet.")
    return FileResponse(path, media_type="text/html", filename="evidence-report.html")


@app.get("/api/runs/{run_id}/patch-diff")
def patch_diff(run_id: str):
    path = settings.runs_dir / run_id / "patch.diff"
    if not path.exists():
        raise HTTPException(404, "Patch diff is not available for this run.")
    return FileResponse(path, media_type="text/plain", filename="patch.diff")


@app.get("/api/runs/{run_id}/verified-codebase")
def verified_codebase(run_id: str):
    path = settings.runs_dir / run_id / "verified-fixed-codebase.zip"
    if not path.exists():
        raise HTTPException(404, "Verified codebase is not available because this run is not verified.")
    return FileResponse(path, media_type="application/zip", filename="verified-fixed-codebase.zip")


@app.get("/api/runs")
def list_runs(limit: int = 20) -> list[dict]:
    # Deliberately keep the public API compact; detailed evidence stays in the run endpoint.
    limit = max(1, min(limit, 100))
    from db import SessionLocal, RunRecord
    with SessionLocal() as db:
        rows = db.query(RunRecord).order_by(RunRecord.created_at.desc()).limit(limit).all()
        return [
            {"run_id": r.run_id, "filename": r.filename, "status": r.status, "created_at": r.created_at.isoformat(), "completed_at": r.completed_at.isoformat() if r.completed_at else None}
            for r in rows
        ]
