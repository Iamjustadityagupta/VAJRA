from llm_reasoner import LLMReasoner

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path
import ast
import difflib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv
    load_dotenv(BASE / ".env")
except ImportError:
    pass

RUNS = BASE / "runs"
RUNS.mkdir(exist_ok=True)

app = FastAPI(title="VAJRA Demo", version="0.6.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def emit(stage, status, message, **data):
    return {"stage": stage, "status": status, "message": message, **data}


def safe_extract(zip_path: Path, dest: Path):
    with zipfile.ZipFile(zip_path) as archive:
        dest_resolved = dest.resolve()
        for member in archive.infolist():
            target = (dest / member.filename).resolve()
            if not str(target).startswith(str(dest_resolved) + os.sep):
                raise ValueError("Unsafe archive path")
        archive.extractall(dest)


def fallback_scan(root: Path):
    findings = []
    for path in root.rglob("*.py"):
        text = path.read_text(errors="ignore")
        if "request.args.get" in text and "execute(query)" in text and "+ name +" in text:
            line = next(
                (i for i, value in enumerate(text.splitlines(), 1) if "query =" in value),
                1,
            )
            findings.append({
                "check_id": "python.sql-injection",
                "path": str(path.relative_to(root)),
                "start": {"line": line},
                "extra": {
                    "message": "User-controlled input is concatenated into a SQL query.",
                    "severity": "ERROR",
                },
            })
    return findings


def semgrep_scan(root: Path):
    cmd = ["semgrep", "--config", "p/python", "--json", "--quiet", str(root)]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if completed.stdout.strip():
            return json.loads(completed.stdout).get("results", []), "semgrep"
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass
    return fallback_scan(root), "VAJRA-PYTHON-RULES"


def locate_vuln(root: Path, finding):
    rel = finding.get("path") or finding.get("location", {}).get("path") or "app.py"
    path = root / rel
    if not path.exists():
        candidates = list(root.rglob(Path(rel).name))
        if candidates:
            path = candidates[0]
    return path


def reproduce_with_flask(path: Path, payload: str):
    module_name = f"vajra_target_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        return False, "Could not load target application."

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        if not hasattr(module, "app"):
            return False, "Target does not expose a Flask app."
        with module.app.test_client() as client:
            response = client.get("/user", query_string={"name": payload})
            body = response.get_json(silent=True)
            if body is None:
                return False, response.get_data(as_text=True)
            exploited = body.get("count", 0) >= 3
            return exploited, json.dumps(body)
    finally:
        sys.modules.pop(module_name, None)


def validate_patch_syntax(patched: str, path: Path):
    if path.suffix == ".py":
        ast.parse(patched, filename=str(path))


def reason_and_patch(path: Path, finding, reproduction, previous_attempt=None):
    source = path.read_text(errors="ignore")
    reasoner = LLMReasoner()
    result = reasoner.reason_and_patch(
        finding=finding,
        source=source,
        reproduction=reproduction,
        previous_attempt=previous_attempt,
    )
    patched = result.pop("patched_code")
    validate_patch_syntax(patched, path)
    result["mode"] = "live" if reasoner.live else "demo"
    result["model"] = reasoner.model if reasoner.live else "deterministic fallback"
    return patched, result


def run_regression_tests(twin: Path):
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=twin,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        output = completed.stdout[-3000:] + completed.stderr[-1000:]
        return completed.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "pytest timed out after 30 seconds."


def write_evidence(run_dir: Path, payload):
    (run_dir / "evidence.json").write_text(json.dumps(payload, indent=2))


def package_verified_codebase(twin: Path, run_dir: Path):
    archive = run_dir / "verified-fixed-codebase.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in twin.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and ".pytest_cache" not in path.parts:
                z.write(path, path.relative_to(twin))
    return archive


@app.get("/api/health")
def health():
    reasoner = LLMReasoner()
    return {
        "ok": True,
        "service": "VAJRA",
        "version": "0.6.0",
        "llm_mode": "live" if reasoner.live else "demo",
    }


@app.get("/api/llm-status")
def llm_status():
    reasoner = LLMReasoner()
    return {
        "provider": reasoner.provider,
        "model": reasoner.model,
        "live": reasoner.live,
        "mode": "live" if reasoner.live else "demo",
    }


@app.post("/api/demo/run")
async def run_demo(file: UploadFile = File(...)):
    run_id = "VAJRA-" + uuid.uuid4().hex[:8].upper()
    run_dir = RUNS / run_id
    original = run_dir / "original"
    twin = run_dir / "vajra-twin"
    original.mkdir(parents=True)
    twin.mkdir(parents=True)
    upload = run_dir / "upload.zip"

    try:
        upload.write_bytes(await file.read())
        safe_extract(upload, original)
        shutil.copytree(original, twin, dirs_exist_ok=True)
    except Exception as exc:
        raise HTTPException(400, f"Invalid codebase: {exc}") from exc

    events = [emit("SAFE CLONE", "pass", "Original codebase protected; VAJRA-TWIN created.")]
    findings, engine = semgrep_scan(twin)
    if not findings:
        result = {
            "run_id": run_id,
            "events": events + [emit("DISCOVER", "pass", "No supported vulnerability detected.", count=0, engine=engine)],
            "findings": [],
            "status": "CLEAN",
            "engine": engine,
        }
        write_evidence(run_dir, result)
        return result

    finding = findings[0]
    path = locate_vuln(twin, finding)
    rel = str(path.relative_to(twin))
    severity = finding.get("extra", {}).get("severity", "HIGH")
    message = finding.get("extra", {}).get("message", "Security vulnerability detected.")
    events.append(emit("DISCOVER", "pass", f"{message} ({rel}:{finding.get('start', {}).get('line', '?')})", count=len(findings), engine=engine, severity=severity, rule=finding.get("check_id")))

    payload = "' OR '1'='1"
    reproduced, reproduction_output = reproduce_with_flask(path, payload)
    reproduction = {"payload": payload, "response": reproduction_output, "exploitable": reproduced}
    events.append(emit("REPRODUCE", "pass" if reproduced else "fail", "Original exploit reproduced successfully." if reproduced else "Exploit could not be reproduced.", **reproduction, target=rel))
    if not reproduced:
        result = {"run_id": run_id, "events": events, "findings": [finding], "status": "FAILED"}
        write_evidence(run_dir, result)
        return result

    before = path.read_text(errors="ignore")
    max_attempts = max(1, min(int(os.getenv("VAJRA_MAX_ATTEMPTS", "2")), 3))
    attempt_history = []
    accepted = False
    final_reasoning = None
    final_diff = ""
    final_attack_results = []
    final_regression_ok = False
    final_pytest_output = ""
    previous_failure = None

    for attempt in range(1, max_attempts + 1):
        try:
            patched, reasoning = reason_and_patch(path, finding, reproduction, previous_failure)
        except Exception as exc:
            events.append(emit("REASON", "fail", f"Reasoning/patch generation failed: {exc}", attempt=attempt))
            break

        final_reasoning = reasoning
        events.append(emit("REASON", "pass", "Root cause identified and remediation strategy selected.", attempt=attempt, **reasoning))

        if patched == before:
            events.append(emit("PATCH", "fail", "Generated patch made no changes.", attempt=attempt))
            previous_failure = {"reason": "Patch made no changes."}
            continue

        path.write_text(patched)
        final_diff = "".join(difflib.unified_diff(before.splitlines(True), patched.splitlines(True), fromfile=f"a/{rel}", tofile=f"b/{rel}"))
        events.append(emit("PATCH", "pass", "Minimal targeted patch generated and applied to VAJRA-TWIN.", file=rel, attempt=attempt))

        mutations = [payload, '" OR "1"="1', "' UNION SELECT NULL--", "admin'--"]
        attack_results = []
        for attack_payload in mutations:
            exploitable, response = reproduce_with_flask(path, attack_payload)
            attack_results.append({"payload": attack_payload, "status": "EXPLOITABLE" if exploitable else "BLOCKED", "response": response})

        attack_ok = all(item["status"] == "BLOCKED" for item in attack_results)
        final_attack_results = attack_results
        events.append(emit("ATTACK", "pass" if attack_ok else "fail", "Patch survived adversarial exploit replay." if attack_ok else "Patch still appears exploitable.", tests=attack_results, attempt=attempt))
        if not attack_ok:
            previous_failure = {"attempt": attempt, "attack_results": attack_results, "reason": "At least one exploit remained effective."}
            path.write_text(before)
            attempt_history.append({"attempt": attempt, "status": "ATTACK_FAILED", "attack_results": attack_results})
            continue

        regression_ok, pytest_output = run_regression_tests(twin)
        final_regression_ok = regression_ok
        final_pytest_output = pytest_output
        events.append(emit("VERIFY", "pass" if regression_ok else "fail", "Regression and security verification passed." if regression_ok else "Regression verification failed.", pytest_output=pytest_output, regression_tests=regression_ok, attempt=attempt))
        if not regression_ok:
            previous_failure = {"attempt": attempt, "pytest_output": pytest_output, "reason": "Regression tests failed."}
            path.write_text(before)
            attempt_history.append({"attempt": attempt, "status": "VERIFY_FAILED", "pytest_output": pytest_output})
            continue

        accepted = True
        attempt_history.append({"attempt": attempt, "status": "PASSED"})
        break

    if not accepted:
        path.write_text(before)

    post_findings, post_engine = semgrep_scan(twin)
    remaining = len(post_findings)
    clean = remaining == 0
    events.append(emit("RESCAN", "pass" if clean and accepted else "fail", f"Rescan complete: {remaining} findings remain.", remaining=remaining, engine=post_engine))
    status = "VERIFIED" if accepted and clean else "FAILED"

    artifacts = {}
    if status == "VERIFIED":
        archive = package_verified_codebase(twin, run_dir)
        artifacts = {
            "verified_codebase": f"/api/runs/{run_id}/verified-codebase",
            "evidence_report": f"/api/runs/{run_id}/evidence",
        }

    result = {
        "run_id": run_id,
        "events": events,
        "findings": [finding],
        "status": status,
        "diff": final_diff,
        "reasoning": final_reasoning or {},
        "attack_results": final_attack_results,
        "file": rel,
        "engine": engine,
        "llm_mode": (final_reasoning or {}).get("mode", "demo"),
        "attempts": attempt_history,
        "max_attempts": max_attempts,
        "regression_tests": final_regression_ok,
        "pytest_output": final_pytest_output,
        "remaining_findings": remaining,
        "post_rescan_engine": post_engine,
        "artifacts": artifacts,
    }
    write_evidence(run_dir, result)
    return result


@app.get("/api/runs/{run_id}/evidence")
def evidence(run_id: str):
    evidence_file = RUNS / run_id / "evidence.json"
    if not evidence_file.exists():
        raise HTTPException(404, "Run not found")
    return FileResponse(evidence_file, media_type="application/json", filename=f"{run_id}-evidence.json")


@app.get("/api/runs/{run_id}/verified-codebase")
def verified_codebase(run_id: str):
    archive = RUNS / run_id / "verified-fixed-codebase.zip"
    if not archive.exists():
        raise HTTPException(404, "Verified codebase is not available for this run")
    return FileResponse(archive, media_type="application/zip", filename=f"{run_id}-verified-fixed-codebase.zip")
