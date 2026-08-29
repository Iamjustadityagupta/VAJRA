from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import difflib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zipfile

BASE = Path(__file__).resolve().parent.parent
RUNS = BASE / "runs"
RUNS.mkdir(exist_ok=True)

app = FastAPI(title="VAJRA Demo", version="0.2.0")
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


def semgrep_scan(root: Path):
    """Use Semgrep when installed; otherwise use the small POC detector."""
    cmd = ["semgrep", "--config", "p/python", "--json", "--quiet", str(root)]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, check=False
        )
        if completed.stdout.strip():
            obj = json.loads(completed.stdout)
            return obj.get("results", []), "semgrep"
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        pass
    return fallback_scan(root), "VAJRA-PYTHON-RULES"


def fallback_scan(root: Path):
    """Small deterministic detector for the included Python SQLi demo."""
    findings = []
    pattern = re.compile(
        r"execute\s*\(\s*query\s*\).*|query\s*=.*(?:\+\s*\w+)",
        re.IGNORECASE,
    )

    for path in root.rglob("*.py"):
        text = path.read_text(errors="ignore")
        if "request.args.get" in text and "execute(query)" in text and "+ name +" in text:
            line = next(
                (i for i, line_text in enumerate(text.splitlines(), 1) if "query =" in line_text),
                1,
            )
            findings.append(
                {
                    "check_id": "python.sql-injection",
                    "path": str(path.relative_to(root)),
                    "start": {"line": line},
                    "extra": {
                        "message": "User-controlled input is concatenated into a SQL query.",
                        "severity": "ERROR",
                    },
                }
            )
    return findings


def locate_vuln(root: Path, finding):
    rel = finding.get("path") or finding.get("location", {}).get("path") or "app.py"
    path = root / rel
    if not path.exists():
        candidates = list(root.rglob(Path(rel).name))
        if candidates:
            path = candidates[0]
    return path


def reproduce_with_flask(path: Path, payload: str):
    """Load the cloned Flask target and exercise the real endpoint in-process."""
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
            body = response.get_data(as_text=True)
            return "ALL USERS" in body, body
    finally:
        sys.modules.pop(module_name, None)


def reason_and_patch(path: Path, finding):
    text = path.read_text(errors="ignore")

    if "request.args.get" in text and "execute(query)" in text and "+ name +" in text:
        patched = text.replace(
            '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
            "    return db.execute(query)",
            '    query = "SELECT * FROM users WHERE name = ?"\n'
            "    return db.execute(query, (name,))",
            1,
        )
        if patched != text:
            return patched, {
                "title": "SQL Injection",
                "root_cause": "User-controlled input is concatenated directly into a SQL query.",
                "remediation": "Use a parameterized query so input is treated as data rather than SQL.",
                "confidence": "High",
            }

    return text, {
        "title": finding.get("check_id", "Security finding"),
        "root_cause": "Potentially unsafe data flow detected.",
        "remediation": "Apply a targeted security fix.",
        "confidence": "Medium",
    }


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
        return completed.returncode == 0, completed.stdout[-3000:] + completed.stderr[-1000:]
    except subprocess.TimeoutExpired:
        return False, "pytest timed out after 30 seconds."


def write_evidence(run_dir: Path, payload):
    (run_dir / "evidence.json").write_text(json.dumps(payload, indent=2))


@app.get("/api/health")
def health():
    return {"ok": True, "service": "VAJRA", "version": "0.2.0"}


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

    events = [
        emit(
            "SAFE CLONE",
            "pass",
            "Original codebase protected; VAJRA-TWIN created.",
            workspace=str(twin.relative_to(BASE)),
        )
    ]

    findings, engine = semgrep_scan(twin)
    if not findings:
        events.append(
            emit("DISCOVER", "pass", "No supported vulnerability detected.", count=0, engine=engine)
        )
        result = {
            "run_id": run_id,
            "events": events,
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
    events.append(
        emit(
            "DISCOVER",
            "pass",
            f"{message} ({rel}:{finding.get('start', {}).get('line', '?')})",
            count=len(findings),
            engine=engine,
            severity=severity,
            rule=finding.get("check_id"),
        )
    )

    payload = "' OR '1'='1"
    reproduced, reproduction_output = reproduce_with_flask(path, payload)
    events.append(
        emit(
            "REPRODUCE",
            "pass" if reproduced else "fail",
            "Original exploit reproduced successfully." if reproduced else "Exploit could not be reproduced.",
            payload=payload,
            target=rel,
            response=reproduction_output,
        )
    )

    if not reproduced:
        result = {"run_id": run_id, "events": events, "findings": [finding], "status": "FAILED"}
        write_evidence(run_dir, result)
        return result

    before = path.read_text(errors="ignore")
    patched, reasoning = reason_and_patch(path, finding)
    events.append(
        emit(
            "REASON",
            "pass",
            "Root cause identified and remediation strategy selected.",
            **reasoning,
        )
    )

    if patched == before:
        events.append(emit("PATCH", "fail", "Could not safely apply an automated patch in this POC."))
        result = {"run_id": run_id, "events": events, "findings": [finding], "status": "FAILED"}
        write_evidence(run_dir, result)
        return result

    path.write_text(patched)
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(True),
            patched.splitlines(True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )
    events.append(
        emit("PATCH", "pass", "Minimal targeted patch generated and applied to VAJRA-TWIN.", file=rel)
    )

    mutations = [
        payload,
        '" OR "1"="1',
        "' UNION SELECT NULL--",
        "admin'--",
    ]
    attack_results = []
    for attack_payload in mutations:
        exploitable, response = reproduce_with_flask(path, attack_payload)
        attack_results.append(
            {
                "payload": attack_payload,
                "status": "EXPLOITABLE" if exploitable else "BLOCKED",
                "response": response,
            }
        )

    attack_ok = all(item["status"] == "BLOCKED" for item in attack_results)
    events.append(
        emit(
            "ATTACK",
            "pass" if attack_ok else "fail",
            "Patch survived adversarial exploit replay."
            if attack_ok
            else "Patch still appears exploitable.",
            tests=attack_results,
        )
    )

    regression_ok, pytest_output = run_regression_tests(twin)
    events.append(
        emit(
            "VERIFY",
            "pass" if regression_ok and attack_ok else "fail",
            "Regression and security verification passed."
            if regression_ok and attack_ok
            else "Verification failed.",
            pytest_output=pytest_output,
            regression_tests=regression_ok,
        )
    )

    post_findings, post_engine = semgrep_scan(twin)
    remaining = len(post_findings)
    clean = remaining == 0
    events.append(
        emit(
            "RESCAN",
            "pass" if clean else "fail",
            f"Rescan complete: {remaining} findings remain.",
            remaining=remaining,
            engine=post_engine,
        )
    )

    status = "VERIFIED" if reproduced and attack_ok and regression_ok and clean else "FAILED"
    result = {
        "run_id": run_id,
        "events": events,
        "findings": [finding],
        "status": status,
        "diff": diff,
        "reasoning": reasoning,
        "attack_results": attack_results,
        "file": rel,
        "engine": engine,
    }
    write_evidence(run_dir, result)
    return result


@app.get("/api/runs/{run_id}/evidence")
def evidence(run_id: str):
    evidence_file = RUNS / run_id / "evidence.json"
    if not evidence_file.exists():
        raise HTTPException(404, "Run not found")
    return json.loads(evidence_file.read_text())
