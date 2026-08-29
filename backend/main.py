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
import re
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

app = FastAPI(title="VAJRA Demo", version="0.7.7")
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
    """Small multi-rule fallback scanner for the POC when Semgrep is absent."""
    findings = []
    for path in root.rglob("*.py"):
        text = path.read_text(errors="ignore")
        lines = text.splitlines()

        if "request.args.get" in text and "execute(query)" in text and "+ name +" in text:
            line = next((i for i, value in enumerate(lines, 1) if "query =" in value), 1)
            findings.append({
                "check_id": "python.sql-injection",
                "path": str(path.relative_to(root)),
                "start": {"line": line},
                "extra": {
                    "message": "User-controlled input is concatenated into a SQL query.",
                    "severity": "ERROR",
                },
            })

        if "subprocess" in text and "shell=True" in text and 'request.args.get("host"' in text:
            line = next((i for i, value in enumerate(lines, 1) if "shell=True" in value), 1)
            findings.append({
                "check_id": "python.command-injection",
                "path": str(path.relative_to(root)),
                "start": {"line": line},
                "extra": {
                    "message": "User-controlled input reaches a shell command executed with shell=True.",
                    "severity": "ERROR",
                },
            })
    return findings


def semgrep_scan(root: Path):
    cmd = ["semgrep", "--config", "p/python", "--json", "--quiet", str(root)]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        if completed.stdout.strip():
            results = json.loads(completed.stdout).get("results", [])
            # The POC fallback supplements Semgrep for the two deliberately seeded demo cases.
            fallback = fallback_scan(root)
            existing = {(r.get("check_id"), r.get("path"), r.get("start", {}).get("line")) for r in results}
            for item in fallback:
                key = (item["check_id"], item["path"], item["start"]["line"])
                if key not in existing:
                    results.append(item)
            return results, "semgrep + VAJRA rules"
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


def load_flask_module(path: Path):
    module_name = f"vajra_target_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        raise RuntimeError("Could not load target application.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module_name, module


def finding_kind(finding, path: Path | None = None):
    """Classify the finding using rule metadata and source evidence.

    Semgrep rule IDs vary by installation/version, so VAJRA does not rely on
    one exact check_id string for vulnerability-specific validation.
    """
    check_id = str(finding.get("check_id", "")).lower()
    message = str(finding.get("extra", {}).get("message", "")).lower()
    source = ""
    if path and path.exists():
        source = path.read_text(errors="ignore").lower()

    command_markers = (
        "command-injection", "command_injection", "shell=true",
        "subprocess", "os.system", "os.popen",
    )
    if any(marker in check_id or marker in message for marker in command_markers):
        return "command-injection"
    if any(marker in check_id or marker in message for marker in ("sql-injection", "sql_injection", "sqli")):
        return "sql-injection"
    if "subprocess" in source and ("shell=true" in source or "check_output(" in source or "run(" in source):
        return "command-injection"
    if "execute(query)" in source and "+ name +" in source:
        return "sql-injection"
    return "unknown"


def reproduce_finding(path: Path, finding, payload: str, kind: str | None = None):
    check_id = finding.get("check_id", "")
    module_name, module = load_flask_module(path)
    try:
        if not hasattr(module, "app"):
            return False, "Target does not expose a Flask app."
        with module.app.test_client() as client:
            if (kind or finding_kind(finding, path)) == "command-injection":
                response = client.get("/ping", query_string={"host": payload})
                body = response.get_json(silent=True)
                if body is None:
                    return False, response.get_data(as_text=True)
                # The injected marker appears as a second command's output.
                return "VAJRA_PWNED" in body.get("output", ""), json.dumps(body)

            response = client.get("/user", query_string={"name": payload})
            body = response.get_json(silent=True)
            if body is None:
                return False, response.get_data(as_text=True)
            # The seed database has exactly three records; returning all three proves SQLi.
            return body.get("count", 0) >= 3, json.dumps(body)
    except Exception as exc:
        return False, f"Target execution error: {exc}"
    finally:
        sys.modules.pop(module_name, None)


def exploit_payloads_for_kind(kind):
    if kind == "command-injection":
        return [
            "localhost; echo VAJRA_PWNED",
            "localhost && echo VAJRA_PWNED",
            "localhost | echo VAJRA_PWNED",
        ]
    if kind == "sql-injection":
        return [
            "' OR '1'='1",
            '" OR "1"="1',
            "' UNION SELECT NULL,NULL--",
            "admin'--",
        ]
    return []


def exploit_payloads(finding, path=None):
    return exploit_payloads_for_kind(finding_kind(finding, path))


def validate_patch_syntax(patched: str, path: Path):
    if path.suffix == ".py":
        ast.parse(patched, filename=str(path))


def patch_preflight(patched: str, kind: str):
    """Validate the candidate patch using the vulnerability class from the original finding."""
    if kind == "sql-injection":
        try:
            tree = ast.parse(patched)
        except SyntaxError as exc:
            return False, f"Patched Python is invalid: {exc}"

        source = patched
        if re.search(r"query\s*=.*\+\s*name", source, flags=re.DOTALL):
            return False, "SQL query still concatenates attacker-controlled input."

        # Accept common parameterized forms, not one exact database variable/call shape.
        parameterized = re.search(
            r"(?:execute|executemany)\s*\([^\n]*\?[^\n]*\)\s*|"
            r"(?:execute|executemany)\s*\([^\n]*query[^\n]*,\s*\([^\n]*name[^\n]*\)\s*\)",
            source,
            flags=re.IGNORECASE,
        )
        if not parameterized:
            return False, "Expected parameterized SQL binding was not detected."
        return True, "Parameterized SQL binding detected."

    if kind == "command-injection":
        try:
            tree = ast.parse(patched)
        except SyntaxError as exc:
            return False, f"Patched Python is invalid: {exc}"

        # Never accept a patch that still explicitly enables a shell.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return False, "Candidate patch still enables shell execution."

        # The command must no longer be assembled by concatenating the attacker-controlled host.
        if re.search(r"(?:command|cmd)\s*=.*\+\s*host", patched, flags=re.DOTALL | re.IGNORECASE):
            return False, "Candidate patch still builds a command by concatenating attacker-controlled host input."

        # Require the subprocess command to be represented as structured arguments.
        # We inspect the AST rather than matching one exact generated source string.
        subprocess_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"run", "call", "check_output", "check_call", "Popen"}:
                    subprocess_calls.append(node)

        if not subprocess_calls:
            return False, "No supported subprocess invocation was found after patching."

        for node in subprocess_calls:
            if not node.args:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.List, ast.Tuple)):
                return True, "Shell-free subprocess argument-list execution detected."

        return False, "Subprocess command must be passed as a list or tuple of arguments."

    return False, "VAJRA could not classify this finding for safe preflight validation." 


def run_regression_tests(twin: Path):
    """
    Run the target regression suite from inside the VAJRA-TWIN.

    The demo target is deliberately self-contained, so the preferred runner is
    pytest when it is available. If pytest cannot be invoked, use unittest
    discovery as a local fallback. A fallback is only considered successful
    when the tests themselves return success; runner errors are never treated
    as a pass.
    """
    commands = [
        ([sys.executable, "-m", "pytest", "-q"], "pytest"),
        ([sys.executable, "-m", "unittest", "discover", "-v"], "unittest"),
    ]

    diagnostics = []

    for command, runner_name in commands:
        try:
            completed = subprocess.run(
                command,
                cwd=twin,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            diagnostics.append(f"{runner_name}: timed out after 30 seconds.")
            continue
        except OSError as exc:
            diagnostics.append(f"{runner_name}: could not start runner: {exc}")
            continue

        output = (completed.stdout + completed.stderr).strip()
        diagnostics.append(
            f"[{runner_name}] exit code {completed.returncode}\n{output[-3000:]}"
        )

        if completed.returncode == 0:
            return True, "\n\n".join(diagnostics)

        # pytest can return 5 when no tests are collected. That is not proof
        # of a successful regression suite, so try the fallback runner.
        if runner_name == "pytest":
            continue

        return False, "\n\n".join(diagnostics)

    return False, "\n\n".join(diagnostics) or "No regression test runner could be executed."


def write_evidence(run_dir: Path, payload):
    (run_dir / "evidence.json").write_text(json.dumps(payload, indent=2))


def package_verified_codebase(twin: Path, run_dir: Path):
    archive = run_dir / "verified-fixed-codebase.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in twin.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and ".pytest_cache" not in path.parts:
                z.write(path, path.relative_to(twin))
    return archive


def apply_reasoned_patch(path, finding, reproduction, previous_failure=None):
    source = path.read_text(errors="ignore")
    reasoner = LLMReasoner()
    result = reasoner.reason_and_patch(finding, source, reproduction, previous_failure)
    patched = result.pop("patched_code")
    validate_patch_syntax(patched, path)
    result["mode"] = "live" if reasoner.live else "demo"
    result["model"] = reasoner.model if reasoner.live else "deterministic fallback"
    return source, patched, result


def process_finding(twin, finding, max_attempts):
    path = locate_vuln(twin, finding)
    rel = str(path.relative_to(twin))
    # Lock the vulnerability class BEFORE patching. Do not reclassify from patched source.
    kind = finding_kind(finding, path)
    payloads = exploit_payloads(finding, path)
    if not payloads:
        return {"accepted": False, "events": [emit("REPRODUCE", "fail", "No supported adversarial payloads are available for this finding.", kind=kind, attack_payload_count=0)], "finding": finding, "file": rel, "kind": kind, "attempts": [], "attack_results": []}
    payload = payloads[0]
    reproduced, reproduction_output = reproduce_finding(path, finding, payload, kind)
    reproduction = {"payload": payload, "response": reproduction_output, "exploitable": reproduced}
    events = [emit("REPRODUCE", "pass" if reproduced else "fail", "Original exploit reproduced successfully." if reproduced else "Exploit could not be reproduced.", **reproduction, target=rel, kind=kind, attack_payload_count=len(payloads))]

    if not reproduced:
        return {"accepted": False, "events": events, "finding": finding, "file": rel, "kind": kind, "attempts": [], "attack_results": []}

    original = path.read_text(errors="ignore")
    previous_failure = None
    attempts = []
    final_reasoning = None
    final_diff = ""
    final_attacks = []
    regression_ok = False
    pytest_output = ""

    for attempt in range(1, max_attempts + 1):
        try:
            before, patched, reasoning = apply_reasoned_patch(path, finding, reproduction, previous_failure)
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

        preflight_ok, preflight_message = patch_preflight(patched, kind)
        events.append(emit(
            "PATCH",
            "pass" if preflight_ok else "fail",
            "Patch preflight passed." if preflight_ok else "Patch rejected during preflight: " + preflight_message,
            preflight=preflight_ok,
            preflight_message=preflight_message,
            attempt=attempt,
        ))
        if not preflight_ok:
            previous_failure = {
                "attempt": attempt,
                "reason": "Patch preflight failed.",
                "preflight_message": preflight_message,
            }
            path.write_text(original)
            attempts.append({"attempt": attempt, "status": "PREFLIGHT_FAILED", "reason": preflight_message})
            continue

        attack_results = []
        attack_payloads = exploit_payloads_for_kind(kind)
        if not attack_payloads:
            events.append(emit("ATTACK", "fail", "No applicable adversarial payloads were generated."))
            previous_failure = {"attempt": attempt, "reason": "No applicable adversarial payloads were generated."}
            path.write_text(original)
            attempts.append({"attempt": attempt, "status": "NO_ATTACKS"})
            continue

        for attack_payload in attack_payloads:
            exploitable, response = reproduce_finding(path, finding, attack_payload, kind)
            attack_results.append({"payload": attack_payload, "status": "EXPLOITABLE" if exploitable else "BLOCKED", "response": response})

        attack_ok = bool(attack_results) and all(
            item["status"] == "BLOCKED" for item in attack_results
        )
        final_attacks = attack_results
        events.append(emit(
            "ATTACK",
            "pass" if attack_ok else "fail",
            "Patch survived adversarial exploit replay." if attack_ok else "Patch still appears exploitable.",
            tests=attack_results,
            attack_count=len(attack_results),
            blocked_count=sum(item["status"] == "BLOCKED" for item in attack_results),
            attempt=attempt,
        ))
        if not attack_ok:
            previous_failure = {"attempt": attempt, "attack_results": attack_results, "reason": "At least one exploit remained effective."}
            path.write_text(original)
            attempts.append({"attempt": attempt, "status": "ATTACK_FAILED", "attack_results": attack_results})
            continue

        regression_ok, pytest_output = run_regression_tests(twin)
        events.append(emit("VERIFY", "pass" if regression_ok else "fail", "Regression tests passed." if regression_ok else "Regression tests failed.", pytest_output=pytest_output, regression_tests=regression_ok, attempt=attempt))
        if not regression_ok:
            previous_failure = {"attempt": attempt, "pytest_output": pytest_output, "reason": "Regression tests failed."}
            path.write_text(original)
            attempts.append({"attempt": attempt, "status": "VERIFY_FAILED", "pytest_output": pytest_output})
            continue

        attempts.append({"attempt": attempt, "status": "PASSED"})
        return {
            "accepted": True,
            "kind": kind,
            "events": events,
            "finding": finding,
            "file": rel,
            "attempts": attempts,
            "reasoning": final_reasoning,
            "diff": final_diff,
            "attack_results": final_attacks,
            "regression_tests": True,
            "pytest_output": pytest_output,
        }

    path.write_text(original)
    return {
        "accepted": False,
        "events": events,
        "finding": finding,
        "file": rel,
        "kind": kind,
        "attempts": attempts,
        "reasoning": final_reasoning or {},
        "diff": final_diff,
        "attack_results": final_attacks,
        "regression_tests": regression_ok,
        "pytest_output": pytest_output,
    }


@app.get("/api/health")
def health():
    reasoner = LLMReasoner()
    return {"ok": True, "service": "VAJRA", "version": "0.7.7", "llm_mode": "live" if reasoner.live else "demo"}


@app.get("/api/llm-status")
def llm_status():
    reasoner = LLMReasoner()
    return {"provider": reasoner.provider, "model": reasoner.model, "live": reasoner.live, "mode": "live" if reasoner.live else "demo"}


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
    events.append(emit("DISCOVER", "pass" if findings else "pass", f"Discovered {len(findings)} supported finding(s).", count=len(findings), engine=engine, kinds=[finding_kind(f, locate_vuln(twin, f)) for f in findings]))

    if not findings:
        result = {"run_id": run_id, "events": events, "findings": [], "status": "CLEAN", "engine": engine}
        write_evidence(run_dir, result)
        return result

    max_attempts = max(1, min(int(os.getenv("VAJRA_MAX_ATTEMPTS", "2")), 3))
    processed = []
    overall_accepted = True
    for finding in findings:
        outcome = process_finding(twin, finding, max_attempts)
        processed.append(outcome)
        events.extend(outcome["events"])
        if not outcome["accepted"]:
            overall_accepted = False
            break

    post_findings, post_engine = semgrep_scan(twin)
    remaining = len(post_findings)
    clean = remaining == 0
    events.append(emit("RESCAN", "pass" if clean and overall_accepted else "fail", f"Rescan complete: {remaining} finding(s) remain.", remaining=remaining, engine=post_engine))

    status = "VERIFIED" if overall_accepted and clean else "FAILED"
    accepted_items = [item for item in processed if item["accepted"]]
    primary = accepted_items[-1] if accepted_items else processed[-1]
    all_attack_results = [attack for item in processed for attack in item.get("attack_results", [])]
    all_kinds = [item.get("kind", "unknown") for item in processed]
    artifacts = {}
    if status == "VERIFIED":
        package_verified_codebase(twin, run_dir)
        artifacts = {
            "verified_codebase": f"/api/runs/{run_id}/verified-codebase",
            "evidence_report": f"/api/runs/{run_id}/evidence",
        }

    result = {
        "run_id": run_id,
        "events": events,
        "findings": findings,
        "status": status,
        "diff": primary.get("diff", ""),
        "reasoning": primary.get("reasoning", {}),
        "attack_results": all_attack_results,
        "finding_kinds": all_kinds,
        "file": primary.get("file", ""),
        "engine": engine,
        "llm_mode": primary.get("reasoning", {}).get("mode", "demo"),
        "attempts": [attempt for item in processed for attempt in item.get("attempts", [])],
        "max_attempts": max_attempts,
        "regression_tests": all(item.get("regression_tests", False) for item in processed),
        "pytest_output": primary.get("pytest_output", ""),
        "remaining_findings": remaining,
        "post_rescan_engine": post_engine,
        "artifacts": artifacts,
        "processed_findings": processed,
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
