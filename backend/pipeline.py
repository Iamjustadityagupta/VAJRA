from __future__ import annotations

import ast
import difflib
import json
import os
import shutil
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Any

from analyzer import scan_codebase
from config import settings
from dependency_scanner import scan_dependencies
from evidence_report import write_report
from fuzzing import run_smoke_fuzz
from llm_reasoner import LLMReasoner


SUPPORTED = {"sql-injection", "command-injection"}


def emit(stage: str, status: str, message: str, **data: Any) -> dict[str, Any]:
    """Create a normalized pipeline event."""
    return {
        "stage": stage,
        "status": status,
        "message": message,
        **data,
    }


def safe_extract(zip_path: Path, dest: Path) -> None:
    """
    Safely extract an uploaded ZIP.

    Protections:
    - archive file-count limit
    - archive expansion limit
    - ZIP symlink rejection
    - path traversal protection
    - Python-file count limit
    """
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()

        if len(infos) > settings.max_archive_files:
            raise ValueError(
                f"Archive contains too many files "
                f"(limit: {settings.max_archive_files})."
            )

        root = dest.resolve()
        expanded = 0

        for member in infos:
            if member.is_dir():
                continue

            # Reject ZIP symbolic links.
            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(
                    "Symbolic links are not allowed in uploaded archives."
                )

            expanded += member.file_size

            if expanded > settings.max_upload_mb * 1024 * 1024 * 4:
                raise ValueError(
                    "Archive expands beyond the configured safety limit."
                )

            target = (dest / member.filename).resolve()

            # IMPORTANT:
            # pathlib.Path does not have Path.sep.
            # os.sep is the correct platform separator.
            if not str(target).startswith(str(root) + os.sep):
                raise ValueError("Unsafe archive path.")

        archive.extractall(dest)

    python_files = list(dest.rglob("*.py"))

    if len(python_files) > settings.max_code_files:
        raise ValueError(
            f"Too many Python files "
            f"(limit: {settings.max_code_files})."
        )


def _prepare_upload(
    file: Any,
    run_dir: Path,
    data: bytes,
) -> None:
    """
    Prepare an uploaded .py or .zip file.

    The original upload is retained under:
        run_dir/original/

    The working VAJRA-TWIN is created under:
        run_dir/vajra-twin/
    """
    original = run_dir / "original"
    twin = run_dir / "vajra-twin"

    original.mkdir(parents=True, exist_ok=True)
    twin.mkdir(parents=True, exist_ok=True)

    filename = Path(file.filename or "upload.py").name

    if not filename:
        filename = "upload.py"

    suffix = Path(filename).suffix.lower()

    if suffix not in {".zip", ".py"}:
        raise ValueError(
            "Only .zip codebase archives and Python .py files are supported."
        )

    uploaded_path = original / filename
    uploaded_path.write_bytes(data)

    if suffix == ".zip":
        safe_extract(uploaded_path, twin)

        # Reject archives that contain no Python code.
        if not list(twin.rglob("*.py")):
            raise ValueError(
                "The uploaded archive does not contain any Python files."
            )

    elif suffix == ".py":
        shutil.copy2(uploaded_path, twin / filename)


def locate_vuln(root: Path, finding: dict[str, Any]) -> Path:
    """Resolve a finding path safely inside the VAJRA-TWIN."""
    rel = finding.get("path") or finding.get("location", {}).get("path")

    if not rel:
        raise ValueError("Finding has no source path.")

    root_resolved = root.resolve()
    path = (root_resolved / rel).resolve()

    # IMPORTANT:
    # Path.sep is invalid. Use os.sep.
    if not str(path).startswith(str(root_resolved) + os.sep):
        raise ValueError("Finding path escaped target root.")

    if not path.exists():
        candidates = list(root.rglob(Path(rel).name))

        if candidates:
            path = candidates[0]

    if not path.exists():
        raise FileNotFoundError(rel)

    return path


def finding_kind(finding: dict[str, Any]) -> str:
    """Determine the supported vulnerability class."""
    metadata = finding.get("extra", {}).get("metadata", {})
    kind = metadata.get("kind")

    if kind in SUPPORTED:
        return kind

    text = " ".join(
        [
            str(finding.get("check_id", "")),
            str(finding.get("extra", {}).get("message", "")),
        ]
    ).lower()

    if any(
        x in text
        for x in (
            "command-injection",
            "command_injection",
            "shell",
            "subprocess",
        )
    ):
        return "command-injection"

    if any(
        x in text
        for x in (
            "sql-injection",
            "sql_injection",
            "sqli",
        )
    ):
        return "sql-injection"

    return "unknown"


def reproduce_finding(
    path: Path,
    finding: dict[str, Any],
    payload: str,
    kind: str,
) -> tuple[bool, str]:
    """
    Reproduce a finding using the isolated target runner.

    The target runner loads the Flask application and exercises
    the vulnerable endpoint using the metadata produced by the
    analyzer.
    """
    metadata = finding.get("extra", {}).get("metadata", {})

    runner = Path(__file__).with_name("target_runner.py")

    command = [
        sys.executable,
        str(runner),
        str(path),
        json.dumps(metadata),
        payload,
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=path.parent,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "Target execution timed out."
    except OSError as exc:
        return False, f"Target execution failed to start: {exc}"

    raw = completed.stdout.strip().splitlines()

    record: dict[str, Any] = {}

    if raw:
        try:
            record = json.loads(raw[-1])
        except json.JSONDecodeError:
            record = {
                "body": "\n".join(raw[-20:])
            }

    body = str(record.get("body", ""))
    status_code = int(record.get("status_code", 500))

    # Command injection:
    # our controlled payload causes the target to emit this marker.
    if kind == "command-injection":
        return "VAJRA_CMD_MARKER" in body, body

    # SQL injection:
    # server/database errors are one strong reproduction signal.
    lowered = body.lower()

    if status_code >= 500 and any(
        x in lowered
        for x in (
            "sql",
            "syntax",
            "sqlite",
            "database",
        )
    ):
        return True, body

    # Otherwise compare the injected response with a benign baseline.
    try:
        baseline = subprocess.run(
            [
                sys.executable,
                str(runner),
                str(path),
                json.dumps(metadata),
                "VAJRA_NONEXISTENT_VALUE",
            ],
            cwd=path.parent,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        base_lines = baseline.stdout.strip().splitlines()

        base: dict[str, Any] = {}

        if base_lines:
            try:
                base = json.loads(base_lines[-1])
            except json.JSONDecodeError:
                base = {}

        base_body = str(base.get("body", ""))

        injected_json = json.loads(body) if body else None
        baseline_json = (
            json.loads(base_body)
            if base_body
            else None
        )

        if (
            isinstance(injected_json, dict)
            and isinstance(baseline_json, dict)
            and injected_json != baseline_json
        ):
            for key in (
                "count",
                "users",
                "results",
                "data",
                "items",
            ):
                if (
                    key in injected_json
                    and key in baseline_json
                    and injected_json[key]
                    != baseline_json[key]
                ):
                    return True, body

        if (
            isinstance(injected_json, list)
            and isinstance(baseline_json, list)
            and len(injected_json) > len(baseline_json)
        ):
            return True, body

        if (
            status_code
            == int(base.get("status_code", 500))
            == 200
            and body != base_body
        ):
            return True, body

    except Exception:
        pass

    return (
        False,
        body
        or str(
            record.get(
                "error",
                "Target returned no body.",
            )
        ),
    )


def exploit_payloads_for_kind(
    kind: str,
) -> list[str]:
    """Return bounded adversarial payloads."""
    if kind == "command-injection":
        return [
            "localhost; echo VAJRA_CMD_MARKER",
            "localhost && echo VAJRA_CMD_MARKER",
            "localhost | echo VAJRA_CMD_MARKER",
        ]

    if kind == "sql-injection":
        return [
            "' OR '1'='1",
            '" OR "1"="1',
            "' UNION SELECT NULL,NULL--",
            "admin'--",
        ]

    return []


def patch_preflight(
    patched: str,
    kind: str,
) -> tuple[bool, str]:
    """
    Perform deterministic validation of an AI-generated patch.
    """
    try:
        tree = ast.parse(patched)
    except SyntaxError as exc:
        return (
            False,
            f"Patched Python is invalid: {exc}",
        )

    if kind == "sql-injection":
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Attribute):
                continue

            if node.func.attr not in {
                "execute",
                "executemany",
            }:
                continue

            # Parameterized query.
            if len(node.args) >= 2:
                return (
                    True,
                    "SQL execution uses a separate parameter argument.",
                )

            # Constant query.
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                return (
                    True,
                    "SQL execution uses a constant query string.",
                )

        return (
            False,
            "Could not prove that attacker-controlled SQL is parameterized.",
        )

    if kind == "command-injection":
        # shell=True must not survive the patch.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    return (
                        False,
                        "Candidate patch still enables shell execution.",
                    )

        subprocess_calls = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Attribute):
                continue

            if not isinstance(node.func.value, ast.Name):
                continue

            if node.func.value.id != "subprocess":
                continue

            if node.func.attr not in {
                "run",
                "call",
                "check_output",
                "check_call",
                "Popen",
            }:
                continue

            subprocess_calls.append(node)

        if not subprocess_calls:
            return (
                False,
                "No supported shell-execution replacement was found.",
            )

        if any(
            node.args
            and isinstance(
                node.args[0],
                (ast.List, ast.Tuple),
            )
            for node in subprocess_calls
        ):
            return (
                True,
                "Shell-free structured subprocess arguments detected.",
            )

        return (
            False,
            "Subprocess command must use structured list/tuple arguments.",
        )

    return (
        False,
        "Unsupported vulnerability class.",
    )


def run_regression_tests(
    twin: Path,
) -> tuple[bool, str]:
    """
    Run supplied pytest tests.

    If no test suite exists, compile the Python codebase instead.
    """
    test_files = (
        list(twin.rglob("test_*.py"))
        + list(twin.rglob("*_test.py"))
    )

    if test_files:
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                ],
                cwd=twin,
                capture_output=True,
                text=True,
                timeout=settings.regression_timeout,
                check=False,
            )

            output = (
                result.stdout
                + result.stderr
            ).strip()

            return (
                result.returncode == 0,
                (
                    f"[pytest] exit code "
                    f"{result.returncode}\n"
                    f"{output[-6000:]}"
                ),
            )

        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as exc:
            return (
                False,
                f"[pytest] could not complete: {exc}",
            )

    compile_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            ".",
        ],
        cwd=twin,
        capture_output=True,
        text=True,
        check=False,
    )

    output = (
        compile_result.stdout
        + compile_result.stderr
    ).strip()

    if compile_result.returncode == 0:
        return (
            True,
            "[regression] No test suite was supplied; "
            "all Python files passed compile validation.",
        )

    return (
        False,
        "[regression] Python compile validation failed.\n"
        + output[-6000:],
    )


def apply_reasoned_patch(
    path: Path,
    finding: dict[str, Any],
    reproduction: dict[str, Any],
    previous_failure: dict[str, Any] | None,
):
    """
    Ask the reasoning layer for a patch and validate Python syntax.
    """
    source = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    reasoner = LLMReasoner()

    result = reasoner.reason_and_patch(
        finding,
        source,
        reproduction,
        previous_failure,
    )

    patched = result.pop("patched_code")

    ast.parse(
        patched,
        filename=str(path),
    )

    result["mode"] = (
        "live"
        if reasoner.live
        else "demo"
    )

    result["model"] = (
        reasoner.model
        if reasoner.live
        else "deterministic fallback"
    )

    return (
        source,
        patched,
        result,
    )


def process_finding(
    twin: Path,
    finding: dict[str, Any],
    max_attempts: int,
) -> dict[str, Any]:
    """Process one supported vulnerability finding."""
    path = locate_vuln(
        twin,
        finding,
    )

    rel = str(
        path.relative_to(twin)
    ).replace("\\", "/")

    kind = finding_kind(finding)

    payloads = exploit_payloads_for_kind(kind)

    if not payloads:
        return {
            "accepted": False,
            "finding": finding,
            "file": rel,
            "kind": kind,
            "events": [
                emit(
                    "REPRODUCE",
                    "fail",
                    "No supported adversarial payloads "
                    "are available for this finding.",
                    kind=kind,
                )
            ],
            "attempts": [],
            "attack_results": [],
        }

    # ---------------------------------------------------------
    # REPRODUCE
    # ---------------------------------------------------------

    reproduction_payload = payloads[0]

    reproduced, reproduction_output = reproduce_finding(
        path,
        finding,
        reproduction_payload,
        kind,
    )

    reproduction = {
        "payload": reproduction_payload,
        "response": reproduction_output,
        "exploitable": reproduced,
    }

    events = [
        emit(
            "REPRODUCE",
            "pass" if reproduced else "fail",
            (
                "Original exploit reproduced successfully."
                if reproduced
                else "Exploit could not be reproduced."
            ),
            **reproduction,
            target=rel,
            kind=kind,
            attack_payload_count=len(payloads),
        )
    ]

    if not reproduced:
        return {
            "accepted": False,
            "finding": finding,
            "file": rel,
            "kind": kind,
            "events": events,
            "attempts": [],
            "attack_results": [],
        }

    # Keep the original vulnerable source in memory so failed
    # remediation attempts can be rolled back.
    original = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    attempts: list[dict[str, Any]] = []
    previous_failure = None

    final_reasoning: dict[str, Any] = {}
    final_diff = ""
    final_attacks: list[dict[str, Any]] = []

    regression_ok = False
    regression_output = ""

    # ---------------------------------------------------------
    # REMEDIATION LOOP
    # ---------------------------------------------------------

    for attempt in range(
        1,
        max_attempts + 1,
    ):
        try:
            before, patched, reasoning = apply_reasoned_patch(
                path,
                finding,
                reproduction,
                previous_failure,
            )

        except Exception as exc:
            attempts.append(
                {
                    "attempt": attempt,
                    "status": "REASON_FAILED",
                    "reason": str(exc),
                }
            )

            events.append(
                emit(
                    "REASON",
                    "fail",
                    (
                        "Reasoning/patch generation "
                        f"failed: {exc}"
                    ),
                    attempt=attempt,
                )
            )

            previous_failure = {
                "attempt": attempt,
                "reason": str(exc),
            }

            continue

        final_reasoning = reasoning

        events.append(
            emit(
                "REASON",
                "pass",
                "Root cause identified and remediation "
                "strategy selected.",
                attempt=attempt,
                **reasoning,
            )
        )

        if patched == before:
            attempts.append(
                {
                    "attempt": attempt,
                    "status": "NO_CHANGE",
                }
            )

            previous_failure = {
                "attempt": attempt,
                "reason": "Patch made no changes.",
            }

            events.append(
                emit(
                    "PATCH",
                    "fail",
                    "Generated patch made no changes.",
                    attempt=attempt,
                )
            )

            continue

        # Apply only to VAJRA-TWIN.
        path.write_text(
            patched,
            encoding="utf-8",
        )

        final_diff = "".join(
            difflib.unified_diff(
                before.splitlines(True),
                patched.splitlines(True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
            )
        )

        events.append(
            emit(
                "PATCH",
                "pass",
                "Targeted patch generated and applied "
                "to VAJRA-TWIN.",
                file=rel,
                attempt=attempt,
            )
        )

        # -----------------------------------------------------
        # PREFLIGHT
        # -----------------------------------------------------

        preflight_ok, preflight_message = patch_preflight(
            patched,
            kind,
        )

        events.append(
            emit(
                "PREFLIGHT",
                "pass" if preflight_ok else "fail",
                (
                    "Patch preflight passed."
                    if preflight_ok
                    else (
                        "Patch rejected: "
                        f"{preflight_message}"
                    )
                ),
                preflight=preflight_ok,
                preflight_message=preflight_message,
                attempt=attempt,
            )
        )

        if not preflight_ok:
            path.write_text(
                original,
                encoding="utf-8",
            )

            attempts.append(
                {
                    "attempt": attempt,
                    "status": "PREFLIGHT_FAILED",
                    "reason": preflight_message,
                }
            )

            previous_failure = {
                "attempt": attempt,
                "reason": "Patch preflight failed.",
                "preflight_message": preflight_message,
            }

            continue

        # -----------------------------------------------------
        # ADVERSARIAL ATTACK
        # -----------------------------------------------------

        attack_results = []

        for attack_payload in payloads:
            exploitable, response = reproduce_finding(
                path,
                finding,
                attack_payload,
                kind,
            )

            attack_results.append(
                {
                    "payload": attack_payload,
                    "status": (
                        "EXPLOITABLE"
                        if exploitable
                        else "BLOCKED"
                    ),
                    "response": response,
                }
            )

        final_attacks = attack_results

        attack_ok = (
            bool(attack_results)
            and all(
                item["status"] == "BLOCKED"
                for item in attack_results
            )
        )

        events.append(
            emit(
                "ATTACK",
                "pass" if attack_ok else "fail",
                (
                    "Patch survived adversarial "
                    "exploit replay."
                    if attack_ok
                    else "Patch still appears exploitable."
                ),
                tests=attack_results,
                attack_count=len(attack_results),
                blocked_count=sum(
                    item["status"] == "BLOCKED"
                    for item in attack_results
                ),
                attempt=attempt,
            )
        )

        if not attack_ok:
            path.write_text(
                original,
                encoding="utf-8",
            )

            attempts.append(
                {
                    "attempt": attempt,
                    "status": "ATTACK_FAILED",
                    "attack_results": attack_results,
                }
            )

            previous_failure = {
                "attempt": attempt,
                "reason": (
                    "At least one exploit "
                    "remained effective."
                ),
                "attack_results": attack_results,
            }

            continue

        # -----------------------------------------------------
        # REGRESSION
        # -----------------------------------------------------

        regression_ok, regression_output = run_regression_tests(
            twin
        )

        events.append(
            emit(
                "REGRESSION",
                "pass" if regression_ok else "fail",
                (
                    "Regression tests passed."
                    if regression_ok
                    else "Regression tests failed."
                ),
                regression_tests=regression_ok,
                regression_output=regression_output,
                attempt=attempt,
            )
        )

        if not regression_ok:
            path.write_text(
                original,
                encoding="utf-8",
            )

            attempts.append(
                {
                    "attempt": attempt,
                    "status": "REGRESSION_FAILED",
                    "regression_output": regression_output,
                }
            )

            previous_failure = {
                "attempt": attempt,
                "reason": "Regression tests failed.",
                "regression_output": regression_output,
            }

            continue

        # Successful remediation.
        attempts.append(
            {
                "attempt": attempt,
                "status": "PASSED",
            }
        )

        return {
            "accepted": True,
            "finding": finding,
            "file": rel,
            "kind": kind,
            "events": events,
            "attempts": attempts,
            "reasoning": final_reasoning,
            "diff": final_diff,
            "attack_results": final_attacks,
            "regression_tests": True,
            "regression_output": regression_output,
        }

    # All attempts failed.
    path.write_text(
        original,
        encoding="utf-8",
    )

    return {
        "accepted": False,
        "finding": finding,
        "file": rel,
        "kind": kind,
        "events": events,
        "attempts": attempts,
        "reasoning": final_reasoning,
        "diff": final_diff,
        "attack_results": final_attacks,
        "regression_tests": regression_ok,
        "regression_output": regression_output,
    }


def write_evidence(
    run_dir: Path,
    payload: dict[str, Any],
) -> None:
    """Write machine-readable evidence."""
    (run_dir / "evidence.json").write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )


def package_verified_codebase(
    twin: Path,
    run_dir: Path,
) -> Path:
    """Package the successfully verified VAJRA-TWIN."""
    archive = (
        run_dir
        / "verified-fixed-codebase.zip"
    )

    with zipfile.ZipFile(
        archive,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as z:
        for path in twin.rglob("*"):
            if not path.is_file():
                continue

            if any(
                x in path.parts
                for x in (
                    "__pycache__",
                    ".pytest_cache",
                    ".git",
                )
            ):
                continue

            z.write(
                path,
                path.relative_to(twin),
            )

    return archive


def execute_run(
    run_id: str,
    run_dir: Path,
) -> dict[str, Any]:
    """
    Execute the complete VAJRA remediation pipeline.
    """
    original = run_dir / "original"
    twin = run_dir / "vajra-twin"

    events = [
        emit(
            "SAFE CLONE",
            "pass",
            "Original codebase protected; "
            "VAJRA-TWIN created.",
        )
    ]

    # ---------------------------------------------------------
    # DISCOVER
    # ---------------------------------------------------------

    findings, scan_meta = scan_codebase(
        twin,
        settings.scan_timeout,
    )

    supported = [
        finding
        for finding in findings
        if finding_kind(finding) in SUPPORTED
    ]

    unsupported_count = (
        len(findings)
        - len(supported)
    )

    events.append(
        emit(
            "DISCOVER",
            "pass",
            (
                f"Discovered {len(supported)} "
                "supported finding(s)."
            ),
            count=len(supported),
            unsupported_findings=unsupported_count,
            engine=scan_meta["engine"],
            scanner=scan_meta,
        )
    )

    # ---------------------------------------------------------
    # DEPENDENCY ANALYSIS
    # ---------------------------------------------------------

    dependencies = scan_dependencies(twin)

    dependency_available = (
        dependencies.get("syft", {}).get("ok")
        or dependencies.get(
            "osv_scanner",
            {},
        ).get("ok")
    )

    events.append(
        emit(
            "DEPENDENCY",
            "pass",
            (
                "Dependency/SBOM analysis completed."
                if dependency_available
                else (
                    "Dependency scanners unavailable; "
                    "core analysis continues."
                )
            ),
            scanners=dependencies,
        )
    )

    # ---------------------------------------------------------
    # FUZZ
    # ---------------------------------------------------------

    fuzz = run_smoke_fuzz(
        twin,
        settings.fuzz_seconds,
    )

    events.append(
        emit(
            "FUZZ",
            "pass" if fuzz.get("ok") else "fail",
            (
                "Atheris smoke fuzzing completed."
                if fuzz.get("ok")
                else (
                    "Atheris smoke fuzzing "
                    "unavailable or failed."
                )
            ),
            fuzz=fuzz,
        )
    )

    # ---------------------------------------------------------
    # CLEAN CODEBASE
    # ---------------------------------------------------------

    if not supported:
        result = {
            "run_id": run_id,
            "status": "CLEAN",
            "events": events,
            "findings": findings,
            "processed_findings": [],
            "remaining_findings": 0,
            "engine": scan_meta["engine"],
            "post_rescan_engine": scan_meta["engine"],
            "unsupported_findings": unsupported_count,
            "dependency_analysis": dependencies,
            "fuzzing": fuzz,
            "regression_tests": True,
            "artifacts": {
                "evidence_report": (
                    f"/api/runs/{run_id}/report"
                ),
                "evidence_json": (
                    f"/api/runs/{run_id}/evidence"
                ),
            },
        }

        write_evidence(
            run_dir,
            result,
        )

        write_report(
            run_dir,
            result,
        )

        return result

    # ---------------------------------------------------------
    # REMEDIATE FINDINGS
    # ---------------------------------------------------------

    processed = []
    overall_accepted = True

    for finding in supported:
        outcome = process_finding(
            twin,
            finding,
            settings.max_attempts,
        )

        processed.append(outcome)
        events.extend(outcome["events"])

        overall_accepted = (
            overall_accepted
            and outcome["accepted"]
        )

    # ---------------------------------------------------------
    # RESCAN
    # ---------------------------------------------------------

    post_findings, post_scan_meta = scan_codebase(
        twin,
        settings.scan_timeout,
    )

    remaining_supported = [
        finding
        for finding in post_findings
        if finding_kind(finding) in SUPPORTED
    ]

    remaining = len(remaining_supported)
    clean = remaining == 0

    events.append(
        emit(
            "RESCAN",
            "pass"
            if overall_accepted and clean
            else "fail",
            (
                "Rescan complete: "
                f"{remaining} supported "
                "finding(s) remain."
            ),
            remaining=remaining,
            engine=post_scan_meta["engine"],
            scanner=post_scan_meta,
        )
    )

    # ---------------------------------------------------------
    # FINAL STATUS
    # ---------------------------------------------------------

    all_attacks = [
        attack
        for item in processed
        for attack in item.get(
            "attack_results",
            [],
        )
    ]

    accepted_items = [
        item
        for item in processed
        if item.get("accepted")
    ]

    regression_ok = (
        all(
            item.get("regression_tests")
            for item in processed
            if item.get("accepted")
        )
        and bool(accepted_items)
    )

    status = (
        "VERIFIED"
        if (
            overall_accepted
            and clean
            and regression_ok
        )
        else "FAILED"
    )

    diff = "\n\n".join(
        item.get("diff", "")
        for item in processed
        if item.get("diff")
    )

    reasoning = next(
        (
            item.get("reasoning")
            for item in reversed(processed)
            if item.get("reasoning")
        ),
        {},
    )

    attempts = [
        attempt
        for item in processed
        for attempt in item.get(
            "attempts",
            [],
        )
    ]

    regression_output = "\n\n".join(
        item.get(
            "regression_output",
            "",
        )
        for item in processed
        if item.get("regression_output")
    )

    artifacts = {
        "evidence_report": (
            f"/api/runs/{run_id}/report"
        ),
        "evidence_json": (
            f"/api/runs/{run_id}/evidence"
        ),
    }

    # Only expose verified artifacts when
    # every verification gate has passed.
    if status == "VERIFIED":
        package_verified_codebase(
            twin,
            run_dir,
        )

        artifacts["verified_codebase"] = (
            f"/api/runs/{run_id}/verified-codebase"
        )

        patch_diff = run_dir / "patch.diff"

        patch_diff.write_text(
            diff,
            encoding="utf-8",
        )

        artifacts["patch_diff"] = (
            f"/api/runs/{run_id}/patch-diff"
        )

    result = {
        "run_id": run_id,
        "status": status,
        "events": events,
        "findings": findings,
        "processed_findings": processed,
        "remaining_findings": remaining,
        "engine": scan_meta["engine"],
        "post_rescan_engine": post_scan_meta["engine"],
        "unsupported_findings": unsupported_count,
        "attack_results": all_attacks,
        "attempts": attempts,
        "max_attempts": settings.max_attempts,
        "reasoning": reasoning,
        "diff": diff,
        "regression_tests": regression_ok,
        "regression_output": regression_output,
        "dependency_analysis": dependencies,
        "fuzzing": fuzz,
        "llm_mode": reasoning.get(
            "mode",
            "demo",
        ),
        "artifacts": artifacts,
    }

    write_evidence(
        run_dir,
        result,
    )

    write_report(
        run_dir,
        result,
    )

    return result