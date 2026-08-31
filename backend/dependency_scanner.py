from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


def _run(command: list[str], cwd: Path, timeout: int = 45) -> tuple[bool, str]:
    try:
        p = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (p.stdout + p.stderr).strip()
    return p.returncode == 0, output


def scan_dependencies(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"syft": {"available": False}, "osv_scanner": {"available": False}}
    ok, out = _run(["syft", str(root), "-o", "json"], root, 90)
    result["syft"] = {"available": ok or "No such file" not in out, "ok": ok}
    if out:
        try:
            parsed = json.loads(out)
            result["syft"]["packages"] = len(parsed.get("artifacts", []))
            (root / ".vajra-sbom.json").write_text(json.dumps(parsed, indent=2), encoding="utf-8")
        except json.JSONDecodeError:
            result["syft"]["output"] = out[-4000:]
    ok, out = _run(["osv-scanner", "scan", "source", "-r", str(root)], root, 90)
    result["osv_scanner"] = {"available": ok or bool(out), "ok": ok, "output": out[-4000:]}
    return result
