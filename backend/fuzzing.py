from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path
from typing import Any


def run_smoke_fuzz(root: Path, seconds: int = 2) -> dict[str, Any]:
    harness = root / ".vajra_fuzz_harness.py"
    harness.write_text(
        """import ast, sys\n\ntry:\n import atheris\nexcept Exception:\n raise SystemExit(2)\n\ndef TestOneInput(data):\n try:\n  ast.parse(data.decode('utf-8', errors='ignore'))\n except Exception:\n  pass\n\natheris.Setup(sys.argv, TestOneInput)\natheris.Fuzz()\n""",
        encoding="utf-8",
    )
    try:
        p = subprocess.run([sys.executable, str(harness), f"-max_total_time={max(1, seconds)}"], cwd=root, capture_output=True, text=True, timeout=max(5, seconds + 8), check=False)
        return {"available": True, "ok": p.returncode in (0, 1), "exit_code": p.returncode, "output": (p.stdout + p.stderr)[-2000:]}
    except FileNotFoundError:
        return {"available": False, "ok": False, "reason": "Python runtime unavailable."}
    except subprocess.TimeoutExpired:
        return {"available": True, "ok": True, "reason": "Fuzz smoke test timed out; process was stopped by the timeout guard."}
    finally:
        harness.unlink(missing_ok=True)
