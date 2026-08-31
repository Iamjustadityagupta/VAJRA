from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class DiscoveryEngine(ABC):
    """Common interface for language-aware VAJRA discovery engines."""

    name = "VAJRA-DISCOVERY"
    language = "unknown"

    @abstractmethod
    def supports(self, root: Path) -> bool:
        """Return whether this engine can inspect the target."""
        raise NotImplementedError

    @abstractmethod
    def scan(self, root: Path) -> list[dict[str, Any]]:
        """Return normalized VAJRA findings."""
        raise NotImplementedError


def _normalize_finding(finding: dict[str, Any], language: str) -> dict[str, Any]:
    """Normalize every engine result into the VAJRA finding contract."""
    extra = dict(finding.get("extra") or {})
    location = dict(finding.get("location") or {})
    start = dict(finding.get("start") or location.get("start") or {})
    message = str(finding.get("message") or extra.get("message") or "Finding reported by discovery engine.")
    severity = str(finding.get("severity") or extra.get("severity") or "WARNING").upper()
    path = str(
        finding.get("path")
        or location.get("path")
        or finding.get("file")
        or ""
    )

    normalized = dict(finding)
    normalized.update(
        {
            "id": str(finding.get("id") or finding.get("check_id") or f"{language}:{path}:{start.get('line', 0)}"),
            "type": str(finding.get("type") or finding.get("check_id") or "unknown"),
            "language": language,
            "path": path,
            "start": {"line": int(start.get("line") or 0)},
            "message": message,
            "severity": severity,
        }
    )
    normalized["extra"] = extra
    normalized["extra"].update(
        {
            "message": message,
            "severity": severity,
            "language": language,
        }
    )
    return normalized


class PythonRulesEngine(DiscoveryEngine):
    """Deterministic fallback rules for the seeded Python demo target."""

    name = "VAJRA-PYTHON-RULES"
    language = "python"

    def supports(self, root: Path) -> bool:
        return any(root.rglob("*.py"))

    def scan(self, root: Path) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for path in root.rglob("*.py"):
            text = path.read_text(errors="ignore")
            lines = text.splitlines()

            if (
                "request.args.get" in text
                and "execute(query)" in text
                and "+ name +" in text
            ):
                line = next(
                    (i for i, value in enumerate(lines, 1) if "query =" in value),
                    1,
                )
                findings.append(
                    _normalize_finding(
                        {
                            "check_id": "python.sql-injection",
                            "path": str(path.relative_to(root)),
                            "start": {"line": line},
                            "extra": {
                                "message": "User-controlled input is concatenated into a SQL query.",
                                "severity": "ERROR",
                            },
                        },
                        self.language,
                    )
                )

            if (
                "subprocess" in text
                and "shell=True" in text
                and 'request.args.get("host"' in text
            ):
                line = next(
                    (i for i, value in enumerate(lines, 1) if "shell=True" in value),
                    1,
                )
                findings.append(
                    _normalize_finding(
                        {
                            "check_id": "python.command-injection",
                            "path": str(path.relative_to(root)),
                            "start": {"line": line},
                            "extra": {
                                "message": "User-controlled input reaches a shell command executed with shell=True.",
                                "severity": "ERROR",
                            },
                        },
                        self.language,
                    )
                )

        return findings


class SemgrepEngine(DiscoveryEngine):
    """Semgrep-backed Python discovery engine when Semgrep is installed."""

    name = "SEMGREP"
    language = "python"

    def supports(self, root: Path) -> bool:
        return any(root.rglob("*.py"))

    def scan(self, root: Path) -> list[dict[str, Any]]:
        command = [
            "semgrep",
            "--config",
            "p/python",
            "--json",
            "--quiet",
            str(root),
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        if not completed.stdout.strip():
            raise RuntimeError("Semgrep returned no JSON findings.")

        results = json.loads(completed.stdout).get("results", [])
        return [_normalize_finding(item, self.language) for item in results]


LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "c": {".c", ".h"},
    "cpp": {".cc", ".cpp", ".cxx", ".hpp", ".hh"},
    "php": {".php"},
    "ruby": {".rb"},
}


class DiscoveryManager:
    """Select discovery engines and expose language coverage for a target."""

    def __init__(self) -> None:
        self.python_rules = PythonRulesEngine()
        self.semgrep = SemgrepEngine()

    def detect_languages(self, root: Path) -> list[str]:
        detected: list[str] = []
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if any(path.suffix.lower() in extensions for path in root.rglob("*")):
                detected.append(language)
        return detected

    def supported_languages(self, root: Path) -> list[str]:
        supported: list[str] = []
        if self.python_rules.supports(root):
            supported.append("python")
        return supported

    def scan(self, root: Path) -> tuple[list[dict[str, Any]], str]:
        """Prefer Semgrep for Python and supplement it with deterministic rules."""
        if self.semgrep.supports(root):
            try:
                results = self.semgrep.scan(root)
                fallback = self.python_rules.scan(root)
                existing = {
                    (item.get("check_id"), item.get("path"), item.get("start", {}).get("line"))
                    for item in results
                }
                for item in fallback:
                    key = (item["check_id"], item["path"], item["start"]["line"])
                    if key not in existing:
                        results.append(item)
                return results, "semgrep + VAJRA rules"
            except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired, RuntimeError):
                pass

        if self.python_rules.supports(root):
            return self.python_rules.scan(root), self.python_rules.name

        return [], "VAJRA-DISCOVERY-NONE"
