from __future__ import annotations

import ast
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tree_analyzer import parse_tree, route_metadata, tree_sitter_available

SUPPORTED = {"sql-injection", "command-injection"}


@dataclass
class Finding:
    check_id: str
    path: str
    line: int
    severity: str
    message: str
    kind: str
    endpoint: str | None = None
    method: str = "GET"
    parameter: str | None = None
    sink: str | None = None
    source_variable: str | None = None
    analyzer: str = "VAJRA-AST"

    def as_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "path": self.path,
            "start": {"line": self.line},
            "extra": {
                "severity": self.severity,
                "message": self.message,
                "metadata": {
                    "kind": self.kind,
                    "endpoint": self.endpoint,
                    "method": self.method,
                    "parameter": self.parameter,
                    "sink": self.sink,
                    "source_variable": self.source_variable,
                    "analyzer": self.analyzer,
                },
            },
        }


def _request_inputs(tree: ast.AST) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}

    def request_root(node: ast.AST) -> bool:
        while isinstance(node, ast.Attribute):
            node = node.value
        return isinstance(node, ast.Name) and node.id == "request"

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            value = node.value
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and request_root(value.func.value):
                parameter = str(value.args[0].value) if value.args and isinstance(value.args[0], ast.Constant) else "input"
                found[node.targets[0].id] = (value.func.attr, parameter)
            elif isinstance(value, ast.Subscript) and request_root(value.value) and isinstance(value.slice, ast.Constant):
                found[node.targets[0].id] = ("subscript", str(value.slice.value))
    return found


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _assignments(tree: ast.AST) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node.value
    return result


def _route_for_line(routes: list[dict[str, Any]], line: int) -> tuple[str | None, str]:
    for route in routes:
        if route["start"] <= line <= route["end"]:
            return route["endpoint"], route["method"]
    return None, "GET"


def _semgrep(root: Path, timeout: int = 30) -> tuple[list[dict[str, Any]], str | None]:
    config = Path(__file__).with_name("semgrep.yml")
    if not config.exists():
        return [], "Semgrep rule file not found."
    try:
        completed = subprocess.run(
            ["semgrep", "scan", "--config", str(config), "--json", "--no-git-ignore", str(root)],
            cwd=root, capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)
    output = completed.stdout.strip()
    if not output:
        return [], (completed.stderr or "Semgrep returned no JSON output.")[-2000:]
    try:
        data = json.loads(output)
        return data.get("results", []), None
    except json.JSONDecodeError:
        return [], output[-2000:]


def _ast_findings(root: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in root.rglob("*.py"):
        if any(part in {".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", ".git"} for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, OSError):
            continue

        # Tree-sitter is used as a structural parse/health check. AST supplies
        # the richer semantic flow information needed by the deterministic rules.
        parse_tree(source)
        inputs = _request_inputs(tree)
        tainted = set(inputs)
        assignments = _assignments(tree)
        routes = route_metadata(source)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or not node.args:
                continue
            if node.func.attr not in {"execute", "executemany", "executescript"}:
                continue
            query = node.args[0]
            if isinstance(query, ast.Name) and query.id in assignments:
                query = assignments[query.id]
            if not isinstance(query, (ast.BinOp, ast.JoinedStr, ast.Mod)):
                continue
            used = _names(query) & tainted
            if not used:
                continue
            route, method = _route_for_line(routes, node.lineno)
            variable = next(iter(used))
            findings.append(Finding(
                "vajra.sql-injection", str(path.relative_to(root)), node.lineno, "HIGH",
                "User-controlled request data reaches a SQL execution sink through a dynamic query.",
                "sql-injection", route, method, inputs[variable][1], node.func.attr, variable,
            ).as_dict())

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            sink = None
            shell_enabled = False
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                sink = f"subprocess.{node.func.attr}"
                shell_enabled = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" and node.func.attr in {"system", "popen"}:
                sink = f"os.{node.func.attr}"
                shell_enabled = True
            if not sink or not shell_enabled:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in assignments:
                arg = assignments[arg.id]

            used = _names(arg)
            if not used:
                continue

            route, method = _route_for_line(routes, node.lineno)

            source_variable = None
            pending = list(used)
            seen = set()

            while pending:
                candidate = pending.pop()
                if candidate in seen:
                    continue

                seen.add(candidate)

                if candidate in inputs:
                    source_variable = candidate
                    break

                assigned_expr = assignments.get(candidate)
                if assigned_expr is not None:
                    pending.extend(_names(assigned_expr))

            if source_variable is None:
                continue

            findings.append(Finding(
                "vajra.command-injection",
                str(path.relative_to(root)),
                node.lineno,
                "CRITICAL",
                "User-controlled request data reaches a shell command execution sink.",
                "command-injection",
                route,
                method,
                inputs[source_variable][1],
                sink,
                source_variable,
            ).as_dict())
    return findings


def _merge_semgrep(ast_findings: list[dict[str, Any]], semgrep_results: list[dict[str, Any]], root: Path) -> list[dict[str, Any]]:
    findings = {(
        f["path"], f["start"]["line"], f["extra"]["metadata"]["kind"]
    ): f for f in ast_findings}
    for item in semgrep_results:
        check = str(item.get("check_id", "")).lower()
        message = str(item.get("extra", {}).get("message", "")).lower()
        kind = "command-injection" if "command" in check or "shell" in message or "subprocess" in message else "sql-injection" if "sql" in check or "sql" in message else None
        if kind not in SUPPORTED:
            continue
        rel = os.path.relpath(item.get("path", ""), root).replace("\\", "/")
        line = int(item.get("start", {}).get("line", 1))
        key = (rel, line, kind)
        if key in findings:
            findings[key]["extra"]["metadata"]["semgrep"] = True
            findings[key]["extra"]["metadata"]["analyzer"] = "Semgrep + Tree-sitter + AST"
        else:
            severity = "CRITICAL" if kind == "command-injection" else "HIGH"
            findings[key] = {
                "check_id": f"vajra.{kind}", "path": rel, "start": {"line": line},
                "extra": {"severity": severity, "message": item.get("extra", {}).get("message", "Semgrep finding"),
                          "metadata": {"kind": kind, "endpoint": None, "method": "GET", "parameter": None,
                                       "sink": None, "source_variable": None, "semgrep": True,
                                       "analyzer": "Semgrep + Tree-sitter"}}
            }
    return list(findings.values())


def scan_codebase(root: Path, timeout: int = 30) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    ast_results = _ast_findings(root)
    semgrep_results, semgrep_error = _semgrep(root, timeout)
    merged = _merge_semgrep(ast_results, semgrep_results, root)
    engine_parts = ["Tree-sitter"]
    if semgrep_results or semgrep_error is None:
        engine_parts.insert(0, "Semgrep")
    engine_parts.append("AST semantic rules")
    metadata = {
        "engine": " + ".join(engine_parts),
        "semgrep_available": semgrep_error is None,
        "semgrep_findings": len(semgrep_results),
        "tree_sitter_available": tree_sitter_available(),
        "fallback": bool(semgrep_error),
        "semgrep_error": semgrep_error,
    }
    return merged, metadata


def scan_python(root: Path) -> list[dict[str, Any]]:
    return _ast_findings(root)
