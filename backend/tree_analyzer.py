from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

try:
    from tree_sitter import Language, Parser
    import tree_sitter_python
except Exception:  # optional runtime fallback
    Language = Parser = tree_sitter_python = None


def tree_sitter_available() -> bool:
    return Parser is not None and tree_sitter_python is not None


def parse_tree(source: str):
    if not tree_sitter_available():
        return None
    language = Language(tree_sitter_python.language())
    parser = Parser(language)
    return parser.parse(source.encode("utf-8"))


def route_metadata(source: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return routes
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
                continue
            if dec.func.attr not in {"route", "get", "post", "put", "patch", "delete"}:
                continue
            route = None
            if dec.args and isinstance(dec.args[0], ast.Constant):
                route = str(dec.args[0].value)
            if not route:
                continue
            method = "GET" if dec.func.attr in {"route", "get"} else dec.func.attr.upper()
            if dec.func.attr == "route":
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        values = [str(x.value).upper() for x in kw.value.elts if isinstance(x, ast.Constant)]
                        if values:
                            method = values[0]
            routes.append({"name": node.name, "start": node.lineno, "end": getattr(node, "end_lineno", node.lineno), "endpoint": route, "method": method})
    return routes
