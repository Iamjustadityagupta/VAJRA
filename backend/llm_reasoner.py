from __future__ import annotations

import ast
import json
import os
import shlex
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from openai import OpenAI
else:
    try:
        from openai import OpenAI
    except ImportError:  # pragma: no cover
        OpenAI = None


class LLMReasoner:
    """Provider-agnostic remediation layer.

    Demo mode is deterministic and uses AST transformations. Live mode sends the
    locked finding, evidence and complete source to a code-capable LLM. Validation
    is never delegated to the LLM.
    """

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "demo").lower()
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    @property
    def live(self) -> bool:
        return self.provider == "openai" and bool(self.api_key) and OpenAI is not None

    @staticmethod
    def _kind(finding: dict[str, Any]) -> str:
        metadata = finding.get("extra", {}).get("metadata", {})
        if metadata.get("kind") in {"sql-injection", "command-injection"}:
            return metadata["kind"]
        text = f"{finding.get('check_id', '')} {finding.get('extra', {}).get('message', '')}".lower()
        if any(x in text for x in ("command-injection", "command_injection", "shell", "subprocess")):
            return "command-injection"
        if any(x in text for x in ("sql-injection", "sql_injection", "sqli")):
            return "sql-injection"
        return "unknown"

    def reason_and_patch(self, finding, source, reproduction, previous_attempt=None):
        kind = self._kind(finding)
        if kind == "unknown":
            raise ValueError("VAJRA could not classify the supplied finding")

        if not self.live:
            result = self._demo_reasoning(finding, source, kind)
        else:
            client = OpenAI(api_key=self.api_key)
            retry = ""
            if previous_attempt:
                retry = f"\nPREVIOUS VALIDATION FAILURE:\n{json.dumps(previous_attempt, indent=2)}\n"
            prompt = f"""
You are VAJRA, a defensive vulnerability-remediation agent.

Original vulnerability class: {kind}
You MUST remediate this finding and must not fix another finding instead.
Do not claim verification. Return complete replacement source.

STATIC FINDING:
{json.dumps(finding, indent=2)}

REPRODUCTION EVIDENCE:
{json.dumps(reproduction, indent=2)}
{retry}

COMPLETE SOURCE FILE:
```python
{source}
```
"""
            response = client.responses.create(
                model=self.model,
                input=prompt,
                text={"format": {"type": "json_schema", "name": "vajra_patch", "strict": True, "schema": {
                    "type": "object",
                    "properties": {
                        "root_cause": {"type": "string"},
                        "impact": {"type": "string"},
                        "remediation": {"type": "string"},
                        "patched_code": {"type": "string"},
                    },
                    "required": ["root_cause", "impact", "remediation", "patched_code"],
                    "additionalProperties": False,
                }}},
            )
            result = json.loads(response.output_text)
            if not result["patched_code"].strip():
                raise ValueError("LLM returned an empty patch")

        result["finding_kind"] = kind
        return result

    @staticmethod
    def _request_variables(tree: ast.AST) -> dict[str, str]:
        result = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            if not isinstance(node.value, ast.Call) or not isinstance(node.value.func, ast.Attribute):
                continue
            base = node.value.func.value
            if isinstance(base, ast.Name) and base.id == "request" or isinstance(base, ast.Attribute) and isinstance(base.value, ast.Name) and base.value.id == "request":
                parameter = str(node.value.args[0].value) if node.value.args and isinstance(node.value.args[0], ast.Constant) else "input"
                result[node.targets[0].id] = parameter
        return result

    @staticmethod
    def _flatten(expr: ast.AST, tainted: set[str]):
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            return [("text", expr.value)]
        if isinstance(expr, ast.Name) and expr.id in tainted:
            return [("var", expr.id)]
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            left = LLMReasoner._flatten(expr.left, tainted)
            right = LLMReasoner._flatten(expr.right, tainted)
            return None if left is None or right is None else left + right
        if isinstance(expr, ast.JoinedStr):
            parts = []
            for value in expr.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(("text", value.value))
                elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name) and value.value.id in tainted:
                    parts.append(("var", value.value.id))
                else:
                    return None
            return parts
        return None

    @staticmethod
    def _unparse(tree: ast.AST) -> str:
        ast.fix_missing_locations(tree)
        return ast.unparse(tree) + "\n"

    @classmethod
    def _demo_reasoning(cls, finding, source: str, kind: str):
        tree = ast.parse(source)
        metadata = finding.get("extra", {}).get("metadata", {})
        request_vars = cls._request_variables(tree)
        source_var = metadata.get("source_variable") or next(iter(request_vars), None)
        if not source_var:
            raise ValueError("Could not identify attacker-controlled request input")

        if kind == "sql-injection":
            assignments = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    assignments[node.targets[0].id] = node.value

            changed = False
            query_bindings: dict[str, list[str]] = {}

            class SQLFix(ast.NodeTransformer):
                def visit_Assign(self, node):
                    nonlocal changed
                    node = self.generic_visit(node)
                    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                        return node
                    parts = cls._flatten(node.value, {source_var})
                    if parts and any(kind_part == "var" for kind_part, _ in parts):
                        variables = [v for kind_part, v in parts if kind_part == "var"]
                        query_parts = []
                        for index, (kind_part, value) in enumerate(parts):
                            if kind_part == "var":
                                if query_parts and query_parts[-1].endswith("'"):
                                    query_parts[-1] = query_parts[-1][:-1]
                                query_parts.append("?")
                            else:
                                text = value
                                if (
                                    index > 0
                                    and parts[index - 1][0] == "var"
                                    and text.startswith("'")
                                ):
                                    text = text[1:]
                                query_parts.append(text)

                        query = "".join(query_parts)
                        node.value = ast.Constant(query)
                        query_bindings[node.targets[0].id] = variables
                        changed = True
                    return node

                def visit_Call(self, node):
                    nonlocal changed
                    node = self.generic_visit(node)
                    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"execute", "executemany", "executescript"} or not node.args:
                        return node
                    if node.func.attr == "executescript":
                        # executescript has no DB-API parameter slot; convert the
                        # common dynamic statement to execute() with bound values.
                        pass
                    query_arg = node.args[0]
                    parts = None
                    variables = []
                    if isinstance(query_arg, ast.Name) and query_arg.id in query_bindings:
                        variables = query_bindings[query_arg.id]
                        query_value = query_arg.id
                        if query_value in assignments:
                            parts = cls._flatten(assignments[query_value], {source_var})
                    else:
                        parts = cls._flatten(query_arg, {source_var})
                    if parts and any(kind_part == "var" for kind_part, _ in parts):
                        variables = [v for kind_part, v in parts if kind_part == "var"]
                        query_parts = []
                        for index, (kind_part, value) in enumerate(parts):
                            if kind_part == "var":
                                if query_parts and query_parts[-1].endswith("'"):
                                    query_parts[-1] = query_parts[-1][:-1]
                                query_parts.append("?")
                            else:
                                text = value
                                if (
                                   index > 0
                                   and parts[index - 1][0] == "var"
                                   and text.startswith("'")
                                ):
                                   text = text[1:]
                                query_parts.append(text)

                        query = "".join(query_parts)
                        node.args[0] = ast.Constant(query)
                        if node.func.attr == "executescript":
                            node.func.attr = "execute"
                        node.args = node.args[:1] + [ast.Tuple(elts=[ast.Name(id=v, ctx=ast.Load()) for v in variables], ctx=ast.Load())]
                        changed = True
                    elif isinstance(query_arg, ast.Name) and query_arg.id in query_bindings and len(node.args) == 1:
                        node.args.append(ast.Tuple(elts=[ast.Name(id=v, ctx=ast.Load()) for v in query_bindings[query_arg.id]], ctx=ast.Load()))
                        changed = True
                    return node

            new_tree = SQLFix().visit(tree)
            if not changed:
                raise ValueError("Demo reasoner could not identify a supported dynamic SQL construction")
            return {
                "root_cause": "Attacker-controlled request data is embedded into a SQL statement.",
                "impact": "Injected syntax can alter query semantics or expose unintended records.",
                "remediation": "Use a constant SQL statement and bind attacker-controlled values as DB-API parameters.",
                "patched_code": cls._unparse(new_tree),
            }

        class CommandFix(ast.NodeTransformer):
            def visit_Call(self, node):
                node = self.generic_visit(node)

                if not node.args:
                    return node

                is_subprocess = (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "subprocess"
                )

                is_os_shell = (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr in {"system", "popen"}
                )

                if not (is_subprocess or is_os_shell):
                    return node

                expr = node.args[0]

                if isinstance(expr, ast.Name):
                    for candidate in ast.walk(tree):
                        if (
                            isinstance(candidate, ast.Assign)
                            and len(candidate.targets) == 1
                            and isinstance(candidate.targets[0], ast.Name)
                            and candidate.targets[0].id == expr.id
                        ):
                            expr = candidate.value
                            break

                # Handle:
                #     command + " > " + output_file.name
                #
                # The shell redirection must NOT be passed to a shell.
                # Instead, preserve the destination as subprocess stdout.
                redirect_target = None
                command_expr = expr

                def split_redirection(value):
                    if not (
                        isinstance(value, ast.BinOp)
                        and isinstance(value.op, ast.Add)
                    ):
                        return value, None

                    right = value.right

                    if not (
                        isinstance(right, ast.Attribute)
                        and right.attr == "name"
                        and isinstance(right.value, ast.Name)
                    ):
                        return value, None

                    left = value.left

                    if not (
                        isinstance(left, ast.BinOp)
                        and isinstance(left.op, ast.Add)
                    ):
                        return value, None

                    redirect_text = left.right

                    if not (
                        isinstance(redirect_text, ast.Constant)
                        and isinstance(redirect_text.value, str)
                        and ">" in redirect_text.value
                    ):
                        return value, None

                    return left.left, right

                command_expr, redirect_target = split_redirection(expr)

                if isinstance(command_expr, ast.Name):
                    for candidate in ast.walk(tree):
                        if (
                            isinstance(candidate, ast.Assign)
                            and len(candidate.targets) == 1
                            and isinstance(candidate.targets[0], ast.Name)
                            and candidate.targets[0].id == command_expr.id
                        ):
                            command_expr = candidate.value
                            break

                parts = cls._flatten(command_expr, {source_var})

                if not parts or not any(
                    part_kind == "var" for part_kind, _ in parts
                ):
                    return node

                tokens: list[ast.AST] = []

                for part_kind, value in parts:
                    if part_kind == "var":
                        tokens.append(
                            ast.Name(
                                id=value,
                                ctx=ast.Load(),
                            )
                        )
                    else:
                        for token in shlex.split(value, posix=True):
                            tokens.append(ast.Constant(token))

                if not tokens:
                    return node

                node.func = ast.Attribute(
                    value=ast.Name(
                        id="subprocess",
                        ctx=ast.Load(),
                    ),
                    attr="run",
                    ctx=ast.Load(),
                )

                node.args[0] = ast.List(
                    elts=tokens,
                    ctx=ast.Load(),
                )

                if redirect_target is not None:
                    output_file = ast.Attribute(
                        value=ast.Name(
                            id=redirect_target.value.id,
                            ctx=ast.Load(),
                        ),
                        attr="name",
                        ctx=ast.Load(),
                    )

                    stdout_open = ast.Call(
                        func=ast.Name(
                            id="open",
                            ctx=ast.Load(),
                        ),
                        args=[
                            output_file,
                            ast.Constant("w"),
                        ],
                        keywords=[
                            ast.keyword(
                                arg="encoding",
                                value=ast.Constant("utf-8"),
                            ),
                        ],
                    )

                    node.keywords = [
                        ast.keyword(
                            arg="stdout",
                            value=stdout_open,
                        ),
                        ast.keyword(
                            arg="text",
                            value=ast.Constant(True),
                        ),
                        ast.keyword(
                            arg="check",
                            value=ast.Constant(False),
                        ),
                    ]

                elif is_subprocess:
                    node.keywords = [
                        kw
                        for kw in node.keywords
                        if kw.arg != "shell"
                    ]

                else:
                    node.keywords = [
                        ast.keyword(
                            arg="check",
                            value=ast.Constant(False),
                        ),
                        ast.keyword(
                            arg="capture_output",
                            value=ast.Constant(True),
                        ),
                        ast.keyword(
                            arg="text",
                            value=ast.Constant(True),
                        ),
                    ]

                return node

        new_tree = CommandFix().visit(tree)

        # Ensure generated Command Injection patches import subprocess.
        has_subprocess_usage = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            for node in ast.walk(new_tree)
        )

        if has_subprocess_usage:
            has_subprocess_import = any(
                isinstance(node, ast.Import)
                and any(alias.name == "subprocess" for alias in node.names)
                for node in new_tree.body
            )

            if not has_subprocess_import:
                new_tree.body.insert(
                    0,
                    ast.Import(
                        names=[ast.alias(name="subprocess", asname=None)]
                    ),
                )

        patched = cls._unparse(new_tree)

        if patched == source:
            raise ValueError(
                "Demo reasoner could not identify a supported dynamic shell command"
            )
        return {
            "root_cause": "Attacker-controlled request data reaches an operating-system command through dynamic shell construction.",
            "impact": "Shell metacharacters can execute unintended operating-system commands.",
            "remediation": "Disable shell parsing and pass the executable and arguments as a structured list.",
            "patched_code": patched,
        }
