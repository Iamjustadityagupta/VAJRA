import json
import os
import re
import sys
from typing import Any, Dict, Optional

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover
    OpenAI = None


class LLMReasoner:
    """Provider-agnostic reasoning and patch-generation layer for VAJRA."""

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "demo").lower()
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    @property
    def live(self) -> bool:
        return self.provider == "openai" and bool(self.api_key) and OpenAI is not None

    @staticmethod
    def _kind(finding: Dict[str, Any], source: str) -> str:
        check_id = str(finding.get("check_id", "")).lower()
        message = str(finding.get("extra", {}).get("message", "")).lower()
        combined = f"{check_id} {message}"

        if any(x in combined for x in ("command-injection", "command_injection", "shell", "subprocess")):
            return "command-injection"
        if any(x in combined for x in ("sql-injection", "sql_injection", "sqli")):
            return "sql-injection"

        lower = source.lower()
        if "subprocess" in lower and "shell=true" in lower:
            return "command-injection"
        if "execute(query)" in lower and "+ name +" in lower:
            return "sql-injection"
        return "unknown"

    def reason_and_patch(
        self,
        finding: Dict[str, Any],
        source: str,
        reproduction: Dict[str, Any],
        previous_attempt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        kind = self._kind(finding, source)
        if kind == "unknown":
            raise ValueError("Demo reasoner could not classify the supplied finding")

        if not self.live:
            result = self._demo_reasoning(source, kind)
        else:
            client = OpenAI(api_key=self.api_key)
            retry_context = ""
            if previous_attempt:
                retry_context = f"""
PREVIOUS PATCH ATTEMPT FAILED VALIDATION:
{json.dumps(previous_attempt, indent=2)}

Generate a different, safer patch and address the specific validation failure.
"""

            prompt = f"""
You are VAJRA, an autonomous defensive vulnerability-remediation reasoner.

The ORIGINAL FINDING has already been classified as: {kind}
You must remediate THIS finding and must not fix a different vulnerability instead.

STATIC FINDING:
{json.dumps(finding, indent=2)}

REPRODUCTION EVIDENCE:
{json.dumps(reproduction, indent=2)}
{retry_context}

RELEVANT SOURCE FILE:
```python
{source}
```

Return a minimal targeted remediation. The patched_code field MUST contain the
COMPLETE replacement contents of the supplied source file. Preserve unrelated
functionality and preserve other vulnerability-bearing code unless changing it
is necessary for THIS finding. Do not claim that the patch is verified; VAJRA
verifies it separately through preflight, attack replay, regression tests, and
rescanning.
"""

            response = client.responses.create(
                model=self.model,
                input=prompt,
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "vajra_patch",
                        "strict": True,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "root_cause": {"type": "string"},
                                "impact": {"type": "string"},
                                "remediation": {"type": "string"},
                                "patched_code": {"type": "string"},
                            },
                            "required": ["root_cause", "impact", "remediation", "patched_code"],
                            "additionalProperties": False,
                        },
                    }
                },
            )
            result = json.loads(response.output_text)
            if not result["patched_code"].strip():
                raise ValueError("LLM returned an empty patch")

        result["finding_kind"] = kind
        return result

    @staticmethod
    def _demo_reasoning(source: str, kind: str) -> Dict[str, Any]:
        if kind == "command-injection":
            old = (
                '    command = "echo PING " + host\n'
                '    output = subprocess.check_output(command, shell=True, text=True, timeout=3)'
            )
            replacement = (
                '    output = subprocess.check_output([sys.executable, "-c", "print(\'PING\', __import__(\'sys\').argv[1])", host], text=True, timeout=3)'
            )
            patched = source.replace(old, replacement, 1)
            if patched != source and "import sys" not in patched:
                patched = "import sys\n" + patched
            if patched == source:
                raise ValueError("Demo reasoner could not identify the command-injection pattern")
            return {
                "root_cause": "User-controlled host input is concatenated into a shell command executed with shell=True.",
                "impact": "An attacker can inject additional shell commands into the process.",
                "remediation": "Avoid shell parsing and execute the fixed command through the current Python interpreter using structured arguments with shell execution disabled.",
                "patched_code": patched,
            }

        old = (
            '    query = "SELECT id, name FROM users WHERE name = \'" + name + "\'"\n'
            '    rows = get_db().execute(query).fetchall()'
        )
        replacement = (
            '    query = "SELECT id, name FROM users WHERE name = ?"\n'
            '    rows = get_db().execute(query, (name,)).fetchall()'
        )
        patched = source.replace(old, replacement, 1)
        if patched == source:
            raise ValueError("Demo reasoner could not identify the SQL-injection pattern")
        return {
            "root_cause": "User-controlled input is concatenated directly into a SQL query.",
            "impact": "An attacker can alter SQL query structure and retrieve unintended records.",
            "remediation": "Use a parameterized query so the user input is bound as data.",
            "patched_code": patched,
        }
