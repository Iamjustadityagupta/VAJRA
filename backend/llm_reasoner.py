import json
import os
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
        # Set LLM_MODEL explicitly in .env for the model available to your API account.
        self.model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    @property
    def live(self) -> bool:
        return self.provider == "openai" and bool(self.api_key) and OpenAI is not None

    def reason_and_patch(
        self,
        finding: Dict[str, Any],
        source: str,
        reproduction: Dict[str, Any],
        previous_attempt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.live:
            return self._demo_reasoning(source)

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

Analyze ONLY the supplied evidence. Do not invent files, APIs, test results,
or verification claims.

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
functionality. Do not claim that the patch is verified; VAJRA verifies it
separately through attack replay, regression tests, and rescanning.
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
        return result

    @staticmethod
    def _demo_reasoning(source: str) -> Dict[str, Any]:
        patched = source.replace(
            '    query = "SELECT id, name FROM users WHERE name = \'" + name + "\'"\n'
            '    rows = db.execute(query).fetchall()',
            '    query = "SELECT id, name FROM users WHERE name = ?"\n'
            '    rows = db.execute(query, (name,)).fetchall()',
            1,
        )
        if patched == source:
            raise ValueError("Demo reasoner could not identify the expected vulnerable SQL pattern")
        return {
            "root_cause": "User-controlled input is concatenated directly into a SQL query.",
            "impact": "An attacker can alter SQL query structure and retrieve unintended records.",
            "remediation": "Use a parameterized query so the user input is bound as data.",
            "patched_code": patched,
        }
