import json
import os
from typing import Any, Dict, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class LLMReasoner:
    """Provider-agnostic VAJRA reasoning and patch-generation layer."""

    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "demo").lower()
        self.api_key = os.getenv("LLM_API_KEY", "")
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
            return self._demo_reasoning(finding, source, reproduction, previous_attempt)

        client = OpenAI(api_key=self.api_key)
        retry_context = ""
        if previous_attempt:
            retry_context = f"""
PREVIOUS PATCH ATTEMPT FAILED VALIDATION:
{json.dumps(previous_attempt, indent=2)}

Generate a better patch. Do not repeat the previous mistake.
"""

        prompt = f"""
You are VAJRA, an autonomous vulnerability remediation reasoner.

Analyze ONLY the supplied evidence. Do not invent files, APIs, test results, or
verification claims.

STATIC FINDING:
{json.dumps(finding, indent=2)}

REPRODUCTION EVIDENCE:
{json.dumps(reproduction, indent=2)}
{retry_context}

RELEVANT SOURCE FILE:
```python
{source}
```

Return ONLY valid JSON with exactly these fields:
root_cause
impact
remediation
patched_code

patched_code must be the COMPLETE replacement contents of the supplied source
file. Preserve unrelated functionality and make the smallest targeted security
fix. Do not claim the patch is verified; VAJRA will perform attack replay,
regression testing, and rescanning separately.
"""

        response = client.responses.create(
            model=self.model,
            input=prompt,
        )
        text = response.output_text.strip()
        result = json.loads(text)

        required = {"root_cause", "impact", "remediation", "patched_code"}
        if not required.issubset(result):
            raise ValueError("LLM response is missing required remediation fields")
        if not isinstance(result["patched_code"], str) or not result["patched_code"].strip():
            raise ValueError("LLM returned an empty patched_code")

        return result

    def _demo_reasoning(
        self,
        finding: Dict[str, Any],
        source: str,
        reproduction: Dict[str, Any],
        previous_attempt: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        patched = source.replace(
            '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
            "    return db.execute(query)",
            '    query = "SELECT * FROM users WHERE name = ?"\n'
            "    return db.execute(query, (name,))",
            1,
        )
        return {
            "root_cause": "User-controlled input is concatenated directly into a SQL query.",
            "impact": "An attacker may alter the intended SQL statement and access unintended data.",
            "remediation": "Use a parameterized query so input is treated as data rather than SQL.",
            "patched_code": patched,
        }
