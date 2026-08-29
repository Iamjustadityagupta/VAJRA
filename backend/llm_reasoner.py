import os
import json
from typing import Any, Dict, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class LLMReasoner:
    """
    Small provider-agnostic reasoning wrapper.

    If LLM_API_KEY is configured and the OpenAI SDK is installed, the
    reasoner asks the configured code-capable model for a structured
    remediation proposal. Otherwise it falls back to the deterministic
    demo reasoning path so the POC remains runnable offline.
    """

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
    ) -> Dict[str, Any]:
        if not self.live:
            return self._demo_reasoning(finding, source, reproduction)

        client = OpenAI(api_key=self.api_key)

        prompt = f"""
You are VAJRA, an autonomous vulnerability remediation reasoner.

Analyze ONLY the supplied evidence. Do not invent files, APIs, or test results.

STATIC FINDING:
{json.dumps(finding, indent=2)}

REPRODUCTION EVIDENCE:
{json.dumps(reproduction, indent=2)}

RELEVANT SOURCE:
```python
{source}
```

Return valid JSON with exactly these fields:
root_cause
impact
remediation
patched_code

patched_code must be the complete replacement contents of the supplied source
file, preserving unrelated functionality. Make the smallest targeted security fix.
Do not claim verification; verification is performed separately by VAJRA.
"""

        response = client.responses.create(
            model=self.model,
            input=prompt,
            temperature=0
        )

        text = response.output_text.strip()
        result = json.loads(text)

        required = {"root_cause", "impact", "remediation", "patched_code"}
        if not required.issubset(result):
            raise ValueError("LLM response is missing required remediation fields")

        return result

    def _demo_reasoning(
        self,
        finding: Dict[str, Any],
        source: str,
        reproduction: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Deterministic fallback used when no LLM credentials are configured.
        patched = source.replace(
            'query = "SELECT * FROM users WHERE name = \'" + name + \'"',
            'query = "SELECT * FROM users WHERE name = ?"'
        ).replace(
            'return db.execute(query)',
            'return db.execute(query, (name,))'
        )

        return {
            "root_cause": (
                "User-controlled input is concatenated directly into a SQL query, "
                "allowing the input to alter query structure."
            ),
            "impact": (
                "An attacker may manipulate the SQL statement and access or alter "
                "data outside the intended query."
            ),
            "remediation": (
                "Use a parameterized SQL query so user input is treated as data "
                "rather than executable SQL."
            ),
            "patched_code": patched,
        }
