# VAJRA Demo v0.4

VAJRA — Vulnerability Assessment, Judgement & Remediation Agent.

## v0.4 additions

- Live OpenAI reasoning/patch generation when configured.
- LLM output is validated as Python before it can modify VAJRA-TWIN.
- Bounded patch retry loop (default: 2 attempts, maximum 3).
- Failed attack or regression validation causes the candidate patch to be rejected and the original twin restored.
- Retry context is sent back to the reasoner so a second patch can address the failure.
- Frontend now displays AI reasoning mode, root cause, remediation and patch-attempt count.
- Backend health reports the active reasoning mode.
- `.env` loading through python-dotenv.
- Removed generated `__pycache__` files from the distributable project.

## Enable live AI reasoning

1. Copy `.env.example` to `.env`.
2. Set:
   - `LLM_PROVIDER=openai`
   - `LLM_API_KEY=<your key>`
   - `LLM_MODEL=<your code-capable model>`
3. Install backend requirements:
   `pip install -r requirements.txt`
4. Start the API from `backend`:
   `python -m uvicorn main:app --reload`

Without credentials, the workflow remains fully runnable in demo mode using the deterministic fallback.

## Trust boundary

The LLM proposes a patch. VAJRA does not trust that proposal by itself.
A candidate patch is accepted only after exploit replay, regression verification,
and rescan succeed. If validation fails, VAJRA restores the previous code and
uses bounded retry reasoning to generate another candidate.
