# VAJRA — Version 0.6

**Vulnerability Assessment, Judgement & Remediation Agent**

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

## Version history

### v0.1 — Initial POC scaffold
- Created the lightweight FastAPI + React/Vite application structure.
- Added the vulnerable target application and basic test harness.
- Established the VAJRA-TWIN workflow concept.
- Added the initial remediation dashboard.

### v0.2 — Working deterministic security loop
- Added safe ZIP extraction and VAJRA-TWIN creation.
- Added vulnerability discovery with Semgrep when available and a deterministic fallback rule.
- Added actual SQL-injection reproduction against the cloned Flask target.
- Added deterministic patch generation.
- Added adversarial payload replay.
- Added pytest regression verification.
- Added post-patch rescan.
- Added evidence JSON for each run.

### v0.3 — AI reasoning layer
- Added `LLMReasoner` abstraction.
- Added root-cause, impact and remediation reasoning.
- Added structured patch generation interface.
- Added live/demo reasoning modes.
- Added environment-based LLM configuration.

### v0.4 — Bounded remediation loop
- Added bounded patch attempts.
- Candidate patches are rejected when adversarial testing fails.
- Candidate patches are rejected when regression tests fail.
- Failed candidates are rolled back before another reasoning attempt.
- Previous validation failures can be supplied to the next reasoning attempt.
- Added patch syntax validation before applying generated Python.
- Improved frontend visibility of reasoning and verification state.

### v0.5 — Realistic vulnerable target
- Replaced the simulated database behavior with a real in-memory SQLite database.
- SQL injection now produces actual unintended database results.
- Updated regression tests for the real application behavior.
- Improved attack-result evaluation using application responses.
- Strengthened the live LLM structured-output contract.
- Fixed the frontend JSX implementation and improved the dashboard state display.

### v0.6 — Evidence-backed final output
- Added a proper **verified fixed codebase ZIP** for successful runs.
- Added a downloadable **evidence report** endpoint.
- Added final-output actions to the dashboard.
- Added model information to the AI Reasoning panel.
- Improved the live LLM configuration so the API model is explicitly environment-controlled.
- Kept the deterministic fallback for offline demos.
- Preserved the trust boundary: an LLM-generated patch is not accepted until attack replay, regression testing and rescan succeed.

## Current POC flow

```text
SAFE CLONE
    ↓
DISCOVER
    ↓
REPRODUCE
    ↓
REASON
    ↓
PATCH
    ↓
ATTACK
    ↓
VERIFY
    ↓
RESCAN
    ↓
VERIFIED FIXED CODEBASE + PATCH DIFF + EVIDENCE REPORT
```

## Current technology

- Python
- FastAPI
- React + Vite
- Flask target application
- SQLite for the demo target
- Semgrep when installed, with a lightweight fallback detector
- One code-capable LLM for reasoning and patch generation
- pytest for regression verification

## Live LLM configuration

Create `.env` in the project root using `.env.example` as a template:

```text
LLM_PROVIDER=openai
LLM_API_KEY=your_key_here
LLM_MODEL=your_available_model
VAJRA_MAX_ATTEMPTS=2
```

The model name should be one available to the API account being used. The demo can continue to run without an API key by leaving `LLM_PROVIDER=demo`.

## POC trust model

VAJRA never treats an LLM response as proof. The model proposes a remediation. VAJRA independently:

1. replays the exploit,
2. runs adversarial mutations,
3. executes regression tests,
4. rescans the patched twin,
5. and only then returns the verified codebase.

This implements the project's central principle:

> **No patch is trusted until the original exploit fails and regression tests pass.**

## Deliberately deferred

The current lightweight demo does not yet implement the complete proposed production stack such as Docker isolation, PostgreSQL persistence, Tree-sitter, Syft, OSV-Scanner, or Atheris. Those remain future extensions rather than requirements for the core demonstration.
