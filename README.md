# VAJRA Demo

**Vulnerability Assessment, Judgement & Remediation Agent**

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

## Overview

VAJRA is a lightweight proof-of-concept demonstrating an autonomous vulnerability-remediation loop:

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

The demo intentionally focuses on a small, demonstrable end-to-end workflow rather than implementing every component proposed for the full VAJRA architecture.

---

# Version History

## v0.1 — Initial POC Scaffold

- Created the lightweight FastAPI + React/Vite application structure.
- Added the vulnerable target application and basic test harness.
- Established the VAJRA-TWIN concept for safe remediation.
- Added the initial remediation dashboard.

## v0.2 — Working Deterministic Security Loop

- Added safe ZIP extraction and VAJRA-TWIN creation.
- Added vulnerability discovery with Semgrep when available and a deterministic fallback detector.
- Added actual SQL-injection reproduction against the cloned Flask target.
- Added deterministic patch generation.
- Added adversarial payload replay.
- Added pytest regression verification.
- Added post-patch rescan.
- Added evidence JSON for each run.

## v0.3 — AI Reasoning Layer

- Added the `LLMReasoner` abstraction.
- Added root-cause, impact and remediation reasoning.
- Added structured patch-generation support.
- Added live and demo reasoning modes.
- Added environment-based LLM configuration.

## v0.4 — Bounded Remediation Loop

- Added bounded patch attempts.
- Candidate patches are rejected when adversarial validation fails.
- Candidate patches are rejected when regression tests fail.
- Failed candidates are rolled back before another reasoning attempt.
- Previous validation failures can be supplied to the next reasoning attempt.
- Added patch syntax validation before applying generated Python.
- Improved frontend visibility of reasoning and verification state.

## v0.5 — Realistic Vulnerable Target

- Replaced simulated database behavior with a real SQLite-backed target.
- SQL injection now produces actual unintended database results.
- Updated regression tests for the real application behavior.
- Improved attack-result evaluation using application responses.
- Strengthened the structured LLM output contract.
- Fixed the frontend JSX implementation and improved dashboard state display.

## v0.6 — Evidence-Backed Final Output

- Added a verified fixed-codebase ZIP for successful runs.
- Added a downloadable evidence-report endpoint.
- Added final-output actions to the dashboard.
- Added model information to the AI Reasoning panel.
- Improved live LLM configuration through environment-controlled model selection.
- Preserved deterministic fallback for offline demos.
- Preserved the trust boundary: an LLM-generated patch is not accepted until validation succeeds.

## v0.7 — Multi-Vulnerability Autonomous Remediation

- Expanded the POC from a single SQL-injection scenario to multiple vulnerability classes.
- Added SQL injection and command injection as supported findings.
- Added vulnerability-specific reproduction.
- Added vulnerability-specific remediation strategies.
- Added vulnerability-specific adversarial payload suites.
- Added patch preflight validation before adversarial replay.
- Added finding-aware reasoning so each finding receives the correct remediation strategy.
- Locked finding identity through the remediation pipeline.
- Added aggregated attack evidence across processed findings.
- Added AST-based command-injection patch validation.
- Added bounded retry behavior after validation or regression failures.
- Strengthened the verification pipeline so zero-payload validation cannot be accepted as proof.
- Improved evidence output for attack results, patch validation, regression results and rescan status.

> All patch-level work previously represented as **v0.7.1 through v0.7.9** is consolidated into the **v0.7** milestone. Those patch numbers are no longer part of the project's version history.

---

# Current POC Flow

A remediation is considered successful only when the evidence supports every required stage:

```text
✓ Vulnerability discovered
✓ Vulnerability reproduced
✓ Root cause reasoned about
✓ Patch generated
✓ Patch applied to VAJRA-TWIN
✓ Patch preflight passed
✓ Applicable adversarial attacks blocked
✓ Regression tests passed
✓ Rescan is clean
        ↓
     VERIFIED
```

The central rule is:

> **No patch is trusted until the exploit fails, regression tests pass, and the post-patch rescan is clean.**

VAJRA never treats an LLM response itself as proof. The model proposes a remediation; VAJRA independently validates the result.

---

# Current Technology

- Python
- FastAPI
- React + Vite
- Flask for the vulnerable demonstration target
- SQLite for the demonstration target
- Semgrep when available
- Deterministic Python fallback discovery rules
- Code-capable LLM API when configured
- `pytest`

---

# Live LLM Configuration

Create `.env` in the project root using `.env.example` as a template:

```text
LLM_PROVIDER=openai
LLM_API_KEY=your_key_here
LLM_MODEL=your_available_model
VAJRA_MAX_ATTEMPTS=2
```

The demo can continue to run without an API key by using the deterministic demo mode.

---

# Deliberately Deferred Capabilities

The following belong to the broader VAJRA architecture but are intentionally outside the lightweight POC:

- Docker-based isolation
- PostgreSQL
- Tree-sitter-based multi-language analysis
- Syft / SBOM generation
- OSV-Scanner
- Atheris fuzzing
- Broad multi-language vulnerability support
- Production deployment and promotion
- Large-scale multi-agent orchestration

The POC prioritizes a credible end-to-end demonstration of:

**Discover → Reproduce → Reason → Patch → Attack → Verify → Rescan**

over implementing every proposed production component.
