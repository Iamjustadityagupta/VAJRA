# VAJRA Demo — Version History

**Project:** VAJRA — Vulnerability Assessment, Judgement & Remediation Agent  
**Positioning:** Autonomous Adversarial Vulnerability Remediation Agent  
**Core principle:** **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

---

## Version 1 — Initial Lightweight POC Scaffold

### Goal

Version 1 established the initial runnable structure for the VAJRA proof of concept. The purpose was to get the basic web-based application running before implementing the complete security-remediation loop.

### Additions

- Created the **FastAPI backend**.
- Created the **React + Vite frontend**.
- Created a basic vulnerable target application for the demo.
- Established the initial VAJRA project structure.
- Added the initial upload/demo workflow.
- Added a `runs/` workspace for storing remediation runs.
- Established the concept of a **VAJRA-TWIN** working copy rather than modifying the original codebase directly.

### Version 1 focus

Version 1 was primarily a **working application scaffold**. It was not intended to implement every security capability in the final architecture.

---

## Version 2 — Working Discover → Reproduce → Patch Pipeline

### Goal

Version 2 turned the initial scaffold into a functional lightweight remediation demonstration.

### Additions

- Added vulnerability discovery through **Semgrep when available**.
- Added a deterministic fallback security detector for the included Python demo.
- Added safe ZIP extraction with archive path validation.
- Added **SAFE CLONE** creation for the target codebase.
- Added SQL-injection exploit reproduction against the cloned Flask application.
- Added deterministic reasoning/remediation for the initial SQL-injection example.
- Added automated patch application to `VAJRA-TWIN`.
- Added adversarial payload replay after patching.
- Added regression-test execution using `pytest`.
- Added post-patch rescan.
- Added evidence JSON for completed runs.
- Added the initial FastAPI endpoints for health and remediation execution.

### Core flow

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
```

---

## Version 3 — LLM Reasoning Layer

### Goal

Version 3 introduced the first dedicated AI reasoning layer while preserving a deterministic fallback so that the POC remained runnable without an API key.

### Additions

- Added `backend/llm_reasoner.py`.
- Added a provider-agnostic LLM reasoning interface.
- Added support for live LLM configuration through environment variables.
- Added root-cause analysis.
- Added security-impact analysis.
- Added remediation recommendations.
- Added complete patched-source generation.
- Added `.env.example` configuration.
- Added an LLM status endpoint.
- Added a small reasoning integration helper.
- Updated the frontend to display the reasoning mode and remediation information.

### AI responsibility

The architecture deliberately keeps the LLM focused on reasoning and patch generation rather than using AI for every operation.

```text
Deterministic tools → analysis / execution / testing
LLM                → reasoning / patch generation
```

The deterministic fallback remained available when live LLM credentials were not configured.

---

## Version 4 — Validated AI Patching + Bounded Retry

### Goal

Version 4 strengthened the trust boundary around AI-generated patches. The LLM could propose a patch, but VAJRA would not automatically trust it.

### Additions

- Added validation of generated Python patches using Python AST parsing.
- Added bounded patch attempts.
- Added patch rejection when adversarial testing fails.
- Added patch rejection when regression tests fail.
- Added restoration of the previous code before retrying.
- Added retry context containing information about the failed attempt.
- Added AI reasoning/patch-attempt information to the frontend.
- Added clearer verification-state indicators.
- Added `.env` loading through `python-dotenv`.
- Added explicit live-vs-demo reasoning mode reporting.
- Cleaned generated cache files from the distributable project.

### Trust model

```text
LLM proposes patch
       ↓
VAJRA applies patch to VAJRA-TWIN
       ↓
ATTACK
       ↓
VERIFY
       ↓
RESCAN
       ↓
Only then → VERIFIED
```

A failed validation causes the patch to be rejected and the remediation loop to retry within the configured limit.

---

## Version 5 — Real SQLite Vulnerability + Stronger AI Interface

### Goal

Version 5 moved the demo away from the earlier simulated database behavior and made the SQL-injection demonstration use an actual SQLite-backed application.

### Additions

- Replaced the simulated database behavior with a real **SQLite database**.
- Added real demo users: `alice`, `bob`, and `admin`.
- Made the `/user` endpoint perform a genuinely vulnerable SQL query through string concatenation.
- Updated exploit reproduction to determine success from actual application results.
- Updated regression tests for the SQLite-backed target.
- Updated the deterministic reasoning fallback for the new target implementation.
- Strengthened the live LLM interface with structured JSON-schema output.
- Required the AI response to provide:
  - `root_cause`
  - `impact`
  - `remediation`
  - `patched_code`
- Preserved independent VAJRA validation of the generated patch.
- Preserved bounded retry behavior.
- Preserved attack replay and mutation testing.
- Preserved regression testing and rescan requirements.
- Fixed and cleaned up the frontend JSX implementation after the v0.4 Vite parsing issue.
- Regenerated the vulnerable demo target ZIP.

### Version 5 security demonstration

The demo now has a real attack chain:

```text
Vulnerable SQL query
        ↓
SQL injection payload
        ↓
Application returns unintended records
        ↓
Vulnerability confirmed
        ↓
AI / reasoner proposes parameterized query
        ↓
Patch applied to VAJRA-TWIN
        ↓
Original + mutated payloads replayed
        ↓
Attacks blocked
        ↓
Regression tests pass
        ↓
Rescan
        ↓
VERIFIED
```

---

# Current VAJRA POC Architecture

At Version 5, the lightweight POC demonstrates the central VAJRA concept without attempting to implement the entire proposed production architecture.

```text
                    USER CODEBASE
                         │
                         ▼
                    SAFE CLONE
                         │
                         ▼
                      DISCOVER
                         │
                         ▼
                     REPRODUCE
                         │
                         ▼
                  ┌──────────────┐
                  │ AI REASONER  │
                  └──────┬───────┘
                         │
                         ▼
                       PATCH
                         │
                         ▼
                  ATTACK OWN PATCH
                    │           │
                  FAIL         PASS
                    │           │
                    ▼           ▼
               REASON AGAIN   VERIFY
                    │           │
                    └─────┐     ▼
                          │   RESCAN
                          │     │
                          └─────┤
                                ▼
                             VERIFIED
```

## Technologies currently used in the POC

- Python
- FastAPI
- React + Vite
- Flask for the vulnerable demonstration target
- SQLite for the demonstration target
- Semgrep when available
- `pytest`
- Code-capable LLM API when configured

## Deliberately deferred capabilities

The following are part of the broader VAJRA architecture but are **not required for the current lightweight POC**:

- Docker-based isolation
- PostgreSQL
- Tree-sitter
- Syft / SBOM generation
- OSV-Scanner
- Atheris fuzzing
- Multi-language vulnerability support
- Production deployment/promotion
- Large multi-agent orchestration

The POC intentionally prioritizes a small, demonstrable end-to-end loop over implementing every proposed component.

---

# Current Success Criteria

A run should only reach **VERIFIED** when the remediation evidence supports the result.

```text
✓ Vulnerability discovered
✓ Vulnerability reproduced
✓ Root cause reasoned about
✓ Patch generated
✓ Patch applied to VAJRA-TWIN
✓ Original exploit blocked
✓ Mutated attacks blocked
✓ Regression tests pass
✓ Rescan is clean
        ↓
     VERIFIED
```

The central rule remains:

> **No patch is trusted until the exploit fails and regression tests pass.**

---

# Version Summary

| Version | Main milestone |
|---|---|
| **v0.1** | Initial FastAPI + React POC scaffold |
| **v0.2** | Functional discovery, reproduction, patch, attack, verification and rescan loop |
| **v0.3** | Dedicated LLM reasoning and patch-generation layer |
| **v0.4** | Validated AI patches and bounded retry mechanism |
| **v0.5** | Real SQLite SQLi target and stronger structured LLM integration |

---

# Next Direction — v0.6

The next development stage should focus on making the live LLM-generated patch the central remediation path and strengthening the evidence/reporting experience around the complete VAJRA loop.

The target remains:

**Discover → Reproduce → Reason → Patch → Attack → Verify → Rescan**

and ultimately:

**Verified Fixed Codebase + Patch/Diff + Evidence Report**.
