# VAJRA Demo

**Vulnerability Assessment, Judgement & Remediation Agent**

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

## Overview

VAJRA is a lightweight proof-of-concept demonstrating an autonomous
vulnerability-remediation loop:

``` text
SAFE CLONE → DISCOVER → REPRODUCE → REASON → PATCH
→ PREFLIGHT → ATTACK → REGRESSION → RESCAN → VERIFIED
```

The project focuses on a simple security principle:

> **No patch is trusted until the original exploit fails, regression
> tests pass, and the post-patch rescan is clean.**

VAJRA works on an isolated **VAJRA-TWIN** rather than modifying the
original target directly.

------------------------------------------------------------------------

# v0.8 --- Evidence & Run Intelligence

v0.8 builds on the verified multi-vulnerability remediation loop
established in v0.7 and makes the result substantially easier to inspect
and demonstrate.

### v0.8 capabilities

-   Human-readable HTML Evidence Report
-   Evidence Report API
-   Evidence JSON access
-   Patch Diff download
-   Verified Codebase download
-   Improved finding cards
-   Vulnerability severity display
-   Run summary statistics
-   Per-finding remediation state
-   Explicit VAJRA-TWIN status
-   Pre/post-rescan summary
-   Bounded remediation-attempt visualization
-   Evidence-backed execution timeline
-   Clickable timeline events linked to detailed evidence

The timeline and dashboard consume the recorded run evidence rather than
maintaining a separate execution history.

------------------------------------------------------------------------

# v0.8 Verification Model

A successful run communicates the complete chain:

``` text
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
PREFLIGHT
    ↓
ATTACK
    ↓
REGRESSION
    ↓
RESCAN
    ↓
EVIDENCE
    ↓
VERIFIED
```

For the established v0.7 security demonstration, the target contains:

-   SQL Injection
-   Command Injection

The validated adversarial suite contains:

``` text
SQL Injection        4 payloads
Command Injection    3 payloads
                     ───────────
Total                7 payloads
```

The known-good v0.7 milestone achieved:

``` text
7/7 attacks blocked
Regression tests passed
Post-patch rescan clean
0 remaining findings
Evidence accepted
VERIFIED
```

v0.8 does not replace these security gates. It exposes their evidence
more clearly.

------------------------------------------------------------------------

# Evidence Report

v0.8 adds a dedicated human-readable report generated from the stored
run evidence.

The report presents:

-   Final verification status
-   Findings discovered
-   Finding type
-   Affected file and line
-   Severity
-   Reproduction evidence
-   Root cause
-   Impact
-   Remediation
-   Patch information
-   Patch diff
-   Adversarial validation
-   Regression results
-   Rescan results
-   Verification checklist
-   Run timeline

The evidence report is derived from the same evidence data used by the
backend, keeping the report aligned with the actual run.

------------------------------------------------------------------------

# Run Intelligence Dashboard

The v0.8 dashboard summarizes the security result before exposing the
detailed evidence.

A verified run can be understood through:

``` text
FINDINGS DISCOVERED       2
FINDINGS REMEDIATED       2
ATTACKS BLOCKED           7/7
REMAINING FINDINGS        0
```

Individual finding cards expose the vulnerability type, location,
severity, and remediation state.

The dashboard also distinguishes the isolated VAJRA-TWIN from the
original target and the final verified output.

------------------------------------------------------------------------

# Run Timeline

The v0.8 Run Timeline provides an evidence-backed chronological view of
execution.

Typical stages are:

``` text
✓ SAFE CLONE
✓ DISCOVER
✓ REPRODUCE
✓ REASON
✓ PATCH
✓ PREFLIGHT
✓ ATTACK
✓ REGRESSION
✓ RESCAN
✓ VERIFIED
```

Each recorded event can be selected to inspect its existing detailed
evidence.

This makes the dashboard answer both:

> **What is the final result?**

and:

> **How did VAJRA arrive at that result?**

------------------------------------------------------------------------

# Rescan Summary

v0.8 presents the post-patch rescan as a before/after security result:

``` text
PRE-PATCH FINDINGS
        ↓
     RESOLVED
        ↓
POST-PATCH FINDINGS
```

The important acceptance condition remains:

``` text
REMAINING FINDINGS = 0
```

VAJRA must not display `VERIFIED` merely because an attack suite passed.

------------------------------------------------------------------------

# Artifacts

A successful run provides access to:

``` text
Evidence Report
Evidence JSON
Patch Diff
Verified Fixed Codebase
```

The verified codebase is produced only after the remediation gates
succeed.

------------------------------------------------------------------------

# v0.7 Security Foundation

v0.8 preserves the v0.7 security foundation.

## SQL Injection

The vulnerable target originally constructs SQL using
attacker-controlled string concatenation:

``` python
name = request.args.get("name", "")
query = "SELECT id, name FROM users WHERE name = '" + name + "'"
rows = get_db().execute(query).fetchall()
```

The remediation uses parameterized SQL:

``` python
query = "SELECT id, name FROM users WHERE name = ?"
rows = get_db().execute(query, (name,)).fetchall()
```

## Command Injection

The vulnerable `/ping` route originally uses shell execution with
attacker-controlled input:

``` python
host = request.args.get("host", "localhost")
command = "echo PING " + host
output = subprocess.check_output(
    command,
    shell=True,
    text=True,
    timeout=3
)
```

The v0.7 remediation removes shell parsing and uses structured
arguments.

For the Windows demonstration environment, the remediation uses the
current Python interpreter so the fixed behavior is platform-compatible.

------------------------------------------------------------------------

# Finding-Aware Remediation

VAJRA processes the original finding identity throughout remediation.

The target contains multiple vulnerability classes, so the remediation
layer must know whether it is processing:

``` text
sql-injection
```

or:

``` text
command-injection
```

The reasoning layer selects the corresponding remediation strategy,
while deterministic validation remains responsible for syntax checks,
exploit replay, preflight, regression testing, and rescanning.

This separation keeps the LLM responsible for reasoning and patch
generation while deterministic code remains responsible for proving the
result.

------------------------------------------------------------------------

# Bounded Remediation

VAJRA uses bounded remediation attempts.

The intended loop is:

``` text
PATCH
  ↓
PREFLIGHT / ATTACK / VERIFY
  ↓
FAIL
  ↓
REASON AGAIN
  ↓
NEW PATCH
  ↓
RETEST
```

There is a maximum attempt count.

The system does not use an unbounded autonomous loop.

------------------------------------------------------------------------

# Architecture

``` text
                    ┌───────────────────────┐
                    │     React + Vite      │
                    │    Demo Dashboard     │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │      FastAPI API      │
                    │      VAJRA Engine     │
                    └───────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
          ▼                     ▼                     ▼
     Discovery              Reasoning           Verification
  Semgrep / Python         Demo / Live LLM       Preflight
       Rules                                      Attack
                                                  Regression
                                                  Rescan
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                ▼
                       ┌──────────────────┐
                       │    VAJRA-TWIN    │
                       │  Isolated copy   │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Vulnerable Flask │
                       │   Demo Target    │
                       └──────────────────┘
```

The original target remains separate from the remediation workspace.

------------------------------------------------------------------------

# Repository Structure

``` text
VAJRA-demo/
│
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── llm_reasoner.py
│   ├── evidence_report.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── package-lock.json
│   └── src/
│       ├── main.jsx
│       └── style.css
│
├── target_app/
│   ├── app.py
│   ├── test_app.py
│   └── README.md
│
├── runs/
├── .env.example
├── .gitattributes
├── .gitignore
├── README.md
└── vajra-demo-target.zip
```

Runtime run artifacts are stored beneath:

``` text
runs/VAJRA-<RUN_ID>/
```

------------------------------------------------------------------------

# Running the Demo

## Backend

``` bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

## Frontend

``` bash
cd frontend
npm install
npm run dev
```

Build the frontend for production with:

``` bash
npm run build
```

------------------------------------------------------------------------

# Environment

The deterministic demo can run without an LLM API key.

Example configuration:

``` text
LLM_PROVIDER=demo
LLM_API_KEY=
LLM_MODEL=gpt-4.1-mini
VAJRA_MAX_ATTEMPTS=2
```

Live LLM reasoning can be enabled through the configured environment
variables.

The architecture intentionally separates:

``` text
LLM
→ reasoning + patch generation

Deterministic tooling
→ execution + validation + verification
```

------------------------------------------------------------------------

# API

Important backend endpoints include:

``` text
GET  /api/health
GET  /api/llm-status
POST /api/demo/run

GET  /api/runs/{run_id}/evidence
GET  /api/runs/{run_id}/report
GET  /api/runs/{run_id}/diff
GET  /api/runs/{run_id}/verified-codebase
```

The artifact endpoints expose the evidence generated by the completed
remediation run.

------------------------------------------------------------------------

# Version History

## v0.1 --- Initial POC

-   Lightweight VAJRA proof-of-concept
-   Basic vulnerability discovery/remediation loop
-   Safe clone / VAJRA-TWIN concept

## v0.2 --- Working Deterministic Security Loop

-   Real Flask target execution
-   SQL injection reproduction
-   Basic adversarial replay
-   Regression testing
-   Post-patch validation

## v0.3 --- AI Reasoning Layer

-   Provider-agnostic LLM reasoning
-   Structured remediation output
-   Demo/live reasoning modes

## v0.4 --- Bounded Remediation

-   Live LLM patch generation
-   Bounded remediation retries
-   Patch syntax validation
-   Retry context

## v0.5 --- Realistic Vulnerable Target

-   SQLite-backed vulnerable target
-   Genuine SQL injection behavior
-   Stronger structured LLM output

## v0.6 --- Evidence-Oriented Output

-   Evidence/proof-oriented output
-   Stronger verification architecture

## v0.7 --- Multi-Vulnerability Proof of Concept

-   SQL injection + command injection
-   Vulnerability-specific reproduction
-   Finding-aware remediation
-   Patch preflight
-   Adversarial validation
-   Regression verification
-   Post-patch rescan
-   7/7 adversarial attacks blocked
-   Verified fixed-codebase output

The intermediate v0.7.x fixes are intentionally consolidated into the
v0.7 milestone rather than cluttering the milestone history.

## v0.8 --- Evidence & Run Intelligence

-   Added human-readable HTML Evidence Report
-   Added Evidence Report API
-   Added downloadable patch diff
-   Improved finding cards
-   Added vulnerability severity display
-   Added run summary statistics
-   Added explicit VAJRA-TWIN status
-   Added pre/post-rescan summary
-   Added bounded remediation-attempt visualization
-   Added evidence-backed Run Timeline
-   Made timeline events selectable for detailed inspection
-   Expanded dashboard artifact access

------------------------------------------------------------------------

# Scope

VAJRA is intentionally a lightweight demonstration rather than a
complete production security platform.

The project does not currently attempt to implement every proposed
production capability such as:

-   Production-grade container isolation
-   PostgreSQL infrastructure
-   Complete SBOM/dependency analysis
-   Full Atheris fuzzing
-   Broad multi-language support
-   Kubernetes deployment
-   Large multi-agent orchestration

The purpose is to make the core idea convincing:

> **AI-generated remediation + deterministic validation + adversarial
> verification + evidence.**

------------------------------------------------------------------------

# Final Principle

A generated patch is not the result.

The result is:

``` text
PATCH
  +
EXPLOIT BLOCKED
  +
REGRESSION TESTS PASSED
  +
RESCAN CLEAN
  +
EVIDENCE
  =
VERIFIED
```

**VAJRA doesn't just fix vulnerabilities. It proves the fix.**
