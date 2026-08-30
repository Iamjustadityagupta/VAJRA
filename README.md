# VAJRA Demo

**Vulnerability Assessment, Judgement & Remediation Agent**

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

## Overview

VAJRA is a lightweight proof-of-concept demonstrating an autonomous
vulnerability-remediation loop.

The v0.7 milestone expands the demonstration from a single vulnerability
to a multi-vulnerability remediation workflow and validates the
resulting fixes with adversarial replay, regression testing, and
post-patch rescanning.

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
VERIFY
    ↓
RESCAN
    ↓
VERIFIED
```

A successful run produces a verified fixed codebase, patch diff, and
evidence report.

------------------------------------------------------------------------

# What VAJRA Demonstrates

The current proof-of-concept demonstrates:

-   Safe cloning of an uploaded target codebase into a **VAJRA-TWIN**
-   Vulnerability discovery using Semgrep when available
-   Deterministic Python fallback discovery rules for the seeded demo
    vulnerabilities
-   Vulnerability reproduction against the target application
-   Finding-aware reasoning and remediation
-   Minimal targeted patch generation
-   Patch syntax and security preflight
-   Vulnerability-specific adversarial replay
-   Regression testing with `pytest`
-   Post-patch vulnerability rescanning
-   Evidence collection for the complete remediation process
-   Verified fixed-codebase packaging after successful verification

The core security principle is:

> **No patch is trusted until the original exploit fails, regression
> tests pass, and the post-patch rescan is clean.**

An LLM-generated patch is therefore treated as a proposal, not as proof.

------------------------------------------------------------------------

# v0.7 Status

**v0.7 is the current stable milestone.**

The complete multi-vulnerability demonstration has been successfully
verified with:

``` text
SAFE CLONE              ✓
DISCOVER                ✓
REPRODUCE               ✓
REASON                  ✓
PATCH                   ✓
PATCH PREFLIGHT         ✓
ADVERSARIAL VALIDATION  7/7 attacks blocked
REGRESSION TESTS        ✓
RESCAN                  ✓
REMAINING FINDINGS      0
EVIDENCE                ACCEPTED
FINAL STATUS            VERIFIED
```

The demo target contains two supported vulnerability classes:

1.  SQL Injection
2.  Command Injection

The combined adversarial validation covers **7 payloads**:

### SQL Injection --- 4 payloads

``` text
' OR '1'='1
" OR "1"="1
' UNION SELECT NULL,NULL--
admin'--
```

### Command Injection --- 3 payloads

``` text
localhost & echo VAJRA_PWNED
localhost && echo VAJRA_PWNED
localhost | echo VAJRA_PWNED
```

The command-injection payloads use shell separators that are meaningful
for the Windows demonstration environment.

------------------------------------------------------------------------

# v0.7 Remediation Flow

A vulnerability is considered remediated only when all required stages
succeed:

``` text
1.  Discovered
2.  Reproduced
3.  Root cause reasoned about
4.  Targeted patch generated
5.  Patch preflight passed
6.  Applicable attacks blocked
7.  Regression tests passed
8.  Post-patch rescan is clean
9.  Evidence is produced
```

Only then does VAJRA return:

``` text
VERIFIED
```

If a candidate patch fails adversarial validation or regression testing,
VAJRA rejects it and restores the original source before attempting
another bounded remediation attempt.

------------------------------------------------------------------------

# Vulnerabilities in the Demo Target

The deliberately vulnerable Flask target contains two vulnerabilities in
the same codebase.

## 1. SQL Injection

The vulnerable user lookup originally follows this pattern:

``` python
name = request.args.get("name", "")

query = "SELECT id, name FROM users WHERE name = '" + name + "'"
rows = get_db().execute(query).fetchall()
```

The deterministic remediation converts it to parameterized SQL:

``` python
query = "SELECT id, name FROM users WHERE name = ?"
rows = get_db().execute(query, (name,)).fetchall()
```

The attack suite verifies that injected SQL no longer changes the query
structure.

------------------------------------------------------------------------

## 2. Command Injection

The vulnerable `/ping` route originally follows this pattern:

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

The remediation removes shell execution and passes the
attacker-controlled value as a separate argument.

The v0.7 implementation uses the current Python interpreter with
structured subprocess arguments so that the demo works consistently on
Windows:

``` python
output = subprocess.check_output(
    [
        sys.executable,
        "-c",
        "print('PING', __import__('sys').argv[1])",
        host
    ],
    text=True,
    timeout=3
)
```

The important security properties are:

-   `shell=True` is removed
-   The host value is not concatenated into a shell command
-   The host value is passed as data
-   The patch is validated before attack replay
-   Adversarial payloads must fail to produce command execution
-   The application must still satisfy its regression tests

------------------------------------------------------------------------

# Finding-Aware Reasoning

One of the important v0.7 improvements is that remediation is tied to
the **original finding identity**.

The target contains both SQL injection and command injection. Earlier
implementations could identify a vulnerable pattern in the source
without reliably respecting which finding was currently being processed.

v0.7 fixes this by:

-   Classifying the original finding
-   Locking the vulnerability class through remediation
-   Passing the finding kind explicitly into the reasoning layer
-   Selecting the corresponding patch strategy
-   Selecting the corresponding attack suite
-   Preventing a patch for one vulnerability from being used to
    remediate another

This enables the same target codebase to contain multiple vulnerability
classes without cross-remediation.

------------------------------------------------------------------------

# Patch Preflight

Candidate patches are checked before adversarial replay.

## SQL Injection

The preflight checks for:

-   Valid Python syntax
-   Removal of attacker-controlled SQL concatenation
-   Parameterized SQL binding

## Command Injection

The preflight uses Python AST inspection and source checks to validate
that:

-   The patched Python is syntactically valid
-   `shell=True` is not retained
-   The command is not constructed by concatenating `host`
-   A subprocess invocation remains
-   Structured list/tuple arguments are used

Preflight is an early safety gate. Passing preflight does **not** mean
the patch is trusted; the patch must still survive adversarial
validation and regression testing.

------------------------------------------------------------------------

# Adversarial Validation

VAJRA replays vulnerability-specific attack payloads against the patched
VAJRA-TWIN.

The v0.7 target produces:

``` text
SQL Injection        4/4 blocked
Command Injection    3/3 blocked
---------------------------------
Total                 7/7 blocked
```

For command injection, VAJRA does not simply search the response for the
marker string.

A safe patch may legitimately reflect attacker-controlled input as data.
The validator therefore distinguishes:

``` text
PING <exact supplied payload>
```

from output showing that an additional command was actually executed.

This prevents reflected attack input from being incorrectly treated as
proof of successful exploitation.

------------------------------------------------------------------------

# Regression Verification

Regression testing is a separate trust gate after adversarial replay.

The backend:

1.  Prefers `pytest`
2.  Records the test output
3.  Treats genuine application test failures as failures
4.  Can use a controlled direct-test fallback when `pytest` is
    unavailable or test collection fails
5.  Never uses the fallback to hide genuine application regressions

The v0.7 target regression suite passes successfully before a
remediation is accepted.

------------------------------------------------------------------------

# Post-Patch Rescan

After all findings have been processed, VAJRA rescans the modified
VAJRA-TWIN.

A successful run requires:

``` text
remaining findings = 0
```

The final status is:

``` text
VERIFIED
```

only when both the remediation workflow and the clean rescan succeed.

If a finding remains, the run is:

``` text
FAILED
```

VAJRA does not force a successful verification state.

------------------------------------------------------------------------

# Evidence and Artifacts

Each run creates evidence describing the remediation process.

The evidence includes:

-   Run ID
-   Discovery results
-   Vulnerability classes
-   Reproduction payload and response
-   Root cause
-   Impact
-   Remediation strategy
-   Patch information
-   Patch diff
-   Patch preflight result
-   Adversarial attack results
-   Regression results
-   Rescan result
-   Final verification status
-   Processed finding information
-   Bounded remediation attempts

For a verified run, VAJRA also packages the fixed codebase.

The backend exposes:

``` text
GET /api/runs/{run_id}/evidence
GET /api/runs/{run_id}/verified-codebase
```

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
             ┌──────────────────┼──────────────────┐
             │                  │                  │
             ▼                  ▼                  ▼
       Discovery            Reasoning          Verification
       Semgrep /            Demo or Live        Preflight
       Python Rules         LLM Reasoner        Attack Replay
                                                 Regression
                                                 Rescan
             │                  │                  │
             └──────────────────┼──────────────────┘
                                ▼
                       ┌──────────────────┐
                       │    VAJRA-TWIN    │
                       │ Isolated working │
                       │      copy        │
                       └────────┬─────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Vulnerable Flask │
                       │   Demo Target    │
                       └──────────────────┘
```

The original uploaded codebase is protected separately from the
remediation working copy.

------------------------------------------------------------------------

# Repository Structure

``` text
VAJRA-demo/
│
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── llm_reasoner.py
│   ├── reasoning_demo.py
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
├── .env.example
├── .gitattributes
├── .gitignore
├── README.md
└── vajra-demo-target.zip
```

Runtime-generated run data is stored under:

``` text
runs/
└── VAJRA-<RUN_ID>/
    ├── original/
    ├── vajra-twin/
    ├── upload.zip
    ├── evidence.json
    └── verified-fixed-codebase.zip
```

The verified codebase archive is produced only for a successful
`VERIFIED` run.

------------------------------------------------------------------------

# Technology Stack

-   **Python**
-   **FastAPI** --- VAJRA backend/API
-   **React + Vite** --- dashboard frontend
-   **Flask** --- deliberately vulnerable demonstration target
-   **SQLite** --- target application's demonstration database
-   **Semgrep** --- discovery when available
-   **Deterministic Python rules** --- fallback discovery for the seeded
    demo
-   **OpenAI-compatible LLM layer** --- optional live reasoning
-   **pytest** --- regression testing

------------------------------------------------------------------------

# Running the Demo

## 1. Backend

Create and activate a Python virtual environment, then install the
backend dependencies:

``` bash
cd backend
pip install -r requirements.txt
```

Start the FastAPI service:

``` bash
uvicorn main:app --reload
```

The backend exposes:

``` text
GET  /api/health
GET  /api/llm-status
POST /api/demo/run
GET  /api/runs/{run_id}/evidence
GET  /api/runs/{run_id}/verified-codebase
```

------------------------------------------------------------------------

## 2. Frontend

From the frontend directory:

``` bash
cd frontend
npm install
npm run dev
```

The frontend is a React/Vite dashboard for visualizing the VAJRA
pipeline and verification evidence.

------------------------------------------------------------------------

# Environment Configuration

Copy `.env.example` to `.env` in the project root.

The demonstration configuration is:

``` text
LLM_PROVIDER=demo
LLM_API_KEY=
LLM_MODEL=gpt-4.1-mini
VAJRA_MAX_ATTEMPTS=2
```

Demo mode is deterministic and can run without an LLM API key.

Live LLM reasoning can be configured through the environment when a
supported provider and API key are available.

------------------------------------------------------------------------

# Demo Target

The supplied target archive contains the deliberately vulnerable Flask
application used by the POC.

It contains:

``` text
app.py
test_app.py
```

The target is intentionally vulnerable and exists only for local
security demonstration and validation.

Do not deploy the vulnerable target as a production application.

------------------------------------------------------------------------

# API Run Flow

The main demonstration endpoint is:

``` text
POST /api/demo/run
```

It accepts a target codebase archive and executes the remediation
pipeline.

A successful response contains the run ID, event stream, findings,
reasoning information, attack results, regression information, rescan
result, and verification status.

For a verified run, artifact links are also returned for:

``` text
Verified fixed codebase
Evidence report
```

------------------------------------------------------------------------

# Version History

## v0.1 --- Initial POC Scaffold

-   Created the lightweight FastAPI + React/Vite application structure.
-   Added the vulnerable target application and basic test harness.
-   Established the VAJRA-TWIN concept for safe remediation.
-   Added the initial remediation dashboard.

## v0.2 --- Working Deterministic Security Loop

-   Added safe ZIP extraction and VAJRA-TWIN creation.
-   Added vulnerability discovery with Semgrep when available and
    deterministic fallback detection.
-   Added actual SQL-injection reproduction against the cloned Flask
    target.
-   Added deterministic patch generation.
-   Added adversarial payload replay.
-   Added pytest regression verification.
-   Added post-patch rescan.
-   Added evidence JSON for each run.

## v0.3 --- AI Reasoning Layer

-   Added the `LLMReasoner` abstraction.
-   Added root-cause, impact, and remediation reasoning.
-   Added structured patch-generation support.
-   Added live and demo reasoning modes.
-   Added environment-based LLM configuration.

## v0.4 --- Bounded Remediation Loop

-   Added bounded patch attempts.
-   Candidate patches are rejected when adversarial validation fails.
-   Candidate patches are rejected when regression tests fail.
-   Failed candidates are rolled back before another reasoning attempt.
-   Previous validation failures can be supplied to the next reasoning
    attempt.
-   Added patch syntax validation before applying generated Python.
-   Improved frontend visibility of reasoning and verification state.

## v0.5 --- Realistic Vulnerable Target

-   Replaced simulated database behavior with a real SQLite-backed
    target.
-   SQL injection now produces actual unintended database results.
-   Updated regression tests for real application behavior.
-   Improved attack-result evaluation using application responses.
-   Strengthened the structured LLM output contract.
-   Fixed the frontend JSX implementation and improved dashboard state
    display.

## v0.6 --- Evidence-Backed Final Output

-   Added a verified fixed-codebase ZIP for successful runs.
-   Added a downloadable evidence-report endpoint.
-   Added final-output actions to the dashboard.
-   Added model information to the AI Reasoning panel.
-   Improved live LLM configuration through environment-controlled model
    selection.
-   Preserved deterministic fallback for offline demos.
-   Preserved the trust boundary: an LLM-generated patch is not accepted
    until validation succeeds.

## v0.7 --- Multi-Vulnerability Autonomous Remediation

-   Expanded the POC from a single SQL-injection scenario to multiple
    vulnerability classes.
-   Added SQL injection and command injection as supported findings.
-   Added vulnerability-specific reproduction.
-   Added vulnerability-specific remediation strategies.
-   Added vulnerability-specific adversarial payload suites.
-   Added patch preflight validation before adversarial replay.
-   Added finding-aware reasoning so each finding receives the correct
    remediation strategy.
-   Locked finding identity through the remediation pipeline.
-   Added aggregated attack evidence across processed findings.
-   Added AST-based command-injection preflight validation.
-   Added bounded retry behavior after validation or regression
    failures.
-   Hardened regression verification with pytest-first execution and a
    controlled direct-test fallback.
-   Made the command-injection remediation compatible with the Windows
    demonstration environment.
-   Improved command-injection attack evaluation so reflected attacker
    input is not mistaken for successful command execution.
-   Completed the full v0.7 verification loop with **7/7 adversarial
    attacks blocked, regression tests passing, a clean rescan, and final
    evidence accepted**.

> Patch-level development work during the v0.7 line is consolidated into
> the v0.7 milestone history rather than listed as separate README
> releases.

------------------------------------------------------------------------

# Deliberately Deferred Capabilities

The broader VAJRA architecture can eventually include capabilities that
are intentionally outside this lightweight POC:

-   Docker-grade isolation
-   PostgreSQL
-   Tree-sitter-based multi-language analysis
-   Syft / SBOM generation
-   OSV-Scanner
-   Atheris fuzzing
-   Broad multi-language vulnerability support
-   Production deployment and promotion
-   Large-scale multi-agent orchestration
-   Full dependency and supply-chain analysis

The current project prioritizes a credible, demonstrable end-to-end
security remediation loop over implementing every proposed production
component.

------------------------------------------------------------------------

# v0.7 Milestone Summary

VAJRA v0.7 demonstrates the complete concept:

``` text
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
VERIFIED
```

The defining result is not simply that VAJRA can generate a patch.

It is that VAJRA can **generate a targeted patch, attack that patch, run
regression tests, rescan the result, and refuse to trust the remediation
unless the evidence supports the fix.**

**v0.7: VERIFIED.**
