# VAJRA — Vulnerability Assessment, Judgement & Remediation Agent

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

VAJRA is an **Autonomous Adversarial Vulnerability Remediation Agent** designed to demonstrate an end-to-end security workflow for vulnerable software.

Instead of stopping after finding a vulnerability or generating a patch, VAJRA follows the remediation through validation: it reproduces the original issue, reasons about the root cause, generates a targeted remediation, attacks the patched version, runs regression checks, rescans the result, and produces evidence of the outcome.

---

## 1. What is VAJRA?

Traditional vulnerability scanners are good at telling developers **what is wrong**. VAJRA focuses on the next question:

**Can an automated system fix the vulnerability and prove that the fix actually works?**

The demo implements this workflow:

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
PREFLIGHT
    ↓
ATTACK
    ↓
VERIFY
    ↓
RESCAN
    ↓
PROMOTE
```

The original target is never used as the remediation workspace. VAJRA creates a protected **VAJRA-TWIN** and performs analysis, patching, and validation there.

---

## 2. Core Differentiator

VAJRA combines:

- **AI-assisted reasoning** for understanding the vulnerability and generating remediation.
- **Deterministic security tooling** for analysis and validation.
- **Adversarial verification** to challenge the generated patch.
- **Evidence-oriented output** so the final result is backed by observable checks.

The security principle is simple:

> **A patch is not a solution until it survives its own attack.**

The reasoning layer can operate in two modes:

### Demo mode

Uses deterministic remediation logic so the demonstration remains reproducible and lightweight.

### Live LLM mode

Uses a code-capable LLM to reason about the locked finding and generate a targeted replacement source file. The LLM is not trusted with verification; execution, exploit replay, testing, and rescanning remain deterministic responsibilities.

---

## 3. Demonstrated Vulnerability Classes

The current demo focuses on two vulnerability classes:

### SQL Injection

The target contains an intentionally vulnerable user lookup flow in which untrusted input is incorporated into a SQL statement.

VAJRA can:

1. identify the SQL injection;
2. reproduce the vulnerable behavior;
3. identify unsafe query construction;
4. generate parameterized SQL;
5. replay adversarial SQL payloads;
6. verify that the payloads are blocked;
7. run regression tests;
8. rescan the patched code.

A representative remediation is:

```python
query = "SELECT id, name FROM users WHERE name = ?"
rows = get_db().execute(query, (name,)).fetchall()
```

### Command Injection

The target also contains an intentionally vulnerable command-execution path in which user-controlled input reaches a shell command.

VAJRA identifies the command-injection data flow and applies a targeted remediation that removes unsafe shell interpretation and uses structured command arguments where appropriate.

The patched version is then subjected to adversarial validation rather than being trusted merely because the source code changed.

---

## 4. End-to-End Pipeline

### 4.1 SAFE CLONE

The uploaded codebase is copied into an isolated working environment called **VAJRA-TWIN**.

This protects the original source from modification during analysis and remediation.

### 4.2 DISCOVER

VAJRA analyzes the target and identifies supported security findings.

The demo uses:

- Semgrep
- Tree-sitter
- AST-based semantic rules
- vulnerability-specific classification

The pipeline currently locks supported findings to:

- SQL injection
- Command injection

### 4.3 REPRODUCE

The identified vulnerability is executed against the vulnerable target.

The purpose is to establish that the finding represents an observable security problem before remediation begins.

### 4.4 REASON

VAJRA determines:

- vulnerability class;
- root cause;
- security impact;
- remediation strategy.

The finding identity is preserved throughout the remediation process so that the agent does not silently switch to fixing an unrelated issue.

### 4.5 PATCH

A targeted patch is generated and applied only to the VAJRA-TWIN.

The patch can be produced by:

- deterministic demo reasoning; or
- the configured live LLM provider.

### 4.6 PREFLIGHT

Before executing adversarial validation, VAJRA checks whether the generated source has the expected security properties.

Examples include checking for:

- parameterized SQL;
- removal of unsafe shell execution;
- syntactically valid Python;
- a patch that actually corresponds to the locked finding.

### 4.7 ATTACK

The generated patch is deliberately challenged with adversarial payloads.

For SQL injection, the demo uses multiple injection patterns.

For command injection, the demo uses payloads designed to test whether attacker-controlled input can still influence command execution.

The goal is not simply to inspect the patch, but to **try to break it**.

### 4.8 VERIFY

Regression and functional tests are executed against the patched code.

A patch is considered trustworthy only when the security validation and regression validation agree.

### 4.9 RESCAN

The patched VAJRA-TWIN is analyzed again to determine whether the original vulnerability remains.

This provides a second, independent confirmation after attack replay and regression testing.

### 4.10 PROMOTE

When the complete validation chain succeeds, the verified fixed codebase and supporting evidence can be returned as the remediation result.

---

## 5. Architecture

```text
                         ┌──────────────────────┐
                         │      React + Vite    │
                         │      Web Dashboard   │
                         └──────────┬───────────┘
                                    │
                                    │ REST API
                                    ▼
                         ┌──────────────────────┐
                         │       FastAPI        │
                         │      API Backend     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                    ┌──────────────────────────────┐
                    │       VAJRA Pipeline         │
                    │                              │
                    │ Clone → Discover → Reproduce │
                    │ Reason → Patch → Validate    │
                    │ Attack → Verify → Rescan     │
                    └──────────────┬───────────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             ▼                     ▼                     ▼
      ┌────────────┐       ┌──────────────┐       ┌────────────┐
      │ Semgrep /  │       │ LLM Reasoner │       │  pytest /  │
      │ Tree-sitter│       │              │       │ validation │
      │ / AST      │       │ Demo / Live  │       │            │
      └────────────┘       └──────────────┘       └────────────┘
                                   │
                                   ▼
                         ┌──────────────────────┐
                         │     VAJRA-TWIN       │
                         │ Isolated target copy │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Evidence + Patch Diff│
                         │ Verified Codebase    │
                         └──────────────────────┘
```

---

## 6. Technology Stack

The demo is built around a lightweight implementation of the proposed VAJRA architecture.

| Component | Technology |
|---|---|
| Backend | Python |
| API | FastAPI |
| Frontend | React + Vite |
| Containerization | Docker / Docker Compose |
| Database | PostgreSQL |
| Static analysis | Semgrep |
| Syntax / semantic analysis | Tree-sitter + AST |
| Dependency analysis | Syft / OSV-Scanner |
| Fuzzing / testing direction | Atheris / pytest |
| Reasoning | Code-capable LLM |
| Verification | Deterministic execution and tests |

The implementation intentionally keeps the demonstration lightweight while preserving the central VAJRA concept: **AI reasoning combined with deterministic proof**.

---

## 7. Project Structure

A typical VAJRA demo repository is organized around the frontend, backend, target code, and generated run artifacts:

```text
VAJRA-demo/
│
├── backend/
│   ├── main.py
│   ├── pipeline.py
│   ├── llm_reasoner.py
│   ├── analyzer.py
│   ├── dependency_scanner.py
│   ├── fuzzing.py
│   ├── evidence_report.py
│   ├── config.py
│   ├── db.py
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── index.html
│   └── package.json
│
├── runs/
│   └── <run-id>/
│       ├── original/
│       ├── vajra-twin/
│       ├── evidence.json
│       ├── evidence-report.html
│       ├── patch.diff
│       └── verified-fixed-codebase.zip
│
├── target_app/
│   ├── app.py
│   ├── test_app.py
│   └── README.md
│
├── docker-compose.yml
└── README.md
```

The exact repository contents can vary between demo versions as implementation details evolve.

---

## 8. Running the Demo

### Prerequisites

The recommended way to run the complete demo is with:

- Docker
- Docker Compose

No local Python virtual environment or Node.js installation is required for the containerized setup.

### Start VAJRA

From the project root:

```powershell
docker compose up --build
```

Check the running services:

```powershell
docker compose ps
```

The backend health endpoint is available at:

```text
http://localhost:8000/api/health
```

The web dashboard is served through the frontend container, typically at:

```text
http://localhost:8080
```

### Stop the demo

```powershell
docker compose down
```

To rebuild after source changes:

```powershell
docker compose down
docker compose up --build
```

---

## 9. Using the Dashboard

The normal demo flow is:

1. Open the VAJRA dashboard.
2. Upload a vulnerable `.zip` codebase or supported Python source.
3. Start a VAJRA run.
4. Watch the pipeline progress through the security stages.
5. Review discovered vulnerabilities.
6. Review reproduction evidence.
7. Review the remediation reasoning.
8. Inspect the generated patch diff.
9. Review adversarial validation.
10. Review regression verification.
11. Review the rescan result.
12. Download or inspect the resulting evidence and verified codebase.

The dashboard is designed to make the autonomous security loop visible rather than presenting VAJRA as a conventional CRUD application.

---

## 10. API

### Health

```http
GET /api/health
```

Returns service, version, database, and reasoning-mode information.

### Start a run

```http
POST /api/runs
```

Upload a supported codebase using the `file` form field.

Example:

```powershell
curl.exe -X POST http://localhost:8000/api/runs `
  -F "file=@D:\path\to\vulnerable-target.zip"
```

The API returns a run identifier.

### Get run status / evidence

```http
GET /api/runs/{run_id}
```

### List runs

```http
GET /api/runs
```

### Evidence

```http
GET /api/runs/{run_id}/evidence
```

### HTML evidence report

```http
GET /api/runs/{run_id}/report
```

### Patch diff

```http
GET /api/runs/{run_id}/patch-diff
```

### Verified codebase

```http
GET /api/runs/{run_id}/verified-codebase
```

---

## 11. Evidence and Proof

Every VAJRA run produces structured evidence.

The evidence records the stages of the remediation process and provides the information needed to understand how the final result was reached.

Typical evidence includes:

- run identifier;
- pipeline stages;
- discovered findings;
- vulnerability classification;
- reproduction result;
- root cause;
- remediation strategy;
- patch attempt;
- preflight result;
- adversarial attack results;
- regression-test result;
- rescan result;
- patch diff;
- final verification status.

This is the basis of VAJRA's **proof-carrying remediation** concept.

---

## 12. Security Model

VAJRA follows a simple trust boundary:

```text
ORIGINAL CODEBASE
       │
       ▼
   SAFE CLONE
       │
       ▼
   VAJRA-TWIN
       │
       ├── Analysis
       ├── Reproduction
       ├── Reasoning
       ├── Patching
       ├── Attack Replay
       ├── Regression Tests
       └── Rescan
               │
               ▼
      VERIFIED FIXED CODEBASE
```

The original codebase is treated as immutable during remediation.

The generated patch is not trusted merely because it was produced by an AI system.

Instead, VAJRA requires deterministic validation of the result.

---

## 13. Demo Target

The included demonstration target intentionally contains vulnerable application logic so the complete remediation workflow can be observed.

The primary demonstration cases are:

- SQL Injection
- Command Injection

The target also includes functional/regression tests so that security remediation can be checked against application behavior.

---

## 14. Demo vs Production

VAJRA is currently a **lightweight proof-of-concept demonstration**, not a complete enterprise vulnerability-management platform.

The purpose of the demo is to prove the central autonomous remediation loop:

```text
Find it
   ↓
Prove it
   ↓
Understand it
   ↓
Fix it
   ↓
Attack the fix
   ↓
Test the fix
   ↓
Rescan it
   ↓
Prove the result
```

A production implementation could extend this foundation with broader language support, stronger sandbox isolation, richer dependency intelligence, scalable execution, deeper fuzzing, CI/CD integration, and enterprise policy controls.

---

## 15. Development Milestones

### v0.1
- Initial lightweight VAJRA proof-of-concept.
- Basic vulnerability discovery/remediation loop.
- Safe clone / VAJRA-TWIN concept.

### v0.2
- Real Flask target execution.
- SQL injection reproduction and verification.
- Basic adversarial replay and regression testing.

### v0.3
- Provider-agnostic LLM reasoning layer.
- Structured remediation output.
- Demo/live reasoning modes.

### v0.4
- Live LLM patch generation.
- Bounded remediation retries.
- Patch syntax validation.
- Retry context.

### v0.5
- Real SQLite-backed vulnerable target.
- Genuine SQL injection behavior.
- Stronger structured LLM output.

### v0.6
- Evidence/proof-oriented output.
- Stronger verification architecture.

### v0.7
- Multi-vulnerability proof of concept.
- SQL injection + command injection.
- Vulnerability-specific reproduction and adversarial validation.

### v0.8
- Containerized full demo architecture.
- FastAPI backend and React/Vite dashboard.
- PostgreSQL-backed run persistence.
- Integrated analysis, dependency, reasoning, patching, adversarial validation, regression testing, and evidence workflow.
- Docker-based deployment path for the complete demonstration.
- Expanded run/evidence/report handling.

---

## 16. Why VAJRA?

Most automated security workflows end with:

> **"Vulnerability found."**

Some automated remediation systems go one step further:

> **"Patch generated."**

VAJRA aims to go further:

> **"Patch generated, attacked, tested, rescanned, and proven."**

That distinction is the core of the project.

### VAJRA

**Discover → Reproduce → Reason → Patch → Attack → Verify → Rescan**

**AI generates the remediation.  
Deterministic systems prove it.**

---

## 17. Project Identity

**Name:** VAJRA

**Full Form:** Vulnerability Assessment, Judgement & Remediation Agent

**Positioning:** Autonomous Adversarial Vulnerability Remediation Agent

**Core Statement:**

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

**Secondary USP:**

> **A patch is not a solution until it survives its own attack.**

---

## License

This project is a security research and demonstration prototype intended for controlled testing of intentionally vulnerable applications.
