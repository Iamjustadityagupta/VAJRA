# VAJRA — Vulnerability Assessment, Judgement & Remediation Agent

> **VAJRA doesn't just fix vulnerabilities. It proves the fix.**

VAJRA is an **Autonomous Adversarial Vulnerability Remediation Agent** that demonstrates an end-to-end workflow for discovering, reproducing, reasoning about, patching, and verifying security vulnerabilities in a codebase.

The central idea is simple:

> **A patch is not a solution until it survives its own attack.**

---

## 1. What is VAJRA?

Traditional vulnerability scanners primarily answer:

**"What is vulnerable?"**

VAJRA extends that workflow to:

**"Can the vulnerability be reproduced, can it be remediated, and can the remediation be demonstrated to work?"**

The demo follows this security workflow:

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

The original uploaded codebase is preserved while VAJRA creates an isolated **VAJRA-TWIN** workspace for analysis and remediation.

---

## 2. Core Capabilities

The current demo brings together:

- Vulnerability discovery
- Vulnerability reproduction
- Vulnerability classification
- AI-assisted root-cause reasoning
- Targeted patch generation
- Patch preflight validation
- Adversarial exploit replay
- Regression testing
- Post-remediation rescanning
- Evidence generation
- Patch-diff generation
- Verified fixed-codebase packaging
- Persistent run storage
- Web-based dashboard
- Dockerized deployment

The demonstrated vulnerability classes are:

- **SQL Injection**
- **Command Injection**

---

## 3. The VAJRA Workflow

### SAFE CLONE

The uploaded codebase is copied into a protected working environment.

VAJRA performs remediation against **VAJRA-TWIN**, rather than modifying the original submission directly.

### DISCOVER

The target is analyzed for supported security findings using static analysis and code-level inspection.

The demo integrates:

- Semgrep
- Tree-sitter
- Python AST analysis
- VAJRA-specific security rules

### REPRODUCE

A detected finding is actively exercised against the vulnerable target.

This establishes that the finding represents an observable security weakness before remediation is attempted.

### REASON

VAJRA determines:

- What the vulnerability is
- Where the unsafe data flow occurs
- Why the code is vulnerable
- What the security impact is
- What remediation strategy should be applied

The reasoning layer can operate in deterministic demo mode or through a configured live LLM provider.

### PATCH

A targeted remediation is generated and applied to the isolated VAJRA-TWIN.

The system is designed to preserve the application's intended behavior while removing the vulnerable construction.

### PREFLIGHT

The generated patch is checked before adversarial execution.

Examples include:

- Python syntax validation
- Parameterized SQL checks
- Unsafe shell-execution checks
- Structured subprocess validation
- Finding-specific remediation checks

### ATTACK

VAJRA deliberately attempts to exploit the patched application.

The patch is not trusted simply because the source code changed.

SQL injection and command-injection payloads are replayed against the patched target.

### VERIFY

Regression tests are executed against the remediated codebase.

Security validation and functional validation are both part of the verification chain.

### RESCAN

The patched VAJRA-TWIN is scanned again to determine whether the original security finding remains.

### PROMOTE

When the complete validation chain succeeds, VAJRA can produce the verified fixed codebase together with the supporting evidence and patch information.

---

## 4. Vulnerability Coverage

### SQL Injection

The demo contains intentionally vulnerable SQL query construction.

VAJRA demonstrates the remediation path from:

```text
User-controlled input
        ↓
Unsafe SQL construction
        ↓
SQL Injection
```

to:

```text
User-controlled input
        ↓
Parameterized query
        ↓
Input treated as data
```

The remediation uses parameter binding rather than incorporating attacker-controlled input into the SQL statement.

---

### Command Injection

The demo also contains intentionally vulnerable command-execution paths.

VAJRA identifies cases where attacker-controlled input can reach shell execution and applies a shell-free remediation strategy using structured command arguments.

The verification stage then attempts adversarial command-injection payloads against the patched implementation.

The important distinction is that VAJRA does not consider simple reflection of an input string to be proof of command execution. The validation process is intended to establish whether the injected command actually executes.

---

## 5. Architecture

```text
                    ┌──────────────────────────┐
                    │      React + Vite        │
                    │      Web Dashboard       │
                    └────────────┬─────────────┘
                                 │
                                 │ REST API
                                 ▼
                    ┌──────────────────────────┐
                    │         FastAPI          │
                    │       API Backend        │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │      VAJRA Pipeline      │
                    │                          │
                    │ Clone                    │
                    │ Discover                 │
                    │ Reproduce                │
                    │ Reason                   │
                    │ Patch                    │
                    │ Preflight                │
                    │ Attack                   │
                    │ Verify                   │
                    │ Rescan                   │
                    └────────────┬─────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
   │ Static       │      │ LLM Reasoner │      │ Regression & │
   │ Analysis     │      │              │      │ Verification │
   │              │      │ Demo / Live  │      │              │
   │ Semgrep      │      │              │      │ pytest       │
   │ Tree-sitter  │      │              │      │ AST checks   │
   │ AST          │      │              │      │ Attack replay│
   └──────────────┘      └──────────────┘      └──────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       VAJRA-TWIN         │
                    │    Isolated Codebase     │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       Evidence Layer     │
                    │                          │
                    │ evidence.json             │
                    │ evidence-report.html      │
                    │ patch.diff                │
                    │ verified-fixed-codebase  │
                    └──────────────────────────┘
```

---

## 6. Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React |
| Frontend tooling | Vite |
| Backend | Python |
| API framework | FastAPI |
| Database | PostgreSQL |
| Containerization | Docker |
| Orchestration | Docker Compose |
| Static analysis | Semgrep |
| Syntax / semantic analysis | Tree-sitter + Python AST |
| Dependency analysis | Syft / OSV tooling |
| Testing | pytest |
| Fuzzing support | Atheris |
| AI reasoning | Configurable code-capable LLM |
| Evidence | JSON + HTML reports |

---

## 7. Repository Structure

```text
VAJRA-demo/
│
├── .github/
│   └── workflows/
│       └── ci.yml
│
├── backend/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── config.py
│   ├── db.py
│   ├── dependency_scanner.py
│   ├── discovery.py
│   ├── Dockerfile
│   ├── evidence_report.py
│   ├── fuzzing.py
│   ├── llm_reasoner.py
│   ├── main.py
│   ├── models.py
│   ├── pipeline.py
│   ├── reasoning_demo.py
│   ├── requirements.txt
│   ├── semgrep.yml
│   ├── target_runner.py
│   ├── tree_analyzer.py
│   ├── test_analyzer.py
│   ├── test_discovery.py
│   ├── test_reasoner.py
│   └── tools/
│       └── install_security_tools.sh
│
├── frontend/
│   ├── src/
│   │   ├── config.js
│   │   ├── main.jsx
│   │   └── style.css
│   ├── Dockerfile
│   ├── index.html
│   ├── nginx.conf
│   ├── package.json
│   └── package-lock.json
│
├── target_app/
│   ├── app.py
│   ├── README.md
│   └── test_app.py
│
├── VAJRA-5-bug-test-targets/
│   ├── VAJRA-01_sql_concat.zip
│   ├── VAJRA-02_sql_fstring.zip
│   ├── VAJRA-03_command_subprocess.zip
│   ├── VAJRA-04_command_os_system.zip
│   └── VAJRA-05_mixed_two_findings.zip
│
├── runs/
│   └── <generated run artifacts>
│
├── .dockerignore
├── .env.example
├── .gitattributes
├── .gitignore
├── docker-compose.yml
├── docker-compose.prod.yml
├── README.md
├── start.ps1
└── start.sh
```

The `runs/` directory contains generated runtime artifacts and is not required to contain pre-existing run data for the application to start.

---

## 8. Running the Demo

### Prerequisites

The recommended setup uses:

- Docker
- Docker Compose

The application is containerized, so the backend, frontend, and database can be run together through Docker Compose.

### Start

From the project root:

```powershell
docker compose up --build
```

Check the containers:

```powershell
docker compose ps
```

### Application

The web interface is available through the frontend service:

```text
http://localhost:8080
```

The backend health endpoint is:

```text
http://localhost:8000/api/health
```

### Stop

```powershell
docker compose down
```

### Rebuild

After changing source code:

```powershell
docker compose down
docker compose up --build
```

---

## 9. Using VAJRA

The normal demonstration flow is:

1. Open the VAJRA dashboard.
2. Upload a vulnerable codebase.
3. Start a security analysis run.
4. Observe the discovery stage.
5. Review the reproduced vulnerability.
6. Review the root-cause reasoning.
7. Review the generated remediation.
8. Inspect patch preflight validation.
9. Observe adversarial attack replay.
10. Review regression verification.
11. Review the post-patch rescan.
12. Inspect the generated evidence and patch artifacts.

The supplied `VAJRA-5-bug-test-targets` directory contains five prepared demonstration targets covering SQL injection, command injection, and a mixed vulnerability scenario.

---

## 10. API

### Health

```http
GET /api/health
```

Returns the current VAJRA service health and runtime information.

### Start a run

```http
POST /api/runs
```

Accepts a supported codebase upload.

Example:

```powershell
curl.exe -X POST http://localhost:8000/api/runs `
  -F "file=@D:\path\to\vulnerable-target.zip"
```

### Retrieve a run

```http
GET /api/runs/{run_id}
```

### List runs

```http
GET /api/runs
```

### Retrieve evidence

```http
GET /api/runs/{run_id}/evidence
```

### Retrieve the HTML report

```http
GET /api/runs/{run_id}/report
```

### Retrieve the patch diff

```http
GET /api/runs/{run_id}/patch-diff
```

### Retrieve the verified codebase

```http
GET /api/runs/{run_id}/verified-codebase
```

---

## 11. Evidence

VAJRA produces structured evidence for each run.

A completed run can contain:

```text
runs/
└── VAJRA-XXXXXXXX/
    ├── original/
    ├── vajra-twin/
    ├── evidence.json
    ├── evidence-report.html
    ├── patch.diff
    └── verified-fixed-codebase.zip
```

The evidence captures the security workflow rather than only the final status.

Typical information includes:

- Run identifier
- Discovered findings
- Vulnerability classification
- Reproduction payload and result
- Root-cause analysis
- Remediation strategy
- Patch information
- Preflight validation
- Adversarial attack results
- Regression-test results
- Rescan results
- Remaining findings
- Final verification status

---

## 12. Security and Trust Model

VAJRA separates the original codebase from the remediation workspace:

```text
Original Upload
      │
      ▼
  SAFE CLONE
      │
      ▼
 VAJRA-TWIN
      │
      ├── Discover
      ├── Reproduce
      ├── Reason
      ├── Patch
      ├── Preflight
      ├── Attack
      ├── Verify
      └── Rescan
             │
             ▼
       Verified Result
```

The important trust boundary is between **AI-generated remediation** and **deterministic validation**.

The LLM can propose a remediation, but it does not get to declare the remediation successful.

The patch must still pass the validation pipeline.

---

## 13. AI Reasoning

VAJRA supports a configurable reasoning layer.

### Demo mode

Deterministic remediation logic provides reproducible behavior for demonstrations and controlled testing.

### Live mode

A configured LLM can analyze the locked finding and generate a targeted remediation.

The reasoning layer is expected to return structured information such as:

- Root cause
- Security impact
- Remediation strategy
- Complete patched source

Regardless of reasoning mode, the resulting patch is subjected to VAJRA's independent validation workflow.

---

## 14. Demo Targets

The repository includes five prepared vulnerable targets:

| Target | Demonstration |
|---|---|
| `VAJRA-01_sql_concat.zip` | SQL injection through string concatenation |
| `VAJRA-02_sql_fstring.zip` | SQL injection through formatted SQL construction |
| `VAJRA-03_command_subprocess.zip` | Command injection through subprocess shell execution |
| `VAJRA-04_command_os_system.zip` | Command injection through `os.system` |
| `VAJRA-05_mixed_two_findings.zip` | Combined SQL injection and command injection |

These targets are intentionally vulnerable and are provided for controlled demonstration and validation of the VAJRA workflow.

---

## 15. Deployment

The application is containerized with Docker Compose.

The repository includes separate Compose configurations for the normal demonstration environment and production-oriented deployment.

The deployment architecture consists of:

```text
                    Internet / User
                           │
                           ▼
                    React + Nginx
                           │
                           ▼
                        FastAPI
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
         PostgreSQL               VAJRA Engine
                                        │
                                        ▼
                                   VAJRA-TWIN
```

For a hosted deployment, the frontend can be exposed through a public web endpoint while the backend and database remain behind the application layer.

---

## 16. Project Scope

VAJRA is a **security research and demonstration prototype** focused on proving the autonomous remediation concept.

The current implementation demonstrates:

- Python code analysis
- SQL injection remediation
- Command injection remediation
- AI-assisted reasoning
- Isolated remediation
- Adversarial validation
- Regression testing
- Post-remediation rescanning
- Evidence-oriented results
- Containerized deployment

A larger production implementation could extend these foundations with broader programming-language coverage, stronger sandboxing, expanded vulnerability classes, richer dependency intelligence, CI/CD integration, scalable execution, policy controls, and enterprise workflow integration.

---

## 17. The VAJRA Principle

Most security automation stops at:

> **"Vulnerability found."**

Some systems continue to:

> **"Patch generated."**

VAJRA aims to complete the loop:

> **"Vulnerability found, reproduced, patched, attacked, tested, rescanned, and proven."**

That is the core idea behind VAJRA.

```text
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

### VAJRA

**AI generates the remediation.  
Deterministic systems prove it.**

---

## License

This project is a security research and demonstration prototype intended for controlled testing of intentionally vulnerable applications.
