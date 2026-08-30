"""Human-readable HTML evidence reports for completed VAJRA runs."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _status_class(status: str) -> str:
    return "pass" if str(status).lower() in {"pass", "verified", "blocked", "clean"} else "fail"


def _finding_kind(finding: dict[str, Any]) -> str:
    check_id = str(finding.get("check_id", ""))
    if "command" in check_id.lower():
        return "Command Injection"
    if "sql" in check_id.lower():
        return "SQL Injection"
    return check_id or "Unknown finding"


def render_evidence_report(evidence: dict[str, Any]) -> str:
    """Render stored evidence JSON into a self-contained HTML report."""
    run_id = evidence.get("run_id", "Unknown run")
    status = evidence.get("status", "UNKNOWN")
    findings = evidence.get("findings", [])
    processed = evidence.get("processed_findings", [])
    events = evidence.get("events", [])
    attacks = evidence.get("attack_results", [])
    blocked = sum(1 for item in attacks if item.get("status") == "BLOCKED")
    remaining = evidence.get("remaining_findings", "—")
    regression = bool(evidence.get("regression_tests"))

    finding_rows = []
    for finding in findings:
        location = finding.get("start", {}).get("line", "—")
        finding_rows.append(
            f"<tr><td>{_esc(_finding_kind(finding))}</td>"
            f"<td>{_esc(finding.get('path', '—'))}</td>"
            f"<td>{_esc(location)}</td>"
            f"<td>{_esc(finding.get('extra', {}).get('severity', '—'))}</td>"
            f"<td>{_esc(finding.get('extra', {}).get('message', '—'))}</td></tr>"
        )
    if not finding_rows:
        finding_rows.append('<tr><td colspan="5">No findings.</td></tr>')

    attack_rows = []
    for attack in attacks:
        attack_rows.append(
            f"<tr><td><code>{_esc(attack.get('payload', ''))}</code></td>"
            f"<td class='{_status_class(attack.get('status', ''))}'>{_esc(attack.get('status', ''))}</td>"
            f"<td><pre>{_esc(attack.get('response', ''))}</pre></td></tr>"
        )
    if not attack_rows:
        attack_rows.append('<tr><td colspan="3">No adversarial results recorded.</td></tr>')

    event_rows = []
    for event in events:
        event_rows.append(
            f"<tr><td>{_esc(event.get('stage', ''))}</td>"
            f"<td class='{_status_class(event.get('status', ''))}'>{_esc(event.get('status', ''))}</td>"
            f"<td>{_esc(event.get('message', ''))}</td></tr>"
        )

    reasoning = evidence.get("reasoning", {}) or {}
    diff = evidence.get("diff", "No patch diff recorded.")

    checks = [
        ("Exploit reproduced", any(e.get("stage") == "REPRODUCE" and e.get("status") == "pass" for e in events)),
        ("Patch generated", any(e.get("stage") == "PATCH" and e.get("status") == "pass" for e in events)),
        ("Patch preflight passed", any(e.get("preflight") is True for e in events if e.get("stage") == "PATCH")),
        ("Patch survived attack", any(e.get("stage") == "ATTACK" and e.get("status") == "pass" for e in events)),
        ("Regression tests passed", regression),
        ("Rescan clean", remaining == 0),
    ]
    check_html = "".join(
        f"<li class='{ 'pass' if passed else 'fail' }'>{'✓' if passed else '!'} {_esc(label)}</li>"
        for label, passed in checks
    )

    processed_sections = []
    for item in processed:
        kind = item.get("kind", "unknown")
        accepted = item.get("accepted", False)
        processed_sections.append(
            f"<div class='finding-card'><div class='finding-head'><h3>{_esc(kind)}</h3>"
            f"<span class='{_status_class('pass' if accepted else 'fail')}'>{'ACCEPTED' if accepted else 'REJECTED'}</span></div>"
            f"<p><b>File:</b> {_esc(item.get('file', '—'))}</p>"
            f"<p><b>Attempts:</b> {_esc(len(item.get('attempts', [])))}</p></div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VAJRA Evidence Report — {_esc(run_id)}</title>
<style>
:root {{ color-scheme: dark; --bg:#090a0c; --panel:#101114; --line:#2b2d31; --text:#eee; --muted:#98999d; --gold:#bca878; --green:#b9d6b2; --red:#d7a7a7; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px Arial,sans-serif; line-height:1.55; }}
main {{ max-width:1180px; margin:0 auto; padding:42px 28px 70px; }}
header {{ border-bottom:1px solid var(--line); padding-bottom:28px; margin-bottom:30px; }}
.eyebrow {{ color:var(--gold); font:11px monospace; letter-spacing:.18em; }}
h1 {{ margin:10px 0 4px; font-size:34px; }}
h2 {{ margin:0 0 18px; font-size:22px; }}
h3 {{ margin:0; font-size:17px; }}
.meta {{ color:var(--muted); }}
.badge {{ display:inline-block; border:1px solid #496248; color:var(--green); padding:7px 12px; font:12px monospace; margin-top:14px; }}
section {{ margin:28px 0; }}
.panel {{ background:var(--panel); border:1px solid var(--line); padding:22px; overflow:auto; }}
.summary {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }}
.metric {{ border:1px solid var(--line); padding:18px; }}
.metric b {{ display:block; font-size:25px; margin-top:6px; }}
.metric span {{ color:var(--muted); font:11px monospace; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; vertical-align:top; padding:11px 10px; border-bottom:1px solid var(--line); }}
th {{ color:var(--gold); font:11px monospace; letter-spacing:.08em; }}
.pass {{ color:var(--green); }} .fail {{ color:var(--red); }}
code,pre {{ font-family:monospace; }}
pre {{ white-space:pre-wrap; margin:0; color:#adb9a8; max-height:300px; overflow:auto; }}
ul.checks {{ list-style:none; padding:0; margin:0; }}
ul.checks li {{ padding:7px 0; font-family:monospace; }}
.finding-grid {{ display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }}
.finding-card {{ border:1px solid var(--line); padding:18px; }}
.finding-head {{ display:flex; justify-content:space-between; gap:20px; align-items:center; }}
.finding-head span {{ font:11px monospace; }}
.diff pre {{ font-size:12px; line-height:1.7; }}
footer {{ margin-top:45px; padding-top:20px; border-top:1px solid var(--line); color:var(--muted); font:11px monospace; }}
@media(max-width:760px) {{ .summary,.finding-grid {{ grid-template-columns:1fr; }} main {{ padding:28px 16px 50px; }} h1 {{ font-size:28px; }} }}
</style>
</head>
<body>
<main>
<header>
<div class="eyebrow">PROOF-CARRYING REMEDIATION / EVIDENCE REPORT</div>
<h1>VAJRA Run {_esc(run_id)}</h1>
<div class="meta">Generated from the stored run evidence.</div>
<div class="badge">FINAL STATUS: {_esc(status)}</div>
</header>

<section class="summary">
<div class="metric"><span>FINDINGS DISCOVERED</span><b>{len(findings)}</b></div>
<div class="metric"><span>ATTACKS BLOCKED</span><b>{blocked}/{len(attacks)}</b></div>
<div class="metric"><span>REGRESSION</span><b>{'PASS' if regression else 'FAIL'}</b></div>
<div class="metric"><span>REMAINING FINDINGS</span><b>{_esc(remaining)}</b></div>
</section>

<section><div class="panel"><h2>Verification Checklist</h2><ul class="checks">{check_html}</ul></div></section>

<section><div class="panel"><h2>Discovered Findings</h2><table><thead><tr><th>TYPE</th><th>FILE</th><th>LINE</th><th>SEVERITY</th><th>DESCRIPTION</th></tr></thead><tbody>{''.join(finding_rows)}</tbody></table></div></section>

<section><h2>Processed Findings</h2><div class="finding-grid">{''.join(processed_sections) or '<div class="panel">No processed findings.</div>'}</div></section>

<section><div class="panel"><h2>Reasoning</h2><p><b>Finding:</b> {_esc(reasoning.get('finding_kind', '—'))}</p><p><b>Root cause:</b> {_esc(reasoning.get('root_cause', '—'))}</p><p><b>Impact:</b> {_esc(reasoning.get('impact', '—'))}</p><p><b>Remediation:</b> {_esc(reasoning.get('remediation', '—'))}</p><p><b>Mode:</b> {_esc(reasoning.get('mode', evidence.get('llm_mode', '—')))} &nbsp; <b>Model:</b> {_esc(reasoning.get('model', '—'))}</p></div></section>

<section><div class="panel"><h2>Adversarial Validation</h2><table><thead><tr><th>PAYLOAD</th><th>STATUS</th><th>RESPONSE</th></tr></thead><tbody>{''.join(attack_rows)}</tbody></table></div></section>

<section><div class="panel diff"><h2>Patch Diff</h2><pre>{_esc(diff)}</pre></div></section>

<section><div class="panel"><h2>Regression Evidence</h2><pre>{_esc(evidence.get('pytest_output', 'No regression output recorded.'))}</pre></div></section>

<section><div class="panel"><h2>Run Timeline</h2><table><thead><tr><th>STAGE</th><th>STATUS</th><th>MESSAGE</th></tr></thead><tbody>{''.join(event_rows)}</tbody></table></div></section>

<footer>VAJRA — No patch is trusted until the original exploit fails, regression tests pass, and the post-patch rescan is clean.</footer>
</main>
</body>
</html>"""


def write_report(run_dir: Path, evidence: dict[str, Any]) -> Path:
    report = run_dir / "evidence-report.html"
    report.write_text(render_evidence_report(evidence), encoding="utf-8")
    return report
