import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const API = 'http://localhost:8000';
const STAGES = ['SAFE CLONE', 'DISCOVER', 'REPRODUCE', 'REASON', 'PATCH', 'ATTACK', 'VERIFY', 'RESCAN'];

function findingLabel(finding, index) {
  const checkId = String(finding?.check_id || '').toLowerCase();
  const message = String(finding?.extra?.message || '').toLowerCase();
  if (checkId.includes('command') || message.includes('subprocess')) return 'Command Injection';
  if (checkId.includes('sql') || message.includes('sql')) return 'SQL Injection';
  return finding?.check_id || `Finding ${index + 1}`;
}

function statusForFinding(processed) {
  return processed?.accepted ? 'FIXED' : 'FAILED';
}

function severityForFinding(finding) {
  return String(finding?.extra?.severity || finding?.severity || 'UNSPECIFIED').toUpperCase();
}

function App() {
  const [file, setFile] = useState(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [selected, setSelected] = useState(null);

  async function runDemo() {
    if (!file) return;
    setRunning(true);
    setResult(null);
    setSelected(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await fetch(`${API}/api/demo/run`, { method: 'POST', body: formData });
      if (!response.ok) throw new Error(`VAJRA API returned HTTP ${response.status}`);
      setResult(await response.json());
    } catch (error) {
      setResult({ status: 'FAILED', events: [{ stage: 'SYSTEM', status: 'fail', message: error.message }] });
    } finally {
      setRunning(false);
    }
  }

  const events = result?.events || [];
  const eventMap = useMemo(() => Object.fromEntries(events.map((event) => [event.stage, event])), [events]);
  const attackResults = result?.attack_results || [];
  const findings = result?.findings || [];
  const processed = result?.processed_findings || [];
  const blocked = attackResults.filter((item) => item.status === 'BLOCKED').length;
  const regressionPassed = result?.regression_tests === true || eventMap.VERIFY?.status === 'pass';
  const attemptsUsed = Array.isArray(result?.attempts) ? result.attempts.length : 0;
  const maxAttempts = Number(result?.max_attempts || 0);
  const twinStatus = result?.status === 'VERIFIED' ? 'VERIFIED' : running ? 'REMEDIATING' : 'ISOLATED';
  const rescanRemaining = Number.isFinite(Number(result?.remaining_findings)) ? Number(result.remaining_findings) : null;

  const checks = [
    ['Exploit reproduced', eventMap.REPRODUCE?.status === 'pass'],
    ['Patch generated', events.some((e) => e.stage === 'PATCH' && e.status === 'pass')],
    ['Patch preflight passed', events.some((e) => e.stage === 'PATCH' && e.preflight === true)],
    ['Patch survived attack', eventMap.ATTACK?.status === 'pass'],
    ['Regression tests passed', regressionPassed],
    ['Rescan clean', eventMap.RESCAN?.status === 'pass' && rescanRemaining === 0],
  ];

  const stageEvent = (stage) => eventMap[stage];
  const timelineClass = (stage) => {
    const event = stageEvent(stage);
    if (!event) return '';
    return event.status === 'fail' ? 'failed' : 'done';
  };

  return (
    <div className="app">
      <header>
        <div><div className="brand">VAJRA</div><div className="tag">Autonomous Adversarial Vulnerability Remediation</div></div>
        <div className="header-right"><div className="version">v0.8</div><div className="badge">AI KAVACH • TCQ 26</div></div>
      </header>
      <main>
        <section className="hero">
          <div>
            <div className="eyebrow">PROOF-CARRYING REMEDIATION</div>
            <h1>Don't just patch.<br /><span>Prove the fix.</span></h1>
            <p>VAJRA discovers a vulnerability, reproduces it, reasons over the evidence, generates a targeted patch, attacks that patch, and verifies the result.</p>
          </div>
          <div className="upload">
            <label>CODEBASE</label>
            <div className="drop">{file ? <><strong>{file.name}</strong><small>Ready for VAJRA-TWIN</small></> : <><strong>Upload a vulnerable .zip</strong><small>Use the included demo target</small></>}</div>
            <input type="file" accept=".zip" onChange={(event) => setFile(event.target.files?.[0] || null)} />
            <button onClick={runDemo} disabled={!file || running}>{running ? 'RUNNING VAJRA…' : 'START REMEDIATION'}</button>
          </div>
        </section>

        {running && <div className="running"><div className="spinner" />VAJRA is executing the remediation loop…</div>}

        {result && (
          <section className="workspace">
            <div className="topline">
              <div><label>RUN</label><strong>{result.run_id || 'LOCAL RUN'}</strong></div>
              <div className="topline-right"><div className="twin"><span>VAJRA-TWIN</span><b>{twinStatus}</b></div><div className={`status ${result.status === 'VERIFIED' ? 'good' : 'bad'}`}>{result.status}</div></div>
            </div>

            <div className="pipeline">
              {STAGES.map((stage, index) => {
                const event = stageEvent(stage);
                const passed = event?.status === 'pass';
                const failed = event?.status === 'fail';
                return <React.Fragment key={stage}><button className={`stage ${timelineClass(stage)}`} onClick={() => event && setSelected(event)}><span>{passed ? '✓' : failed ? '!' : index + 1}</span>{stage}</button>{index < STAGES.length - 1 && <div className="line" />}</React.Fragment>;
              })}
            </div>

            <div className="run-timeline">
              <div className="timeline-head">
                <div>
                  <label>RUN TIMELINE</label>
                  <h2>Evidence-backed execution history</h2>
                </div>
                <span>{events.length} recorded events</span>
              </div>
              <div className="timeline-list">
                {events.map((event, index) => {
                  const passed = event.status === 'pass';
                  const failed = event.status === 'fail';
                  const stageName = String(event.stage || 'SYSTEM').replaceAll('_', ' ');
                  const detail = event.message || event.root_cause || event.remediation || 'Event recorded.';
                  return (
                    <button
                      className={`timeline-event ${passed ? 'passed' : ''} ${failed ? 'failed' : ''}`}
                      key={`${event.stage}-${event.attempt || 0}-${index}`}
                      onClick={() => setSelected(event)}
                    >
                      <span className="timeline-node">{passed ? '✓' : failed ? '!' : '•'}</span>
                      <span className="timeline-copy">
                        <b>{stageName}</b>
                        <small>{detail}</small>
                      </span>
                      <span className="timeline-meta">
                        {event.attempt ? `ATTEMPT ${event.attempt}` : 'EVENT'}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="summary-grid">
              <div className="summary-card"><label>FINDINGS</label><strong>{findings.length}</strong><span>discovered</span></div>
              <div className="summary-card"><label>REMEDIATED</label><strong>{processed.filter((item) => item.accepted).length}/{findings.length}</strong><span>findings fixed</span></div>
              <div className="summary-card"><label>ATTACKS</label><strong>{blocked}/{attackResults.length}</strong><span>blocked</span></div>
              <div className="summary-card"><label>RESCAN</label><strong>{rescanRemaining === null ? '—' : rescanRemaining}</strong><span>findings remaining</span></div>
              <div className="summary-card"><label>REMEDIATION ATTEMPTS</label><strong>{attemptsUsed}{maxAttempts ? `/${maxAttempts}` : ''}</strong><span>bounded attempts used</span></div>
            </div>

            <div className="grid">
              <div className="card finding">
                <label>FINDINGS</label>
                <h2>{findings.length ? `${findings.length} vulnerabilities discovered` : 'Clean'}</h2>
                <div className="finding-list">
                  {findings.map((finding, index) => {
                    const item = processed[index];
                    return <button className="finding-item" key={`${finding.check_id}-${index}`} onClick={() => item && setSelected({ stage: findingLabel(finding, index), ...item })}>
                      <div><b>{findingLabel(finding, index)}</b><small>{finding.path || '—'}:{finding.start?.line || '—'}</small><small className="finding-meta">Severity: {severityForFinding(finding)}</small></div>
                      <span className={item?.accepted ? 'pill good' : 'pill bad'}>{item ? statusForFinding(item) : 'DISCOVERED'}</span>
                    </button>;
                  })}
                </div>
                <div className="metric"><span>Discovery engine</span><b>{result.engine || '—'}</b></div>
              </div>

              <div className="card reasoning"><label>AI REASONING</label><h2>{result.llm_mode === 'live' ? 'LIVE LLM' : 'DEMO REASONER'}</h2><p><b>Root cause:</b> {result.reasoning?.root_cause || '—'}</p><p><b>Remediation:</b> {result.reasoning?.remediation || '—'}</p><div className="metric"><span>Model</span><b>{result.reasoning?.model || '—'}</b></div><div className="metric"><span>Attempts</span><b>{attemptsUsed}/{maxAttempts}</b></div>
                <div className="retry-track"><span>RETRY BUDGET</span><div className="retry-bars">{Array.from({ length: Math.max(maxAttempts, 1) }, (_, i) => <i className={i < attemptsUsed ? 'used' : ''} key={i} />)}</div></div></div>

              <div className="card attack"><label>ADVERSARIAL VALIDATION</label><h2>{blocked}/{attackResults.length} attacks blocked</h2>{attackResults.map((item, index) => <div className="attackrow" key={`${item.payload}-${index}`}><code>{item.payload}</code><b>{item.status}</b></div>)}</div>

              <div className="card verify"><label>VERIFICATION</label><h2>{result.status === 'VERIFIED' ? 'Evidence accepted' : 'Verification incomplete'}</h2>{checks.map(([text, passed]) => <div className={`check ${passed ? '' : 'unchecked'}`} key={text}><span>{passed ? '✓' : '!'}</span>{text}</div>)}</div>

              <div className="card rescan"><label>RESCAN RESULT</label><h2>{rescanRemaining === 0 ? 'Clean rescan' : `${rescanRemaining ?? '—'} findings remain`}</h2><div className="rescan-stats"><div><span>Pre-patch</span><b>{findings.length}</b></div><div><span>Resolved</span><b>{processed.filter((item) => item.accepted).length}</b></div><div><span>Remaining</span><b>{rescanRemaining ?? '—'}</b></div></div><p>Post-patch discovery engine: <b>{result.post_rescan_engine || '—'}</b></p></div>

              <div className="card diff"><label>PATCH DIFF</label><pre>{result.diff || 'No changes.'}</pre></div>
            </div>

            <div className="artifacts">
              <div><label>VERIFIED OUTPUT</label><h2>{result.status === 'VERIFIED' ? 'Remediation package ready' : 'Run artifacts'}</h2><p>{result.status === 'VERIFIED' ? 'The fixed VAJRA-TWIN has passed adversarial validation, regression testing, and rescan.' : 'Inspect the available run evidence to diagnose the verification result.'}</p></div>
              <div className="artifact-actions">
                {result.artifacts?.evidence_report && <a href={`${API}${result.artifacts.evidence_report}`} target="_blank" rel="noreferrer">VIEW EVIDENCE REPORT</a>}
                {result.artifacts?.evidence_json && <a href={`${API}${result.artifacts.evidence_json}`} target="_blank" rel="noreferrer">VIEW EVIDENCE JSON</a>}
                {result.artifacts?.patch_diff && <a href={`${API}${result.artifacts.patch_diff}`} target="_blank" rel="noreferrer">DOWNLOAD PATCH DIFF</a>}
                {result.artifacts?.verified_codebase && <a href={`${API}${result.artifacts.verified_codebase}`} target="_blank" rel="noreferrer">DOWNLOAD VERIFIED CODEBASE</a>}
              </div>
            </div>

            {selected && <div className="detail"><button onClick={() => setSelected(null)}>×</button><label>{selected.stage}</label><h2>{selected.message || selected.kind || 'Finding details'}</h2><pre>{JSON.stringify(selected, null, 2)}</pre></div>}
          </section>
        )}
        <footer><span>SAFE CLONE → DISCOVER → REPRODUCE → REASON → PATCH → ATTACK → VERIFY → RESCAN</span><b>No patch is trusted until the exploit fails, regression tests pass, and the rescan is clean.</b></footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
