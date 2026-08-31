import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { getApiBase } from './config';

const API = getApiBase();
const STAGES = ['SAFE CLONE', 'DISCOVER', 'REPRODUCE', 'REASON', 'PATCH', 'PREFLIGHT', 'ATTACK', 'REGRESSION', 'RESCAN'];

function findingLabel(finding, index) {
  const kind = String(finding?.extra?.metadata?.kind || '').toLowerCase();
  const text = `${finding?.check_id || ''} ${finding?.extra?.message || ''}`.toLowerCase();
  if (kind.includes('command') || text.includes('command') || text.includes('subprocess')) return 'Command Injection';
  if (kind.includes('sql') || text.includes('sql')) return 'SQL Injection';
  return finding?.check_id || `Finding ${index + 1}`;
}

function severityForFinding(finding) {
  return String(finding?.extra?.severity || 'UNSPECIFIED').toUpperCase();
}

function App() {
  const [file, setFile] = useState(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [selected, setSelected] = useState(null);
  const [apiError, setApiError] = useState('');

  async function runDemo() {
    if (!file) return;
    setRunning(true); setResult(null); setSelected(null); setApiError('');
    try {
      const form = new FormData(); form.append('file', file);
      const response = await fetch(`${API}/api/runs`, { method: 'POST', body: form });
      if (!response.ok) throw new Error(`VAJRA API returned HTTP ${response.status}`);
      const queued = await response.json();
      let finalResult = null;
      for (let i = 0; i < 180; i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const poll = await fetch(`${API}/api/runs/${queued.run_id}`);
        if (!poll.ok) throw new Error(`Unable to read run ${queued.run_id}`);
        const current = await poll.json();
        if (current.status !== 'QUEUED' && current.status !== 'RUNNING') { finalResult = current; break; }
      }
      if (!finalResult) throw new Error('VAJRA run exceeded the 180 second UI timeout. Check the run API for its current state.');
      setResult(finalResult);
    } catch (error) {
      setApiError(error.message);
      setResult({ status: 'FAILED', events: [{ stage: 'SYSTEM', status: 'fail', message: error.message }] });
    } finally { setRunning(false); }
  }

  const events = result?.events || [];
  const eventMap = useMemo(() => Object.fromEntries(events.map((event) => [event.stage, event])), [events]);
  const findings = result?.findings || [];
  const processed = result?.processed_findings || [];
  const attacks = result?.attack_results || [];
  const blocked = attacks.filter((x) => x.status === 'BLOCKED').length;
  const attempts = result?.attempts || [];
  const maxAttempts = Number(result?.max_attempts || 0);
  const remaining = Number.isFinite(Number(result?.remaining_findings)) ? Number(result.remaining_findings) : null;
  const regression = result?.regression_tests === true;
  const verified = result?.status === 'VERIFIED';
  const checks = [
    ['Exploit reproduced', events.some((e) => e.stage === 'REPRODUCE' && e.status === 'pass')],
    ['Patch generated', events.some((e) => e.stage === 'PATCH' && e.status === 'pass')],
    ['Patch preflight passed', events.some((e) => e.stage === 'PREFLIGHT' && e.status === 'pass')],
    ['Patch survived attack', events.some((e) => e.stage === 'ATTACK' && e.status === 'pass')],
    ['Regression tests passed', regression],
    ['Rescan clean', eventMap.RESCAN?.status === 'pass' && remaining === 0],
  ];

  return <div className="app">
    <header><div><div className="brand">VAJRA</div><div className="tag">Autonomous Adversarial Vulnerability Remediation</div></div><div className="header-right"><div className="version">v1.0</div><div className="badge">AI KAVACH • TCQ 26</div></div></header>
    <main>
      <section className="hero"><div><div className="eyebrow">PROOF-CARRYING REMEDIATION</div><h1>Don't just patch.<br/><span>Prove the fix.</span></h1><p>Upload a Python codebase. VAJRA combines Semgrep, Tree-sitter and deterministic semantic analysis to discover SQL and command injection, then uses a code-capable reasoner to generate a patch and independent verification to prove it.</p></div>
        <div className="upload"><label>CODEBASE</label><div className="drop">{file ? <><strong>{file.name}</strong><small>Ready for VAJRA-TWIN</small></> : <><strong>Upload a vulnerable .zip or .py</strong><small>Python/Flask codebases • isolated analysis</small></>}</div><input type="file" accept=".zip,.py" onChange={(e) => setFile(e.target.files?.[0] || null)}/><button onClick={runDemo} disabled={!file || running}>{running ? 'RUNNING VAJRA…' : 'START REMEDIATION'}</button></div>
      </section>
      {apiError && <div className="running errorbar">{apiError}</div>}
      {running && <div className="running"><div className="spinner"/>VAJRA is executing the remediation loop…</div>}
      {result && <section className="workspace">
        <div className="topline"><div><label>RUN</label><strong>{result.run_id || 'LOCAL RUN'}</strong></div><div className="topline-right"><div className="twin"><span>VAJRA-TWIN</span><b>{verified ? 'VERIFIED' : 'ISOLATED'}</b></div><div className={`status ${verified ? 'good' : 'bad'}`}>{result.status}</div></div></div>
        <div className="pipeline">{STAGES.map((stage, index) => { const event = eventMap[stage]; const passed = event?.status === 'pass'; const failed = event?.status === 'fail'; return <React.Fragment key={stage}><button className={`stage ${passed ? 'done' : ''} ${failed ? 'failed' : ''}`} onClick={() => event && setSelected(event)}><span>{passed ? '✓' : failed ? '!' : index + 1}</span>{stage}</button>{index < STAGES.length - 1 && <div className="line"/>}</React.Fragment>; })}</div>
        <div className="run-timeline"><div className="timeline-head"><div><label>RUN TIMELINE</label><h2>Evidence-backed execution history</h2></div><span>{events.length} recorded events</span></div><div className="timeline-list">{events.map((event, index) => <button className={`timeline-event ${event.status === 'pass' ? 'passed' : ''} ${event.status === 'fail' ? 'failed' : ''}`} key={`${event.stage}-${event.attempt || 0}-${index}`} onClick={() => setSelected(event)}><span className="timeline-node">{event.status === 'pass' ? '✓' : event.status === 'fail' ? '!' : '•'}</span><span className="timeline-copy"><b>{event.stage}</b><small>{event.message}</small></span><span className="timeline-meta">{event.attempt ? `ATTEMPT ${event.attempt}` : 'EVENT'}</span></button>)}</div></div>
        <div className="summary-grid"><div className="summary-card"><label>FINDINGS</label><strong>{findings.length}</strong><span>discovered</span></div><div className="summary-card"><label>REMEDIATED</label><strong>{processed.filter((x) => x.accepted).length}/{findings.length}</strong><span>findings fixed</span></div><div className="summary-card"><label>ATTACKS</label><strong>{blocked}/{attacks.length}</strong><span>blocked</span></div><div className="summary-card"><label>RESCAN</label><strong>{remaining ?? '—'}</strong><span>findings remaining</span></div><div className="summary-card"><label>ATTEMPTS</label><strong>{attempts.length}{maxAttempts ? `/${maxAttempts}` : ''}</strong><span>bounded attempts</span></div></div>
        <div className="grid">
          <div className="card finding"><label>FINDINGS</label><h2>{findings.length ? `${findings.length} vulnerabilities discovered` : 'Clean codebase'}</h2><div className="finding-list">{findings.map((finding, index) => { const item = processed[index]; return <button className="finding-item" key={`${finding.path}-${finding.start?.line}-${index}`} onClick={() => item && setSelected({stage: findingLabel(finding,index), ...item})}><div><b>{findingLabel(finding,index)}</b><small>{finding.path}:{finding.start?.line || '—'}</small><small className="finding-meta">Severity: {severityForFinding(finding)}</small></div><span className={`pill ${item?.accepted ? 'good' : 'bad'}`}>{item ? (item.accepted ? 'FIXED' : 'FAILED') : 'DISCOVERED'}</span></button>; })}</div><div className="metric"><span>Static analysis</span><b>{result.engine || '—'}</b></div></div>
          <div className="card reasoning"><label>AI REASONING</label><h2>{result.llm_mode === 'live' ? 'LIVE CODE LLM' : 'DEMO REASONER'}</h2><p><b>Root cause:</b> {result.reasoning?.root_cause || '—'}</p><p><b>Remediation:</b> {result.reasoning?.remediation || '—'}</p><div className="metric"><span>Model</span><b>{result.reasoning?.model || '—'}</b></div><div className="metric"><span>Attempts</span><b>{attempts.length}/{maxAttempts}</b></div></div>
          <div className="card attack"><label>ADVERSARIAL VALIDATION</label><h2>{blocked}/{attacks.length} attacks blocked</h2>{attacks.map((item,index)=><div className="attackrow" key={`${item.payload}-${index}`}><code>{item.payload}</code><b>{item.status}</b></div>)}</div>
          <div className="card verify"><label>VERIFICATION</label><h2>{verified ? 'Evidence accepted' : 'Verification incomplete'}</h2>{checks.map(([text,passed])=><div className={`check ${passed ? '' : 'unchecked'}`} key={text}><span>{passed ? '✓' : '!'}</span>{text}</div>)}</div>
          <div className="card rescan"><label>RESCAN RESULT</label><h2>{remaining === 0 ? 'Clean rescan' : `${remaining ?? '—'} findings remain`}</h2><div className="rescan-stats"><div><span>Pre-patch</span><b>{findings.length}</b></div><div><span>Resolved</span><b>{processed.filter((x)=>x.accepted).length}</b></div><div><span>Remaining</span><b>{remaining ?? '—'}</b></div></div><p>Post-patch engine: <b>{result.post_rescan_engine || '—'}</b></p></div>
          <div className="card tooling"><label>SECURITY TOOLCHAIN</label><h2>Static + dependency + fuzzing</h2><div className="tool-list"><div><b>Semgrep</b><span>{result.engine?.includes('Semgrep') ? 'ACTIVE' : 'FALLBACK'}</span></div><div><b>Tree-sitter</b><span>{result.engine?.includes('Tree-sitter') ? 'ACTIVE' : 'UNAVAILABLE'}</span></div><div><b>Syft / OSV-Scanner</b><span>{result.dependency_analysis?.syft?.ok || result.dependency_analysis?.osv_scanner?.ok ? 'COMPLETED' : 'OPTIONAL'}</span></div><div><b>Atheris</b><span>{result.fuzzing?.ok ? 'COMPLETED' : 'OPTIONAL'}</span></div></div></div>
          <div className="card diff"><label>PATCH DIFF</label><pre>{result.diff || 'No patch diff recorded.'}</pre></div>
        </div>
        <div className="artifacts"><div><label>VERIFIED OUTPUT</label><h2>{verified ? 'Remediation package ready' : 'Run artifacts'}</h2><p>{verified ? 'The fixed VAJRA-TWIN passed adversarial validation, regression testing and rescan.' : 'Inspect evidence to diagnose the failed verification gates.'}</p></div><div className="artifact-actions">{result.artifacts?.evidence_report && <a href={`${API}${result.artifacts.evidence_report}`} target="_blank" rel="noreferrer">VIEW EVIDENCE REPORT</a>}{result.artifacts?.evidence_json && <a href={`${API}${result.artifacts.evidence_json}`} target="_blank" rel="noreferrer">VIEW EVIDENCE JSON</a>}{result.artifacts?.patch_diff && <a href={`${API}${result.artifacts.patch_diff}`} target="_blank" rel="noreferrer">DOWNLOAD PATCH DIFF</a>}{result.artifacts?.verified_codebase && <a href={`${API}${result.artifacts.verified_codebase}`} target="_blank" rel="noreferrer">DOWNLOAD VERIFIED CODEBASE</a>}</div></div>
        {selected && <div className="detail"><button onClick={()=>setSelected(null)}>×</button><label>{selected.stage}</label><h2>{selected.message || selected.kind || 'Finding details'}</h2><pre>{JSON.stringify(selected,null,2)}</pre></div>}
      </section>}
      <footer><span>SAFE CLONE → DISCOVER → REPRODUCE → REASON → PATCH → PREFLIGHT → ATTACK → REGRESSION → RESCAN</span><b>No patch is trusted until the exploit fails, regression tests pass, and the rescan is clean.</b></footer>
    </main>
  </div>;
}

createRoot(document.getElementById('root')).render(<App/>);
