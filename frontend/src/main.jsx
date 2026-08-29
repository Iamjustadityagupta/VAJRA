import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const API = 'http://localhost:8000';
const STAGES = ['SAFE CLONE', 'DISCOVER', 'REPRODUCE', 'REASON', 'PATCH', 'ATTACK', 'VERIFY', 'RESCAN'];

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

  const eventMap = Object.fromEntries((result?.events || []).map((event) => [event.stage, event]));
  const attackResults = result?.attack_results || [];
  const blocked = attackResults.filter((item) => item.status === 'BLOCKED').length;
  const checks = [
    ['Exploit reproduced', eventMap.REPRODUCE?.status === 'pass'],
    ['Patch generated', eventMap.PATCH?.status === 'pass'],
    ['Patch survived attack', eventMap.ATTACK?.status === 'pass'],
    ['Regression tests passed', eventMap.VERIFY?.status === 'pass'],
    ['Rescan completed', eventMap.RESCAN?.status === 'pass'],
  ];

  return (
    <div className="app">
      <header>
        <div><div className="brand">VAJRA</div><div className="tag">Autonomous Adversarial Vulnerability Remediation</div></div>
        <div className="badge">AI KAVACH • TCQ 26</div>
      </header>
      <main>
        <section className="hero">
          <div><div className="eyebrow">PROOF-CARRYING REMEDIATION</div><h1>Don't just patch.<br /><span>Prove the fix.</span></h1><p>VAJRA discovers a vulnerability, reproduces it, reasons over the evidence, generates a targeted patch, attacks that patch, and verifies the result.</p></div>
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
            <div className="topline"><div><label>RUN</label><strong>{result.run_id || 'LOCAL RUN'}</strong></div><div className={`status ${result.status === 'VERIFIED' ? 'good' : 'bad'}`}>{result.status}</div></div>
            <div className="pipeline">
              {STAGES.map((stage, index) => {
                const event = eventMap[stage];
                const passed = event?.status === 'pass';
                const failed = event?.status === 'fail';
                return <React.Fragment key={stage}><button className={`stage ${passed ? 'done' : ''} ${failed ? 'failed' : ''}`} onClick={() => event && setSelected(event)}><span>{passed ? '✓' : index + 1}</span>{stage}</button>{index < STAGES.length - 1 && <div className="line" />}</React.Fragment>;
              })}
            </div>

            <div className="grid">
              <div className="card finding"><label>FINDING</label>{result.findings?.length ? <><h2>SQL Injection</h2><p>Security issue confirmed in <b>{result.file}</b>.</p><div className="metric"><span>Exploit</span><b>REPRODUCED ✓</b></div><div className="metric"><span>Engine</span><b>{result.engine}</b></div></> : <h2>Clean</h2>}</div>
              <div className="card reasoning"><label>AI REASONING</label><h2>{result.llm_mode === 'live' ? 'LIVE LLM' : 'DEMO REASONER'}</h2><p><b>Root cause:</b> {result.reasoning?.root_cause || '—'}</p><p><b>Remediation:</b> {result.reasoning?.remediation || '—'}</p><div className="metric"><span>Model</span><b>{result.reasoning?.model || '—'}</b></div><div className="metric"><span>Attempts</span><b>{result.attempts?.length || 0}/{result.max_attempts || 0}</b></div></div>
              <div className="card attack"><label>ADVERSARIAL VALIDATION</label><h2>{blocked}/{attackResults.length} attacks blocked</h2>{attackResults.map((item, index) => <div className="attackrow" key={`${item.payload}-${index}`}><code>{item.payload}</code><b>{item.status}</b></div>)}</div>
              <div className="card verify"><label>VERIFICATION</label><h2>{result.status === 'VERIFIED' ? 'Evidence accepted' : 'Verification incomplete'}</h2>{checks.map(([text, passed]) => <div className={`check ${passed ? '' : 'unchecked'}`} key={text}><span>{passed ? '✓' : '!'}</span>{text}</div>)}</div>
              <div className="card diff"><label>PATCH DIFF</label><pre>{result.diff || 'No changes.'}</pre></div>
            </div>

            {result.status === 'VERIFIED' && result.artifacts && (
              <div className="artifacts">
                <div><label>FINAL OUTPUT</label><h2>Verified remediation package</h2><p>VAJRA has completed the proof loop. The fixed codebase and evidence report are ready.</p></div>
                <div className="artifact-actions"><a href={`${API}${result.artifacts.verified_codebase}`} target="_blank" rel="noreferrer">DOWNLOAD VERIFIED CODEBASE</a><a href={`${API}${result.artifacts.evidence_report}`} target="_blank" rel="noreferrer">DOWNLOAD EVIDENCE REPORT</a></div>
              </div>
            )}

            {selected && <div className="detail"><button onClick={() => setSelected(null)}>×</button><label>{selected.stage}</label><h2>{selected.message}</h2><pre>{JSON.stringify(selected, null, 2)}</pre></div>}
          </section>
        )}
        <footer><span>SAFE CLONE → DISCOVER → REPRODUCE → REASON → PATCH → ATTACK → VERIFY → RESCAN</span><b>No patch is trusted until the exploit fails and regression tests pass.</b></footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
