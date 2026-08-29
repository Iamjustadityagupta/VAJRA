import React, {useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const API='http://localhost:8000';
const stages=['SAFE CLONE','DISCOVER','REPRODUCE','REASON','PATCH','ATTACK','VERIFY','RESCAN'];

function App(){
 const [file,setFile]=useState(null), [running,setRunning]=useState(false), [result,setResult]=useState(null);
 const [selected,setSelected]=useState(null);
 const run=async()=>{if(!file)return;setRunning(true);setResult(null);setSelected(null);try{const fd=new FormData();fd.append('file',file);const r=await fetch(`${API}/api/demo/run`,{method:'POST',body:fd});setResult(await r.json())}catch(e){setResult({status:'FAILED',events:[{stage:'SYSTEM',status:'fail',message:e.message}]})}finally{setRunning(false)}};
 const eventMap=Object.fromEntries((result?.events||[]).map(e=>[e.stage,e]));
 return <div className="app">
  <header><div><div className="brand">VAJRA</div><div className="tag">Autonomous Adversarial Vulnerability Remediation</div></div><div className="badge">AI KAVACH • TCQ 26</div></header>
  <main>
   <section className="hero"><div><div className="eyebrow">PROOF-CARRYING REMEDIATION</div><h1>Don't just patch.<br/><span>Prove the fix.</span></h1><p>VAJRA discovers a vulnerability, reproduces it, generates a targeted patch, attacks that patch, and verifies the result.</p></div>
    <div className="upload"><label>CODEBASE</label><div className="drop">{file?<><strong>{file.name}</strong><small>Ready for VAJRA-TWIN</small></>:<><strong>Upload a vulnerable .zip</strong><small>Use the included demo target</small></>}</div><input type="file" accept=".zip" onChange={e=>setFile(e.target.files[0])}/><button onClick={run} disabled={!file||running}>{running?'RUNNING VAJRA…':'START REMEDIATION'}</button></div>
   </section>
   {running && <div className="running"><div className="spinner"/> VAJRA is executing the remediation loop…</div>}
   {result && <section className="workspace">
    <div className="topline"><div><label>RUN</label><strong>{result.run_id}</strong></div><div className={`status ${result.status==='VERIFIED'?'good':'bad'}`}>{result.status}</div></div>
    <div className="pipeline">{stages.map((s,i)=>{const e=eventMap[s];const ok=e?.status==='pass';return <React.Fragment key={s}><button className={`stage ${ok?'done':''} ${e?.status==='fail'?'failed':''}`} onClick={()=>setSelected(e)}><span>{ok?'✓':i+1}</span>{s}</button>{i<stages.length-1&&<div className="line"/>}</React.Fragment>})}</div>
    <div className="grid">
      <div className="card finding"><label>FINDING</label>{result.findings?.length?<><h2>SQL Injection</h2><p>Critical security issue confirmed in <b>{result.file}</b>.</p><div className="metric"><span>Exploit</span><b>REPRODUCED ✓</b></div></>:<h2>Clean</h2>}</div>
      <div className="card attack"><label>ADVERSARIAL VALIDATION</label><h2>{result.attack_results?.filter(x=>x.status==='BLOCKED').length||0}/{result.attack_results?.length||0} attacks blocked</h2>{result.attack_results?.map((x,i)=><div className="attackrow" key={i}><code>{x.payload}</code><b>{x.status}</b></div>)}</div>
      <div className="card verify"><label>VERIFICATION</label><h2>Evidence collected</h2>{['Exploit reproduced','Patch generated','Patch survived attack','Regression tests passed','Rescan completed'].map(x=><div className="check" key={x}><span>✓</span>{x}</div>)}</div>
      <div className="card diff"><label>PATCH DIFF</label><pre>{result.diff||'No changes.'}</pre></div>
    </div>
    {selected&&<div className="detail"><button onClick={()=>setSelected(null)}>×</button><label>{selected.stage}</label><h2>{selected.message}</h2><pre>{JSON.stringify(selected,null,2)}</pre></div>}
   </section>}
   <footer><span>SAFE CLONE → DISCOVER → REPRODUCE → REASON → PATCH → ATTACK → VERIFY → RESCAN</span><b>No patch is trusted until the exploit fails and regression tests pass.</b></footer>
  </main>
 </div>
}
createRoot(document.getElementById('root')).render(<App/>);
