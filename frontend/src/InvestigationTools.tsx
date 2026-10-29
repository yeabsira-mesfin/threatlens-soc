import {useState} from 'react';

async function request(path:string,token:string,options:Record<string,any>={}){
 const res=await fetch('/api'+path,{...options,headers:{Authorization:'Bearer '+token,...(options.body?{'Content-Type':'application/json'}:{})}});
 if(!res.ok){const item=await res.json().catch(()=>({}));throw Error(item.detail||'Request failed');}
 return res.json();
}
export function IocLookup({token}:{token:string}){
 const [term,setTerm]=useState('198.51.100.77'),[matches,setMatches]=useState<any[]>([]);
 const [error,setError]=useState(''),[searched,setSearched]=useState(false),[busy,setBusy]=useState(false);
 async function lookup(e:any){e.preventDefault();setError('');setBusy(true);
  try{const r=await request('/iocs?q='+encodeURIComponent(term),token);setMatches(r.matches);setSearched(true);}
  catch(e:any){setError(e.message);}finally{setBusy(false);}
 }
 return <div><div className="page-head"><div><span className="kicker">INDICATOR CORRELATION</span><h1>IOC lookup</h1><p>Search source IPs, destinations, process strings and event descriptions in synthetic records.</p></div></div><section className="panel"><form onSubmit={lookup} className="inline"><input aria-label="Indicator to search" required minLength={3} maxLength={100} value={term} onChange={e=>setTerm(e.target.value)} placeholder="IP, hostname or process"/><button className="primary" disabled={busy}>Search telemetry</button></form><p>All results come from ingested local records. Matches are indicators for analyst review, not automatic maliciousness verdicts.</p>{error&&<p role="alert" className="error">{error}</p>}</section>
  {searched&&<section className="panel"><h2>Matching records ({matches.length})</h2><div className="table-scroll"><table><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Destination</th><th>Process or description</th></tr></thead><tbody>{matches.map(e=><tr key={e.id}><td>{new Date(e.timestamp).toLocaleString()}</td><td>{e.event_type}</td><td className="mono">{e.source_ip}</td><td className="mono">{e.destination}</td><td>{e.process||e.summary}</td></tr>)}</tbody></table></div>{!matches.length&&<p className="empty">No matching indicators in current local telemetry.</p>}</section>}
 </div>;
}
export function CaseEditor({caseData,token,onUpdated}:{caseData:any,token:string,onUpdated:()=>Promise<void>}){
 const [open,setOpen]=useState(false),[status,setStatus]=useState(caseData.status),[notes,setNotes]=useState(caseData.notes||''),[assignee,setAssignee]=useState(caseData.assignee||'');
 const [error,setError]=useState(''),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 async function save(e:any){e.preventDefault();setBusy(true);setError('');setNotice('');
  try{await request('/cases/'+caseData.id,token,{method:'PATCH',body:JSON.stringify({status,notes,assignee})});await onUpdated();setNotice('Case saved');setOpen(false);}
  catch(e:any){setError(e.message);}finally{setBusy(false);}
 }
 return <div className="case-editor"><button className="small-button" type="button" onClick={()=>setOpen(!open)}>{open?'Close editor':'Edit case'}</button>{notice&&<small className="success" role="status">{notice}</small>}{error&&<small className="error" role="alert">{error}</small>}{open&&<form className="case-edit-form" onSubmit={save}><label>Status<select value={status} onChange={e=>setStatus(e.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></label><label>Assigned analyst<input value={assignee} maxLength={100} onChange={e=>setAssignee(e.target.value)}/></label><label>Investigation notes<textarea rows={4} maxLength={2000} value={notes} onChange={e=>setNotes(e.target.value)}/></label><button className="primary" disabled={busy}>Save investigation</button></form>}</div>;
}
