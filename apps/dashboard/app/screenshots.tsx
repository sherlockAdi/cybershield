'use client';
import { useEffect,useState } from 'react';
import { api } from '../lib/api';
type Report={config:{enabled:boolean;intervalSeconds:number;revision:number};status:string;capturedAt:string|null;jpeg:string|null};
type History={items:{id:string;capturedAt:string;jpeg:string}[];next:string|null};
const indiaDate=(time:number)=>new Date(time+19800000).toISOString().slice(0,10);
export default function Screenshots({organizationId,deviceId,canManage}:{organizationId:string;deviceId:string;canManage:boolean}){
 const [report,setReport]=useState<Report|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false),[interval,setIntervalValue]=useState(5);
 const endpoint=`/organizations/${organizationId}/devices/${deviceId}/screenshots`;
 useEffect(()=>{
  if(!canManage)return;
  let active=true;let timer:ReturnType<typeof setTimeout>;let initial=true;
  let delay=5000;
  async function poll(){try{if(document.hidden)return;const next=await api<Report>(endpoint);if(active){setReport(old=>!old||next.config.revision>=old.config.revision?next:old);setError('');delay=next.config.enabled?next.config.intervalSeconds*1000:5000;if(initial){setIntervalValue(next.config.intervalSeconds);initial=false;}}}catch(e){if(active){setReport(null);setError(e instanceof Error?e.message:'Screenshot unavailable');}}finally{if(active)timer=setTimeout(poll,delay);}}
  void poll();return()=>{active=false;clearTimeout(timer);};
 },[endpoint,canManage]);
 async function save(enabled:boolean){if(!report)return;setBusy(true);setError('');try{await api(endpoint,'PATCH',{enabled,intervalSeconds:interval,revision:report.config.revision});setReport(await api<Report>(endpoint));}catch(e){setError(e instanceof Error?e.message:'Unable to save');}finally{setBusy(false);}}
 if(!canManage)return <p className="info-note">Screenshots are restricted to organization Owners and Administrators.</p>;
 return <section className="panel device-summary"><h2>Device screenshots</h2><p>Primary monitor only. A visible local helper and the logged-in user’s consent are required. Locking the screen pauses capture; the user can stop sharing at any time.</p>
 {error&&<p role="alert" className="message error">{error}</p>}
 <div className="button-row"><label>Capture interval <select value={interval} onChange={e=>setIntervalValue(Number(e.target.value))}>{[1,5,10,15].map(n=><option key={n} value={n}>{n} second{n===1?'':'s'}</option>)}</select></label><button className="button primary" disabled={busy||!report} onClick={()=>void save(true)}>{report?.config.enabled?'Save interval':'Enable capture request'}</button><button className="button secondary" disabled={busy||!report?.config.enabled} onClick={()=>void save(false)}>Disable and clear latest image</button></div>
 <p>Status: {report?.status.replaceAll('_',' ')||'Loading…'} · Configured interval: {report?.config.intervalSeconds??'—'}s</p>
 <p>The live preview shows screenshots received within the last minute. Screenshot history is encrypted and retained for 72 hours.</p>
 {report?.jpeg?<><p>Captured: {new Date(report.capturedAt!).toLocaleString()}</p><img src={`data:image/jpeg;base64,${report.jpeg}`} alt="Latest primary-monitor screenshot shared with local user consent" style={{width:'100%',maxWidth:960,borderRadius:8}}/></>:<div className="empty">No recent screenshot. Enable capture here, then click Allow in the laptop’s visible screen-sharing helper.</div>}
 <ScreenshotHistory key={endpoint} endpoint={endpoint}/>
 </section>;
}

function ScreenshotHistory({endpoint}:{endpoint:string}){
 const [date,setDate]=useState(()=>indiaDate(Date.now()));
 const [before,setBefore]=useState<string|null>(null);
 const [history,setHistory]=useState<History|null>(null);
 const [error,setError]=useState('');
 const [refresh,setRefresh]=useState(0);
 useEffect(()=>{
  let active=true;
  const query=new URLSearchParams({date});
  if(before)query.set('before',before);
  void api<History>(endpoint+'/history?'+query).then(data=>{
   if(active)setHistory(data);
  }).catch(e=>{if(active)setError(e instanceof Error?e.message:'History unavailable');});
  return()=>{active=false;};
 },[endpoint,date,before,refresh]);
 function reset(){setHistory(null);setError('');}
 return <section>
  <h3>Screenshot history</h3>
  <div className="button-row">
   <label>Capture date (IST) <input type="date" value={date} min={indiaDate(Date.now()-72*3600000)} max={indiaDate(Date.now())} onChange={e=>{if(e.target.value){reset();setBefore(null);setDate(e.target.value);}}}/></label>
   <button className="button secondary" onClick={()=>{reset();setBefore(null);setRefresh(n=>n+1);}}>Refresh history</button>
  </div>
  {error?<p role="alert">{error}</p>:!history?<p>Loading screenshots…</p>:!history.items.length?<p>No retained screenshots for this date.</p>:
   <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(min(100%,240px),1fr))',gap:16}}>
    {history.items.map(frame=><details key={frame.id}>
     <summary>{new Date(frame.capturedAt).toLocaleTimeString('en-IN',{timeZone:'Asia/Kolkata'})} IST · View screenshot</summary>
     <img src={`data:image/jpeg;base64,${frame.jpeg}`} alt="Captured device screen" loading="lazy" style={{width:'100%',borderRadius:8}}/>
    </details>)}
   </div>}
  <div className="button-row">
   {before&&<button className="button secondary" onClick={()=>{reset();setBefore(null);}}>Back to newest</button>}
   {history?.next&&<button className="button secondary" onClick={()=>{const next=history.next;reset();setBefore(next);}}>Older screenshots</button>}
  </div>
 </section>;
}
