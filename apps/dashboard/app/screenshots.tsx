'use client';
import { useEffect,useState } from 'react';
import { api } from '../lib/api';
type Report={config:{enabled:boolean;intervalSeconds:number;revision:number};status:string;capturedAt:string|null;jpeg:string|null};
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
 <p>Only the latest image is retained, encrypted at rest. Images older than 60 seconds are hidden; expired data is cleared after about 5–6 minutes. One-second capture uses more device resources and bandwidth. This is periodic screenshots, not guaranteed real-time video.</p>
 {report?.jpeg?<><p>Captured: {new Date(report.capturedAt!).toLocaleString()}</p><img src={`data:image/jpeg;base64,${report.jpeg}`} alt="Latest primary-monitor screenshot shared with local user consent" style={{width:'100%',maxWidth:960,borderRadius:8}}/></>:<div className="empty">No recent screenshot. Enable capture here, then click Allow in the laptop’s visible screen-sharing helper.</div>}
 <details><summary>One-time local setup</summary><p>After the agent updates to 1.2, run the following from the extracted Windows package in Administrator PowerShell. Use <code>-User 'DOMAIN\username'</code> if the intended logged-in account differs from the administrator account.</p><pre>{'.\\Enable-ScreenCapture.ps1'}</pre><p>Then, as that logged-in user, launch the helper and click Allow:</p><pre style={{whiteSpace:'pre-wrap'}}>{'powershell.exe -NoProfile -File "C:\\ProgramData\\CyberShieldScreenCapture\\Start-ScreenSharing.ps1"'}</pre><p>The helper stays visible in the window/taskbar and notification area. Closing it stops capture. No unattended hidden capture is installed.</p></details>
 </section>;
}
