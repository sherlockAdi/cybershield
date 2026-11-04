'use client';
import {useEffect,useRef,useState} from 'react';
import {collect,decode,decryptFile,download,importKey,readMetadata,type Envelope} from '../../lib/document-crypto';
type PublicDocument={id:string;metadata:Envelope;chunk_count:number;ciphertext_size:number;expires_at:string;server_time:string};
export default function SharePage(){
 const secret=useRef<{token:string;key:string}|null>(null),deadline=useRef(0),alive=useRef(true);
 const [error,setError]=useState(''),[ready,setReady]=useState(false),[busy,setBusy]=useState(false),[remaining,setRemaining]=useState<number|null>(null),[notice,setNotice]=useState('');
 useEffect(()=>{alive.current=true;const fragment=new URLSearchParams(window.location.hash.slice(1));if(!secret.current)secret.current={token:fragment.get('token')||'',key:fragment.get('key')||''};window.history.replaceState(null,'',window.location.pathname);setReady(true);return()=>{alive.current=false;};},[]);
 useEffect(()=>{const timer=setInterval(()=>{if(deadline.current){const left=Math.max(0,Math.ceil((deadline.current-performance.now())/1000));setRemaining(left);if(!left)secret.current=null;}},250);return()=>clearInterval(timer);},[]);
 async function request<T>(body:object):Promise<T>{const response=await fetch('/api/documents/public',{method:'POST',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await response.json();if(!response.ok)throw new Error(data.message||'Link unavailable');return data;}
 async function access(){setBusy(true);setError('');setNotice('');try{
  const value=secret.current;if(!value?.token||!value.key)throw new Error('This link is incomplete or expired. Open the original full link again.');
  if(!/^[A-Za-z0-9_-]{43}$/.test(value.token)||decode(value.key).length!==32)throw new Error('Invalid public link');
  const started=performance.now(),doc=await request<PublicDocument>({token:value.token});
  deadline.current=started+new Date(doc.expires_at).getTime()-new Date(doc.server_time).getTime();
  const key=await importKey(decode(value.key)),meta=await readMetadata(key,doc.metadata,doc.id);
  const bytes=await collect(doc.chunk_count,doc.ciphertext_size,index=>{if(performance.now()>=deadline.current)throw new Error('Link expired. Ask the owner for a new link.');return request({token:value.token,index});});
  const clear=await decryptFile(key,bytes,meta,doc.id);
  // Revalidate immediately before releasing plaintext to the recipient.
  await request({token:value.token});
  if(performance.now()>=deadline.current)throw new Error('Link expired. Ask the owner for a new link.');
  if(alive.current){download(clear,meta.name);setNotice('Document decrypted in your browser and downloaded.');}
 }catch(e){if(alive.current)setError(e instanceof Error?e.message:'Unable to open encrypted document');}finally{if(alive.current)setBusy(false);}}
 return <main className="content" style={{maxWidth:760,margin:'40px auto'}}><section className="panel settings-panel"><span className="eyebrow">ENCRYPTED DOCUMENT SHARING</span><h1>Secure document link</h1><p>The document is decrypted in your browser. No account or vault password is needed; the complete link grants access to this one document.</p><p className="muted">The owner sets a 1-minute or 30-minute expiry from link creation and can revoke it sooner. Downloaded copies remain accessible after expiry.</p>{error&&<div className="message error" role="alert">{error}</div>}{notice&&<p role="status">{notice}</p>}{remaining!==null&&<p role="status">{remaining>0?`${remaining} seconds remaining`:'Link expired'}</p>}<button className="button primary" disabled={!ready||busy||remaining===0} onClick={()=>void access()}>{busy?'Checking link and decrypting…':'Decrypt & download'}</button><p className="muted">Keep the full link private. Refreshing this page requires reopening the original link.</p></section></main>;
}
