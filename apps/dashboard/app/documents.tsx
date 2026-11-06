'use client';
import {useEffect,useRef,useState} from 'react';
import {LockKeyhole, Download, Link2, Trash2} from 'lucide-react';
import {api} from '../lib/api';
import {CHUNK,MAX_FILE,collect,decode,decryptFile,derive,download,encode,encryptFile,importKey,open,randomKey,readMetadata,seal,type Envelope,type FileMetadata} from '../lib/document-crypto';
type Vault={salt:string;wrapped_key:Envelope};
type Stored={id:string;wrapped_key:Envelope;metadata:Envelope;ciphertext_size:number;chunk_count:number;ready:boolean;created_at:string};
type Document=Stored & {name:string;meta?:FileMetadata;key?:CryptoKey;rawKey?:Uint8Array<ArrayBuffer>};
type Share={id:string;expires_at:string;revoked_at:string|null};
export default function Documents({organizationId,userId,records=false}:{organizationId:string;userId:string;records?:boolean}) {
 const base=`/organizations/${organizationId}/documents`, context=`vault:${organizationId}:${userId}:v1`;
 const [vault,setVault]=useState<Vault|null>(),[master,setMaster]=useState<CryptoKey|null>(null),[rows,setRows]=useState<Document[]>([]);
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState(''),[progress,setProgress]=useState(''),[page,setPage]=useState(0);
 const [minutes,setMinutes]=useState<1|30>(1),[link,setLink]=useState<{url:string;expires:string}|null>(null),[selected,setSelected]=useState<Document|null>(null),[links,setLinks]=useState<Share[]>([]);
 const [inspection,setInspection]=useState<{row:Document;bytes:Uint8Array<ArrayBuffer>;chunks:string[];plain?:string}|null>(null);
 const [title,setTitle]=useState(''),[content,setContent]=useState(''),[format,setFormat]=useState<'text'|'json'>('text');
 const visibleRows=rows.filter(row=>!row.meta || (row.meta.kind==='record')===records);
 const alive=useRef(true),generation=useRef(0),fileInput=useRef<HTMLInputElement>(null);
 useEffect(()=>{alive.current=true; void api<{vault:Vault|null}>(`${base}/vault`).then(data=>setVault(data.vault)).catch(e=>setError(e.message)); return()=>{alive.current=false;generation.current++;};},[base]);
 function lock(){generation.current++;setInspection(null);setTitle('');setContent('');setMaster(null);setRows([]);setLink(null);setSelected(null);setLinks([]);setNotice('Vault locked');}
 useEffect(()=>{if(!master)return;const timer=setTimeout(lock,10*60*1000);return()=>clearTimeout(timer);},[master]);
 async function work(fn:()=>Promise<void>){setBusy(true);setError('');setNotice('');try{await fn();}catch(e){if(alive.current)setError(e instanceof Error?e.message:'Operation failed');}finally{if(alive.current){setBusy(false);setProgress('');}}}
 async function load(key:CryptoKey,version=generation.current){
  const stored=await api<Stored[]>(base); const result:Document[]=[];
  for(const row of stored){try{const rawKey=await open(key,row.wrapped_key,`document:${row.id}:key:v1`);const fileKey=await importKey(rawKey);const meta=await readMetadata(fileKey,row.metadata,row.id);result.push({...row,name:meta.name,meta,key:fileKey,rawKey});}catch{result.push({...row,name:'Unable to decrypt document'});}}
  if(alive.current&&generation.current===version){setRows(result);setPage(0);}
 }
 async function upload(file:File,recordFormat?:'text'|'json'){
  if(!master)return;const key=master,version=generation.current;
  if(file.size<1||file.size>MAX_FILE)throw new Error('Choose a non-empty file up to 5 MiB.');
  if(file.name.length>255)throw new Error('Filename must be 255 characters or fewer.');
  setProgress('Encrypting in your browser…');
  const id=crypto.randomUUID(),rawKey=randomKey(),fileKey=await importKey(rawKey);
  const encrypted=await encryptFile(fileKey,await file.arrayBuffer(),id);
  const metadata=await seal(fileKey,new TextEncoder().encode(JSON.stringify({name:file.name,size:file.size,iv:encrypted.iv,...(recordFormat?{kind:'record',format:recordFormat}:{})})),`document:${id}:metadata:v1`);
  const wrappedKey=await seal(key,rawKey,`document:${id}:key:v1`);rawKey.fill(0);
  const count=Math.ceil(encrypted.ciphertext.length/CHUNK);
  if(!alive.current||generation.current!==version)throw new Error('Vault locked. Upload cancelled.');
  await api(base,'POST',{id,wrappedKey,metadata,ciphertextSize:encrypted.ciphertext.length,chunkCount:count});
  try{
   for(let index=0;index<count;index++){
    if(!alive.current||generation.current!==version)throw new Error('Vault locked. Upload cancelled.');
    setProgress(`Uploading encrypted document: ${Math.round(index/count*100)}%`);
    await api(`${base}/${id}/chunks`,'POST',{index,ciphertext:encode(encrypted.ciphertext.slice(index*CHUNK,(index+1)*CHUNK))});
   }
   await api(`${base}/${id}/complete`,'POST',{});
   if(alive.current&&generation.current===version){await load(key,version);setNotice(recordFormat?'Encrypted record saved. Click its row to inspect storage.':'Encrypted document stored. No public link is active.');if(recordFormat){setTitle('');setContent('');}}
  }catch(e){if(alive.current&&generation.current===version)await load(key,version);throw e;}
 }
 async function getFile(row:Document){
  if(!row.key||!row.meta)throw new Error('Unable to decrypt this document');const version=generation.current;
  const bytes=await collect(row.chunk_count,row.ciphertext_size,index=>api(`${base}/${row.id}/chunks/${index}`));
  const clear=await decryptFile(row.key,bytes,row.meta,row.id);
  if(alive.current&&generation.current===version)download(clear,row.meta.name);
 }
 async function inspect(row:Document){
  const version=generation.current;setInspection(null);const chunks:string[]=[];
  const bytes=await collect(row.chunk_count,row.ciphertext_size,async index=>{const result=await api<{ciphertext:string}>(`${base}/${row.id}/chunks/${index}`);chunks.push(result.ciphertext);return result;});
  if(alive.current&&generation.current===version)setInspection({row,bytes,chunks});
 }
 async function reveal(){
  if(!inspection?.row.key||!inspection.row.meta)return;
  const current=inspection,version=generation.current;
  const plain=new TextDecoder('utf-8',{fatal:true}).decode(await decryptFile(current.row.key!,current.bytes,current.row.meta!,current.row.id));
  if(alive.current&&generation.current===version)setInspection(previous=>previous===current?{...current,plain}:previous);
 }
 async function showLinks(row:Document){const version=generation.current;const data=await api<Share[]>(`${base}/${row.id}/links`);if(alive.current&&generation.current===version){setSelected(row);setLinks(data);}}
 return <>
  <section className="panel settings-panel"><div className="section-toolbar"><div><h2><LockKeyhole size={21}/> {records?'Encrypted data storage':'Encrypted document vault'}</h2><p className="muted">Private to your account in this organization. {records?'Record titles and data are encrypted before saving. Uses the same password as Document Storing.':'Files and filenames are encrypted before upload.'}</p></div>{master&&<button className="button secondary" onClick={lock}>Lock vault</button>}</div>
   {error&&<div className="message error" role="alert">{error}</div>}{notice&&<div className="message" role="status">{notice}</div>}
   {vault===undefined?<p>Loading vault…</p>:!master?<form onSubmit={event=>{event.preventDefault();const form=event.currentTarget,data=new FormData(form),password=String(data.get('password'));const confirm=String(data.get('confirm'));form.reset();void work(async()=>{
    const version=generation.current;
    if(!vault&&password!==confirm)throw new Error('Passwords do not match');
    if(!vault&&password.length<16)throw new Error('Use a unique passphrase of at least 16 characters.');
    const salt=vault?.salt||encode(crypto.getRandomValues(new Uint8Array(16))),passwordKey=await derive(password,salt);
    let key:CryptoKey;
    if(vault){try{key=await importKey(await open(passwordKey,vault.wrapped_key,context));}catch{throw new Error('Wrong vault password or damaged vault. No server-side password reset is possible.');}}
    else{const raw=randomKey();key=await importKey(raw);const wrappedKey=await seal(passwordKey,raw,context);raw.fill(0);await api(`${base}/vault`,'POST',{salt,wrappedKey});if(alive.current)setVault({salt,wrapped_key:wrappedKey});}
    if(alive.current&&generation.current===version){setMaster(key);await load(key,version);}
   });}}>
    <label className="field"><span>{vault?'Vault password':'Create a separate vault passphrase'}</span><input name="password" type="password" required minLength={vault?1:16} maxLength={256} autoComplete={vault?'current-password':'new-password'} /></label>
    {!vault&&<><label className="field"><span>Confirm vault passphrase</span><input name="confirm" type="password" required minLength={16} maxLength={256} autoComplete="new-password"/></label><label className="field"><span><input type="checkbox" required/> I understand that losing this password means losing access to my documents.</span></label></>}
    <button className="button primary" disabled={busy}>{busy?'Unlocking…':vault?'Unlock vault':'Create encrypted vault'}</button>
   </form>:<><p className="muted">Up to 5 MiB per file · 100 documents / 100 MiB per vault · Locks after 10 minutes or when you leave this page.</p>{records?<form onSubmit={event=>{event.preventDefault();void work(async()=>{
 if(!title.trim()||!content.trim())throw new Error('Enter a title and data.');
 if(new TextEncoder().encode(content).length>65536)throw new Error('Record data must be 64 KiB or less.');
 if(format==='json'){try{JSON.parse(content);}catch{throw new Error('Enter valid JSON or choose Plain text.');}}
 await upload(new File([content],title.trim(),{type:'text/plain'}),format);
})}}><label className="field"><span>Record title</span><input value={title} onChange={event=>setTitle(event.target.value)} required maxLength={200} disabled={busy}/></label><label className="field"><span>Data format</span><select value={format} onChange={event=>setFormat(event.target.value as 'text'|'json')} disabled={busy}><option value="text">Plain text</option><option value="json">JSON</option></select></label><label className="field"><span>Data to encrypt (up to 64 KiB)</span><textarea rows={8} value={content} onChange={event=>setContent(event.target.value)} required maxLength={65536} disabled={busy} style={{width:'100%'}}/></label><button className="button primary" disabled={busy}>Encrypt & save record</button></form>:<input ref={fileInput} type="file" aria-label="Choose document to encrypt" disabled={busy} onChange={event=>{const file=event.target.files?.[0];event.target.value='';if(file)void work(()=>upload(file));}}/>}<p role="status">{progress}</p><button className="button secondary" disabled={busy} onClick={()=>void work(()=>load(master))}>Refresh documents</button></>}
  </section>
  {master&&<section className="panel section-gap"><div className="panel-heading"><h2>{records?'My encrypted records':'My encrypted documents'} ({visibleRows.length})</h2><label>Link expiry <select value={minutes} onChange={event=>setMinutes(Number(event.target.value) as 1|30)}><option value={1}>1 minute</option><option value={30}>30 minutes</option></select></label></div>
   <div className="table-wrap"><table><thead><tr><th>Document</th><th>Size</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>{visibleRows.slice(page*10,page*10+10).map(row=><tr key={row.id} onClick={records&&!busy&&row.ready?()=>void work(()=>inspect(row)):undefined} style={records?{cursor:'pointer'}:undefined}><td>{records?<button className="text-button" disabled={busy||!row.ready} onClick={event=>{event.stopPropagation();void work(()=>inspect(row));}}>{row.name}</button>:row.name}{!row.ready&&<span className="badge">Incomplete upload — delete and retry</span>}</td><td>{row.meta?`${(row.meta.size/1024).toFixed(1)} KiB`:'Encrypted'}</td><td>{new Date(row.created_at).toLocaleString()}</td><td onClick={event=>event.stopPropagation()}><div className="button-row"><button className="button secondary compact" disabled={busy||!row.ready||!row.key} onClick={()=>void work(()=>getFile(row))}><Download size={15}/>Download</button><button className="button secondary compact" disabled={busy||!row.ready||!row.rawKey} onClick={()=>void work(async()=>{
    const version=generation.current;const shared=await api<{token:string;expiresAt:string}>(`${base}/${row.id}/links`,'POST',{minutes});
    if(alive.current&&generation.current===version){const fragment=new URLSearchParams({token:shared.token,key:encode(row.rawKey!)});setLink({url:`${window.location.origin}/share#${fragment}`,expires:shared.expiresAt});await showLinks(row);}
   })}><Link2 size={15}/>Generate link</button><button className="text-button" disabled={busy} onClick={()=>void work(()=>showLinks(row))}>Manage links</button><button className="text-button danger" disabled={busy} onClick={()=>{if(window.confirm('Delete this encrypted document and revoke all its links?'))void work(async()=>{await api(`${base}/${row.id}`,'DELETE');setLink(null);setSelected(null);setInspection(null);await load(master);});}}><Trash2 size={15}/>Delete</button></div></td></tr>)}</tbody></table></div>
   {!visibleRows.length&&<p className="muted settings-panel">{records?'No records yet. Enter a title and data above.':'No documents yet. Choose a file above to encrypt and upload.'}</p>}<div className="section-toolbar settings-panel"><button className="button secondary" disabled={page===0} onClick={()=>setPage(page-1)}>Previous</button><span>Page {page+1} of {Math.max(1,Math.ceil(visibleRows.length/10))} · 10 per page</span><button className="button secondary" disabled={(page+1)*10>=visibleRows.length} onClick={()=>setPage(page+1)}>Next</button></div>
  </section>}
  {master&&inspection&&<section className="panel settings-panel section-gap" aria-label="Record storage details"><div className="section-toolbar"><h2>{inspection.row.name}</h2><button className="button secondary" onClick={()=>setInspection(null)}>Close details</button></div><p>Stored as AES-256-GCM encrypted bytes, encoded as Base64 strings. Base64 is only the storage encoding; it is not the encryption.</p><p className="muted">Record ID: {inspection.row.id} · {inspection.row.ciphertext_size} encrypted bytes · {inspection.chunks.length} chunks</p><label className="field"><span>Exact ciphertext strings returned by storage (JSON array, chunk order)</span><textarea readOnly rows={7} value={JSON.stringify(inspection.chunks,null,2)} style={{width:'100%',fontFamily:'monospace'}}/></label><details><summary>Encrypted metadata and wrapped key stored on server</summary><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{JSON.stringify({metadata:inspection.row.metadata,wrapped_key:inspection.row.wrapped_key},null,2)}</pre></details><div className="button-row"><button className="button primary" disabled={busy||!inspection.row.key} onClick={()=>void work(reveal)}>Decrypt & view actual data</button>{inspection.plain!==undefined&&<button className="button secondary" onClick={()=>setInspection({...inspection,plain:undefined})}>Hide actual data</button>}</div>{inspection.plain!==undefined&&<label className="field"><span>Actual saved data — decrypted only in this browser</span><textarea readOnly rows={10} value={inspection.plain} style={{width:'100%',fontFamily:'monospace'}}/></label>}</section>}
  {master&&link&&<section className="panel settings-panel section-gap"><h2>Public link generated</h2><p>Anyone with the complete link can download this document until {new Date(link.expires).toLocaleString()}. Expiry starts when the link is generated.</p><label className="field"><span>Copy and share privately</span><input readOnly value={link.url} onFocus={event=>event.target.select()}/></label><button className="button primary" onClick={()=>void work(async()=>{await navigator.clipboard.writeText(link.url);setNotice('Link copied');})}>Copy link</button><p className="muted">Expiry/revocation stops new requests. It cannot erase downloaded files or copies. This link is shown only in this session.</p></section>}
  {master&&selected&&<section className="panel settings-panel section-gap"><h2>Links for {selected.name}</h2>{!links.length&&<p>No links created.</p>}{links.map(item=><div className="section-toolbar" key={item.id}><span>{item.revoked_at?'Revoked':new Date(item.expires_at).getTime()<=Date.now()?'Expired':'Active'} · Expires {new Date(item.expires_at).toLocaleString()}</span><button className="button secondary" disabled={busy||!!item.revoked_at} onClick={()=>void work(async()=>{await api(`${base}/${selected.id}/links/${item.id}`,'DELETE');setLink(null);await showLinks(selected);})}>Revoke</button></div>)}</section>}
  <div className="info-note"><LockKeyhole size={18}/><p>The server stores ciphertext, encrypted keys and file sizes. Your vault password stays in this browser. A compromised browser or a server that alters this website’s code can steal keys while you use it. Use a strong, unique vault passphrase; there is no password recovery.</p></div>
 </>;
}
