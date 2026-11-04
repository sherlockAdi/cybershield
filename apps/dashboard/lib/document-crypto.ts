// All plaintext and keys remain in the browser. Never persist keys in web storage.
export type Envelope = {iv: string; data: string};
export const MAX_FILE = 5 * 1024 * 1024;
export const CHUNK = 49152;
const encoder = new TextEncoder();
export function encode(bytes: Uint8Array): string {
 let result=''; for(let i=0;i<bytes.length;i+=8192) result+=String.fromCharCode(...bytes.subarray(i,i+8192));
 return btoa(result);
}
export function decode(value: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(atob(value), c=>c.charCodeAt(0)); }
export async function importKey(bytes: Uint8Array<ArrayBuffer>) { return crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['encrypt','decrypt']); }
export function randomKey() { return crypto.getRandomValues(new Uint8Array(32)); }
export async function derive(password: string, salt: string) {
 const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',iterations:600000,salt:decode(salt)},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
export async function seal(key: CryptoKey, bytes: Uint8Array<ArrayBuffer>, context: string): Promise<Envelope> {
 const iv=crypto.getRandomValues(new Uint8Array(12));
 return {iv:encode(iv),data:encode(new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(context)},key,bytes)))};
}
export async function open(key: CryptoKey, value: Envelope, context: string): Promise<Uint8Array<ArrayBuffer>> {
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(value.iv),additionalData:encoder.encode(context)},key,decode(value.data)));
}
export type FileMetadata = {name:string;size:number;iv:string};
export async function readMetadata(key: CryptoKey, envelope: Envelope, id: string): Promise<FileMetadata> {
 const data=JSON.parse(new TextDecoder().decode(await open(key,envelope,`document:${id}:metadata:v1`)));
 if(typeof data.name!=='string'||data.name.length>255||!Number.isInteger(data.size)||data.size<1||data.size>MAX_FILE||typeof data.iv!=='string'||decode(data.iv).length!==12) throw new Error('Invalid encrypted metadata');
 return data;
}
export async function encryptFile(key: CryptoKey, bytes: ArrayBuffer, id: string) {
 const iv=crypto.getRandomValues(new Uint8Array(12));
 return {iv:encode(iv),ciphertext:new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encoder.encode(`document:${id}:file:v1`)},key,bytes))};
}
export async function decryptFile(key: CryptoKey, bytes: Uint8Array<ArrayBuffer>, meta: FileMetadata, id: string) {
 const data=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(meta.iv),additionalData:encoder.encode(`document:${id}:file:v1`)},key,bytes);
 if(data.byteLength!==meta.size) throw new Error('Document integrity check failed');
 return data;
}
export function download(data: ArrayBuffer, name: string) {
 // Download as an attachment; never execute uploaded HTML/SVG in our origin.
 const url=URL.createObjectURL(new Blob([data],{type:'application/octet-stream'}));
 const a=document.createElement('a'); a.href=url; a.download=name.replace(/[\\/\x00-\x1f]/g,'_'); a.click();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export async function collect(count: number, size: number, fetchChunk: (index: number)=>Promise<{ciphertext:string}>) {
 if(!Number.isInteger(size)||size<17||size>MAX_FILE+16||count!==Math.ceil(size/CHUNK)) throw new Error('Invalid document size');
 const bytes=new Uint8Array(size);
 for(let i=0;i<count;i++) { const chunk=decode((await fetchChunk(i)).ciphertext); if(chunk.length!==Math.min(CHUNK,size-i*CHUNK)) throw new Error('Incomplete document'); bytes.set(chunk,i*CHUNK); }
 return bytes;
}
