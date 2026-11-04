import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Database, Queryable } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';

const encoded = (max: number) => z.string().min(4).max(max).refine(value => /^[A-Za-z0-9+/]*={0,2}$/.test(value) && Buffer.from(value,'base64').toString('base64') === value, 'Invalid encoding');
const envelope = z.object({ iv: encoded(16).refine(value => Buffer.from(value,'base64').length === 12), data: encoded(4096) }).strict();
const wrapped = envelope.refine(value => Buffer.from(value.data,'base64').length === 48, 'Invalid wrapped key');
const vaultSchema = z.object({salt: encoded(24).refine(value => Buffer.from(value,'base64').length === 16), wrappedKey: wrapped}).strict();
const documentSchema = z.object({id: uuid, wrappedKey: wrapped, metadata: envelope, ciphertextSize: z.number().int().min(17).max(5242896), chunkCount: z.number().int().min(1).max(107)}).strict().refine(value => value.chunkCount === Math.ceil(value.ciphertextSize / 49152), 'Invalid chunk count');
const chunkSchema = z.object({index: z.number().int().min(0).max(106), ciphertext: encoded(65536)}).strict();
const hash = (value: string) => createHash('sha256').update(value).digest('hex');

@Injectable()
export class DocumentService {
 constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}
 private async own(client: Queryable, actor: Actor, org: string, id: string) {
  await this.control.membership(client,org,actor);
  const row=(await client.query('SELECT * FROM encrypted_documents WHERE id=$1 AND organization_id=$2 AND user_id=$3',[input(uuid,id),org,actor.id])).rows[0];
  if(!row) throw new NotFoundException('Document not found');
  return row;
 }
 async vault(actor: Actor, org: string) {
  await this.control.membership(this.db,org,actor);
  return (await this.db.query('SELECT salt,wrapped_key FROM document_vaults WHERE organization_id=$1 AND user_id=$2',[org,actor.id])).rows[0] || null;
 }
 async createVault(actor: Actor, org: string, body: unknown) {
  const data=input(vaultSchema,body);
  return this.db.transaction(async client => {
   await this.control.membership(client,org,actor);
   const result=await client.query('INSERT INTO document_vaults(organization_id,user_id,salt,wrapped_key) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING RETURNING user_id',[org,actor.id,data.salt,JSON.stringify(data.wrappedKey)]);
   if(!result.rows.length) throw new ConflictException('Vault already exists. Unlock the existing vault.');
   await this.control.audit(client,org,actor.id,'document.vault_created',actor.id);
   return {ok:true};
  });
 }
 async list(actor: Actor, org: string) {
  await this.control.membership(this.db,org,actor);
  return (await this.db.query('SELECT id,wrapped_key,metadata,ciphertext_size,chunk_count,ready,created_at FROM encrypted_documents WHERE organization_id=$1 AND user_id=$2 ORDER BY created_at DESC,id DESC LIMIT 100',[org,actor.id])).rows;
 }
 async create(actor: Actor, org: string, body: unknown) {
  const data=input(documentSchema,body);
  return this.db.transaction(async client => {
   await this.control.membership(client,org,actor);
   const vault=await client.query('SELECT user_id FROM document_vaults WHERE organization_id=$1 AND user_id=$2 FOR UPDATE',[org,actor.id]);
   if(!vault.rows.length) throw new ConflictException('Create your vault first');
   const used=(await client.query('SELECT count(*)::int AS count,COALESCE(sum(ciphertext_size),0)::bigint AS bytes FROM encrypted_documents WHERE organization_id=$1 AND user_id=$2',[org,actor.id])).rows[0];
   if(used.count>=100 || Number(used.bytes)+data.ciphertextSize>104857600) throw new ConflictException('Vault limit: 100 documents / 100 MiB. Delete unused files first.');
   await client.query('INSERT INTO encrypted_documents(id,organization_id,user_id,wrapped_key,metadata,ciphertext_size,chunk_count) VALUES($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7)',[data.id,org,actor.id,JSON.stringify(data.wrappedKey),JSON.stringify(data.metadata),data.ciphertextSize,data.chunkCount]);
   return {id:data.id};
  });
 }
 async uploadChunk(actor: Actor, org: string, id: string, body: unknown) {
  const data=input(chunkSchema,body);
  return this.db.transaction(async client => {
   await this.own(client,actor,org,id);
   const row=(await client.query('SELECT * FROM encrypted_documents WHERE id=$1 FOR UPDATE',[id])).rows[0];
   if(row.ready) throw new ConflictException('Completed documents cannot be modified');
   const expected=data.index===row.chunk_count-1 ? row.ciphertext_size-data.index*49152 : 49152;
   if(data.index>=row.chunk_count || Buffer.from(data.ciphertext,'base64').length!==expected) throw new BadRequestException('Invalid chunk size');
   await client.query('INSERT INTO document_chunks(document_id,chunk_index,ciphertext) VALUES($1,$2,$3) ON CONFLICT(document_id,chunk_index) DO UPDATE SET ciphertext=excluded.ciphertext',[id,data.index,data.ciphertext]);
   return {ok:true};
  });
 }
 async complete(actor: Actor, org: string, id: string) {
  return this.db.transaction(async client => {
   await this.own(client,actor,org,id);
   const row=(await client.query('SELECT * FROM encrypted_documents WHERE id=$1 FOR UPDATE',[id])).rows[0];
   const count=(await client.query('SELECT count(*)::int AS count FROM document_chunks WHERE document_id=$1',[id])).rows[0].count;
   if(count!==row.chunk_count) throw new ConflictException('Upload incomplete');
   if(!row.ready) {
    await client.query('UPDATE encrypted_documents SET ready=true WHERE id=$1',[id]);
    await this.control.audit(client,org,actor.id,'document.uploaded',id);
   }
   return {ok:true};
  });
 }
 async chunk(actor: Actor, org: string, id: string, index: string) {
  const row=await this.own(this.db,actor,org,id);
  if(!row.ready) throw new ConflictException('Upload incomplete');
  const number=input(z.coerce.number().int().min(0).max(106),index);
  const chunk=(await this.db.query('SELECT ciphertext FROM document_chunks WHERE document_id=$1 AND chunk_index=$2',[id,number])).rows[0];
  if(!chunk) throw new NotFoundException('Chunk not found');
  return chunk;
 }
 async remove(actor: Actor, org: string, id: string) {
  return this.db.transaction(async client => {
   await this.own(client,actor,org,id);
   await client.query('DELETE FROM encrypted_documents WHERE id=$1',[id]);
   await this.control.audit(client,org,actor.id,'document.deleted',id);
   return {ok:true};
  });
 }
 async links(actor: Actor, org: string, id: string) {
  await this.own(this.db,actor,org,id);
  return (await this.db.query('SELECT id,created_at,expires_at,revoked_at FROM document_links WHERE document_id=$1 ORDER BY created_at DESC LIMIT 100',[id])).rows;
 }
 async share(actor: Actor, org: string, id: string, body: unknown) {
  const {minutes}=input(z.object({minutes:z.union([z.literal(1),z.literal(30)])}).strict(),body);
  return this.db.transaction(async client => {
   const row=await this.own(client,actor,org,id);
   if(!row.ready) throw new ConflictException('Upload incomplete');
   await client.query('SELECT id FROM encrypted_documents WHERE id=$1 FOR UPDATE',[id]);
   const count=(await client.query('SELECT count(*)::int AS count FROM document_links WHERE document_id=$1 AND revoked_at IS NULL AND expires_at>now()',[id])).rows[0].count;
   if(count>=10) throw new ConflictException('Revoke an active link first (maximum 10)');
   const token=randomBytes(32).toString('base64url'), linkId=randomUUID();
   const result=await client.query("INSERT INTO document_links(id,document_id,token_hash,expires_at) VALUES($1,$2,$3,now()+$4*interval '1 minute') RETURNING expires_at",[linkId,id,hash(token),minutes]);
   await this.control.audit(client,org,actor.id,'document.link_created',id,{linkId,minutes});
   return {id:linkId,token,expiresAt:result.rows[0].expires_at};
  });
 }
 async revoke(actor: Actor, org: string, id: string, linkId: string) {
  return this.db.transaction(async client => {
   await this.own(client,actor,org,id);
   await client.query('UPDATE document_links SET revoked_at=now() WHERE document_id=$1 AND id=$2',[id,input(uuid,linkId)]);
   await this.control.audit(client,org,actor.id,'document.link_revoked',id,{linkId});
   return {ok:true};
  });
 }
 async publicRead(body: unknown) {
  const {token,index}=input(z.object({token:z.string().regex(/^[A-Za-z0-9_-]{43}$/),index:z.number().int().min(0).max(106).optional()}).strict(),body);
  // Every chunk re-checks expiry, revocation, membership and account status using database time.
  const row=(await this.db.query(`SELECT d.id,d.metadata,d.chunk_count,d.ciphertext_size,l.expires_at,now() AS server_time,c.ciphertext
   FROM document_links l JOIN encrypted_documents d ON d.id=l.document_id
   JOIN users u ON u.id=d.user_id JOIN memberships m ON m.user_id=d.user_id AND m.organization_id=d.organization_id
   LEFT JOIN document_chunks c ON c.document_id=d.id AND c.chunk_index=$2
   WHERE l.token_hash=$1 AND l.revoked_at IS NULL AND l.expires_at>now() AND d.ready=true AND u.disabled_at IS NULL`,[hash(token),index ?? -1])).rows[0];
  if(!row || (index!==undefined&&!row.ciphertext)) throw new NotFoundException('Link expired, revoked or unavailable');
  if(index!==undefined) return {ciphertext:row.ciphertext};
  return {id:row.id,metadata:row.metadata,chunk_count:row.chunk_count,ciphertext_size:row.ciphertext_size,expires_at:row.expires_at,server_time:row.server_time};
 }
}
