import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { z } from 'zod';
import { createCipheriv, createDecipheriv, randomBytes, hkdfSync } from 'node:crypto';
import { Database } from './database';
import { ControlService, Actor } from './service';
import { AgentService, AgentRequest } from './agents';
import { input, uuid } from './input';
import { mfaKey } from './config';
import { indiaDay } from './activity';
const intervals=z.union([z.literal(1),z.literal(5),z.literal(10),z.literal(15)]);
const upload=z.object({schemaVersion:z.literal(1),serverId:uuid,credentialId:uuid,sequence:z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),revision:z.number().int().min(1),capturedAt:z.string().datetime({offset:true}),jpeg:z.string().min(8).max(128000).regex(/^[A-Za-z0-9+/]+={0,2}$/)}).strict();
function key(org:string,id:string){return Buffer.from(hkdfSync('sha256',mfaKey,Buffer.from(org),Buffer.from(`device-screenshot:${id}`),32));}
function seal(org:string,id:string,jpeg:string){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key(org,id),iv);const bytes=Buffer.concat([cipher.update(jpeg,'utf8'),cipher.final()]);return Buffer.concat([iv,cipher.getAuthTag(),bytes]).toString('base64');}
function open(org:string,id:string,value:string){const bytes=Buffer.from(value,'base64'),cipher=createDecipheriv('aes-256-gcm',key(org,id),bytes.subarray(0,12));cipher.setAuthTag(bytes.subarray(12,28));return Buffer.concat([cipher.update(bytes.subarray(28)),cipher.final()]).toString('utf8');}
@Injectable()
export class ScreenshotService implements OnModuleInit,OnModuleDestroy {
 private cleanup?:ReturnType<typeof setInterval>;
 constructor(@Inject(Database) private readonly db:Database,@Inject(ControlService) private readonly control:ControlService,@Inject(AgentService) private readonly agents:AgentService){}
 onModuleInit(){
  const prune=()=>{
   void this.db.query("UPDATE servers SET screen_ciphertext=NULL,screen_captured_at=NULL WHERE screen_ciphertext IS NOT NULL AND screen_received_at<now()-interval '5 minutes'").catch(()=>{});
   void this.db.query("DELETE FROM device_screenshots WHERE captured_at<now()-interval '72 hours'").catch(()=>{});
  };
  prune();
  this.cleanup=setInterval(prune,60000);
  this.cleanup.unref();
 }
 onModuleDestroy(){if(this.cleanup)clearInterval(this.cleanup);}
 async history(actor:Actor,org:string,id:string,query:unknown){
  await this.control.membership(this.db,org,actor,['OWNER','ADMIN']);
  const {date,before}=input(z.object({date:z.string(),before:uuid.optional()}).strict(),query);
  const day=indiaDay(date);
  const device=await this.db.query('SELECT id FROM servers WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL',[org,input(uuid,id)]);
  if(!device.rows.length)throw new NotFoundException('Device not found');
  const rows=(await this.db.query(`SELECT id,captured_at,ciphertext FROM device_screenshots
   WHERE organization_id=$1 AND server_id=$2 AND captured_at >= $3 AND captured_at < $4
   AND captured_at >= now()-interval '72 hours'
   AND ($5::uuid IS NULL OR (captured_at,id) < (SELECT captured_at,id FROM device_screenshots WHERE organization_id=$1 AND server_id=$2 AND id=$5))
   ORDER BY captured_at DESC,id DESC LIMIT 13`,[org,id,day.start,day.end,before??null])).rows;
  const page=rows.slice(0,12);
  if(page.length)await this.control.audit(this.db,org,actor.id,'device.screenshot_history_viewed',id,{date});
  return {items:page.map(row=>({id:row.id,capturedAt:row.captured_at,jpeg:open(org,id,row.ciphertext)})),next:rows.length>12?page.at(-1)!.id:null};
 }
 async read(actor:Actor,org:string,id:string){
  await this.control.membership(this.db,org,actor,['OWNER','ADMIN']);
  const row=(await this.db.query('SELECT screen_config,screen_ciphertext,screen_captured_at,screen_received_at FROM servers WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL',[org,input(uuid,id)])).rows[0];
  if(!row)throw new NotFoundException('Device not found');
  const fresh=row.screen_config.enabled && row.screen_ciphertext && Date.now()-new Date(row.screen_received_at).getTime()<60000;
  if(fresh){const recent=await this.db.query("SELECT id FROM audit_logs WHERE organization_id=$1 AND actor_id=$2 AND resource_id=$3 AND action='device.screenshot_viewed' AND created_at>now()-interval '1 minute' LIMIT 1",[org,actor.id,id]);if(!recent.rows.length)await this.control.audit(this.db,org,actor.id,'device.screenshot_viewed',id);}
  return {config:row.screen_config,capturedAt:fresh?row.screen_captured_at:null,jpeg:fresh?open(org,id,row.screen_ciphertext):null,status:!row.screen_config.enabled?'OFF':fresh?'LATEST_RECEIVED':'WAITING_FOR_LOCAL_CONSENT_OR_AGENT'};
 }
 async configure(actor:Actor,org:string,id:string,body:unknown){
  const data=input(z.object({enabled:z.boolean(),intervalSeconds:intervals,revision:z.number().int().min(0)}).strict(),body);
  return this.db.transaction(async client=>{
   await this.control.membership(client,org,actor,['OWNER','ADMIN']);
   const row=(await client.query('SELECT screen_config FROM servers WHERE organization_id=$1 AND id=$2 AND device_config IS NOT NULL AND decommissioned_at IS NULL FOR UPDATE',[org,input(uuid,id)])).rows[0];
   if(!row)throw new NotFoundException('Active device not found');
   if(row.screen_config.revision!==data.revision)throw new ConflictException('Screenshot settings changed; refresh');
   const config={...data,revision:data.revision+1,requestedBy:actor.id};
   await client.query('UPDATE servers SET screen_config=$3::jsonb,screen_ciphertext=NULL,screen_captured_at=NULL,screen_received_at=NULL WHERE organization_id=$1 AND id=$2',[org,id,JSON.stringify(config)]);
   await this.control.audit(client,org,actor.id,'device.screenshot_configured',id,config);
   return {config};
  });
 }
 async ingest(request:AgentRequest){
  const data=input(upload,request.body),bytes=Buffer.from(data.jpeg,'base64');
  if(bytes.length>96000||bytes[0]!==255||bytes[1]!==216||bytes[bytes.length-2]!==255||bytes[bytes.length-1]!==217)throw new BadRequestException('Expected bounded JPEG');
  if(Math.abs(Date.now()-Date.parse(data.capturedAt))>30000)throw new BadRequestException('Screenshot must be recent');
  return this.db.transaction(async client=>{
   const {server}=await this.agents.authorizeReport(client,request,data,'/api/agent/v1/screenshot','WINDOWS');
   const row=(await client.query('SELECT device_config,screen_config,screen_received_at FROM servers WHERE id=$1',[data.serverId])).rows[0];
   if(!row.device_config||!row.screen_config.enabled||row.screen_config.revision!==data.revision)throw new ConflictException('Screenshot capture is disabled or settings changed');
   const authorized=await client.query("SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 AND m.user_id=$2 AND m.role IN ('OWNER','ADMIN') AND u.disabled_at IS NULL",[server.organization_id,row.screen_config.requestedBy]);
   if(!authorized.rows.length)throw new ConflictException('Screenshot requester is no longer authorized');
   if(row.screen_received_at&&Date.now()-new Date(row.screen_received_at).getTime()<row.screen_config.intervalSeconds*800)throw new ConflictException('Screenshot interval not reached');
   await client.query('UPDATE agent_credentials SET last_sequence=$2 WHERE id=$1',[data.credentialId,data.sequence]);
   const ciphertext=seal(server.organization_id,data.serverId,data.jpeg);
   await client.query('INSERT INTO device_screenshots (organization_id,server_id,captured_at,ciphertext) VALUES ($1,$2,$3,$4)',[server.organization_id,data.serverId,data.capturedAt,ciphertext]);
   await client.query('UPDATE servers SET screen_ciphertext=$2,screen_captured_at=$3,screen_received_at=now() WHERE id=$1',[data.serverId,ciphertext,data.capturedAt]);
   return {accepted:true,acceptedSequence:data.sequence};
  });
 }
}
