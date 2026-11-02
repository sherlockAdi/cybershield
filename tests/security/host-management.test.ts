import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, generateKeyPairSync, sign, randomBytes } from 'node:crypto';
import { Database } from '../../apps/api/src/database';
import { Actor, ControlService } from '../../apps/api/src/service';
import { AgentService, AgentRequest, signingMessage } from '../../apps/api/src/agents';
import { HostManagementService, managementSchema } from '../../apps/api/src/host-management';

test('host actions are tenant scoped, privileged, fresh, signed, credential bound, expiring and acknowledged', async () => {
 const db=await new Database().open(true), control=new ControlService(db), service=new HostManagementService(db,control), agents=new AgentService(db,control);
 const org=randomUUID(), foreign=randomUUID(), user=randomUUID(), viewer=randomUUID(), server=randomUUID(), credential=randomUUID();
 const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const actor={id:user} as Actor;
 const snapshot={applications:[{id:'systemd:example.service',name:'example.service',kind:'SYSTEMD',state:'active',instance:'123',details:'PID 100',stoppable:true}],rules:[],firewall:true,errors:[],truncated:false,results:[]};
 let sequence=0;
 async function heartbeat(report: object, key=pair.privateKey) {
  const body={schemaVersion:1,serverId:server,credentialId:credential,sequence:++sequence,hostname:'host',os:'LINUX',osVersion:'Test',agentVersion:'0.9.0',uptimeSeconds:10,management:report};
  const rawBody=Buffer.from(JSON.stringify(body)), endpoint='/api/agent/v1/heartbeat', timestamp=String(Math.floor(Date.now()/1000)),nonce=randomBytes(16).toString('base64url');
  return agents.heartbeat({body,rawBody,originalUrl:endpoint,headers:{'x-sg-timestamp':timestamp,'x-sg-nonce':nonce,'x-sg-signature':sign('sha256',signingMessage(endpoint,timestamp,nonce,rawBody),key).toString('base64')}} as AgentRequest);
 }
 try {
  await db.query("INSERT INTO organizations(id,name,updated_at) VALUES($1,'Host',now()),($2,'Foreign',now())",[org,foreign]);
  await db.query("INSERT INTO users(id,name,email,password_hash) VALUES($1,'Owner','host-owner@example.test','unused'),($2,'Viewer','host-viewer@example.test','unused')",[user,viewer]);
  await db.query("INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'OWNER'),($1,$3,'VIEWER')",[org,user,viewer]);
  await db.query("INSERT INTO servers(id,organization_id,hostname,os) VALUES($1,$2,'host','LINUX')",[server,org]);
  await db.query("INSERT INTO agent_credentials(id,organization_id,server_id,public_key_pem,key_fingerprint,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')",[credential,org,server,pair.publicKey.export({format:'pem',type:'spki'}).toString(),'a'.repeat(64)]);
  const block={operation:'BLOCK_IP',ip:'192.0.2.4',scope:'LOGIN',ports:[22]};
  await assert.rejects(service.command(actor,org,server,block),/unavailable|stale/);
  await heartbeat(snapshot);
  await assert.rejects(service.read(actor,foreign,server));
  await assert.rejects(service.command({id:viewer} as Actor,org,server,block));
  await assert.rejects(service.command(actor,org,server,{...block,ip:'example.com'}));
  await assert.rejects(service.command(actor,org,server,{...block,ports:[]}));
  await assert.rejects(service.command(actor,org,server,{operation:'STOP_APPLICATION',applicationId:snapshot.applications[0].id,instance:'old'}));
  const queued=await service.command(actor,org,server,block);
  await assert.rejects(service.command(actor,org,server,block),/previous/);
  await assert.rejects(heartbeat(snapshot,generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey));
  const dispatch=await heartbeat(snapshot);
  assert.equal(dispatch.command?.id,queued.id);
  assert.equal((await heartbeat(snapshot)).command?.id,queued.id,'lost response redelivers same command');
  const ack={...snapshot,results:[{id:queued.id,success:true,message:'verified'}]};
  assert.equal((await heartbeat(ack)).command,null);
  await heartbeat(ack);
  let records=await service.read(actor,org,server);
  assert.equal(records.commands[0].state,'SUCCEEDED');
  assert.equal((await db.query("SELECT id FROM audit_logs WHERE action='host.command_result'")).rows.length,1);
  const stop=await service.command(actor,org,server,{operation:'STOP_APPLICATION',applicationId:snapshot.applications[0].id,instance:'123'});
  await db.query("UPDATE host_commands SET expires_at=now()-interval '1 second' WHERE id=$1",[stop.id]);
  assert.equal((await heartbeat(snapshot)).command,null);
  assert.equal((await service.read(actor,org,server)).commands[0].state,'EXPIRED');
  await service.command(actor,org,server,block);
  await db.query("UPDATE memberships SET role='VIEWER' WHERE organization_id=$1 AND user_id=$2",[org,user]);
  assert.equal((await heartbeat(snapshot)).command,null,'role removal cancels dispatch');
  assert.equal(managementSchema.safeParse({...snapshot,applications:[{...snapshot.applications[0],command:'arbitrary shell'}]}).success,false);
 } finally {await db.close();}
});
