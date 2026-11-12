import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { Database } from '../../apps/api/src/database';
import { ControlService, Actor } from '../../apps/api/src/service';
import { DeviceService } from '../../apps/api/src/devices';
import { devicePolicyHeartbeat, policyStatus } from '../../apps/api/src/device-policy';
import { AgentService, AgentRequest, signingMessage } from '../../apps/api/src/agents';

test('device registration, drafts and signed audit enforce tenant/role/revision/credential boundaries', async () => {
 const db=await new Database().open(true), control=new ControlService(db), devices=new DeviceService(db,control), agents=new AgentService(db,control);
 const org=randomUUID(), foreign=randomUUID(), user=randomUUID(), viewer=randomUUID(), outsider=randomUUID();
 const actor={id:user} as Actor;
 try {
  await db.query("INSERT INTO organizations(id,name,updated_at) VALUES($1,'Office',now()),($2,'Other',now())",[org,foreign]);
  await db.query("INSERT INTO users(id,name,email,password_hash) VALUES($1,'Owner','device-owner@example.test','unused'),($2,'Viewer','device-viewer@example.test','unused'),($3,'Outside','device-outside@example.test','unused')",[user,viewer,outsider]);
  await db.query("INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'OWNER'),($1,$3,'VIEWER'),($4,$5,'OWNER')",[org,user,viewer,foreign,outsider]);
  await assert.rejects(agents.createServer(actor,org,{hostname:'linux-device',os:'LINUX',device:true}));
  await assert.rejects(agents.createServer({id:viewer} as Actor,org,{hostname:'pc',os:'WINDOWS',device:true}));
  const enrollment=await agents.createServer(actor,org,{hostname:'pc',os:'WINDOWS',device:true});
  const id=enrollment.serverId;
  const initial=await devices.read(actor,org,id);
  assert.equal(initial.device_config.employeeId,null);
  assert.equal(initial.enforcement,'NOT_APPLIED');
  await assert.rejects(devices.read({id:outsider} as Actor,foreign,id));
  await assert.rejects(devices.save({id:viewer} as Actor,org,id,{revision:0,config:initial.device_config}));
  await assert.rejects(devices.save(actor,org,id,{revision:0,config:{...initial.device_config,employeeId:outsider}}));
  await assert.rejects(devices.save(actor,org,id,{revision:0,config:{...initial.device_config,storage:'ALLOWLIST'}}));
  await devices.save(actor,org,id,{revision:0,config:{...initial.device_config,employeeId:viewer,storage:'BLOCK'}});
  await assert.rejects(devices.save(actor,org,id,{revision:0,config:initial.device_config}),/changed/);
  assert.equal((await devices.read(actor,org,id)).enforcement,'NOT_APPLIED');
  assert.equal((await devices.list(actor,org,{})).items.length,1);
  for(let i=0;i<10;i++)await agents.createServer(actor,org,{hostname:`pc-${i}`,os:'WINDOWS',device:true});
  assert.equal((await devices.list(actor,org,{page:1})).items.length,10);
  assert.equal((await devices.list(actor,org,{page:1})).hasNext,true);
  assert.equal((await devices.list(actor,org,{page:2})).items.length,1);
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'}), credential=randomUUID();
  await db.query("INSERT INTO agent_credentials(id,organization_id,server_id,public_key_pem,key_fingerprint,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')",[credential,org,id,pair.publicKey.export({format:'pem',type:'spki'}).toString(),'f'.repeat(64)]);
  const audit={schemaVersion:1,collectedAt:new Date().toISOString(),mode:'AUDIT_ONLY',computerName:'pc',employeeMapping:'NOT_CONFIGURED',deviceIdentity:'SIGNED_AGENT',sections:{firewall:{status:'UNKNOWN',data:[],error:'Unavailable'}},limitations:[]};
  function request(sequence:number,deviceAudit:object,key=pair.privateKey){
   const body={schemaVersion:1,serverId:id,credentialId:credential,sequence,hostname:'pc',os:'WINDOWS',osVersion:'Windows',agentVersion:'1.0',uptimeSeconds:10,deviceAudit};
   const rawBody=Buffer.from(JSON.stringify(body)),originalUrl='/api/agent/v1/heartbeat',timestamp=String(Math.floor(Date.now()/1000)),nonce=randomBytes(16).toString('base64url');
   return {body,rawBody,originalUrl,headers:{'x-sg-timestamp':timestamp,'x-sg-nonce':nonce,'x-sg-signature':sign('sha256',signingMessage(originalUrl,timestamp,nonce,rawBody),key).toString('base64')}} as AgentRequest;
  }
  await assert.rejects(agents.heartbeat(request(1,audit,generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey)));
  await agents.heartbeat(request(1,audit));
  assert.equal((await devices.read(actor,org,id)).device_snapshot.sections.firewall.status,'UNKNOWN');
  await assert.rejects(agents.heartbeat(request(1,audit)),/sequence/i);
  await assert.rejects(agents.heartbeat(request(2,{...audit,collectedAt:'2020-01-01T00:00:00Z'})),/recent/);
  await devices.save(actor,org,id,{revision:1,config:{...initial.device_config,requireEncryption:false},apply:true});
  const dispatch=await db.transaction(client=>devicePolicyHeartbeat(client,org,id,true));
  assert.equal(dispatch?.revision,2);
  const result={revision:2,status:'PARTIAL' as const,controls:[{name:'storage',status:'PENDING_RESTART' as const,message:'Reconnect storage'}]};
  await db.transaction(client=>devicePolicyHeartbeat(client,org,id,true,result));
  assert.equal((await devices.read(actor,org,id)).enforcement,'PARTIAL');
  await db.transaction(client=>devicePolicyHeartbeat(client,org,id,true,result));
  assert.equal((await db.query("SELECT id FROM audit_logs WHERE resource_id=$1 AND action='device.policy_result'",[id])).rows.length,1,'unchanged acknowledgement does not flood audit log');
  await devices.save(actor,org,id,{revision:2,config:initial.device_config,apply:true});
  await db.transaction(client=>devicePolicyHeartbeat(client,org,id,true,result));
  assert.equal((await devices.read(actor,org,id)).enforcement,'PENDING','old acknowledgement cannot apply a new revision');
  await db.query("UPDATE memberships SET role='VIEWER' WHERE organization_id=$1 AND user_id=$2",[org,user]);
  assert.equal(await db.transaction(client=>devicePolicyHeartbeat(client,org,id,true)),null,'demoted requester cannot dispatch policy');
  await db.query("UPDATE memberships SET role='OWNER' WHERE organization_id=$1 AND user_id=$2",[org,user]);
  assert.equal(policyStatus({device_policy_requested:true,device_policy_supported:false}),'AGENT_UPGRADE_REQUIRED');
  assert.equal(policyStatus({device_policy_requested:true,device_policy_supported:true,device_revision:1,device_policy_report:{revision:1,status:'APPLIED'},last_heartbeat_at:'2020-01-01'}),'STALE');
  await agents.revoke(actor,org,id);
  await assert.rejects(agents.heartbeat(request(2,audit)));
 } finally { await db.close(); }
});
