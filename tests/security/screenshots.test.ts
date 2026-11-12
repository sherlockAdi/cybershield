import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomUUID,randomBytes,sign} from 'node:crypto';
import {Database} from '../../apps/api/src/database';
import {ControlService,Actor} from '../../apps/api/src/service';
import {AgentService,AgentRequest,signingMessage} from '../../apps/api/src/agents';
import {ScreenshotService} from '../../apps/api/src/screenshots';

test('screenshots default off, require privileged settings, signed fresh uploads, exact revisions and encrypted latest-only storage',async()=>{
 const db=await new Database().open(true),control=new ControlService(db),agents=new AgentService(db,control),screens=new ScreenshotService(db,control,agents);
 const org=randomUUID(),other=randomUUID(),owner=randomUUID(),viewer=randomUUID(),outsider=randomUUID(),credential=randomUUID();
 const actor={id:owner} as Actor,pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 try{
  await db.query("INSERT INTO organizations(id,name,updated_at) VALUES($1,'Office',now()),($2,'Other',now())",[org,other]);
  await db.query("INSERT INTO users(id,name,email,password_hash) VALUES($1,'Owner','screen-owner@example.test','unused'),($2,'Viewer','screen-viewer@example.test','unused'),($3,'Other','screen-other@example.test','unused')",[owner,viewer,outsider]);
  await db.query("INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'OWNER'),($1,$3,'VIEWER'),($4,$5,'OWNER')",[org,owner,viewer,other,outsider]);
  const {serverId:id}=await agents.createServer(actor,org,{hostname:'laptop',os:'WINDOWS',device:true});
  await db.query("INSERT INTO agent_credentials(id,organization_id,server_id,public_key_pem,key_fingerprint,expires_at) VALUES($1,$2,$3,$4,$5,now()+interval '1 day')",[credential,org,id,pair.publicKey.export({format:'pem',type:'spki'}).toString(),'e'.repeat(64)]);
  const jpeg=Buffer.from([255,216,1,2,3,4,255,217]).toString('base64');
  function request(sequence:number,revision:number,key=pair.privateKey,stamp=new Date().toISOString()){
   const body={schemaVersion:1,serverId:id,credentialId:credential,sequence,revision,capturedAt:stamp,jpeg};
   const rawBody=Buffer.from(JSON.stringify(body)),originalUrl='/api/agent/v1/screenshot',timestamp=String(Math.floor(Date.now()/1000)),nonce=randomBytes(16).toString('base64url');
   return {body,rawBody,originalUrl,headers:{'x-sg-timestamp':timestamp,'x-sg-nonce':nonce,'x-sg-signature':sign('sha256',signingMessage(originalUrl,timestamp,nonce,rawBody),key).toString('base64')}} as AgentRequest;
  }
  assert.equal((await screens.read(actor,org,id)).status,'OFF');
  await assert.rejects(screens.ingest(request(1,1)),/disabled/);
  await assert.rejects(screens.read({id:viewer} as Actor,org,id));
  await assert.rejects(screens.read({id:outsider} as Actor,other,id));
  await assert.rejects(screens.configure({id:viewer} as Actor,org,id,{enabled:true,intervalSeconds:1,revision:0}));
  await assert.rejects(screens.configure(actor,org,id,{enabled:true,intervalSeconds:2,revision:0}));
  await screens.configure(actor,org,id,{enabled:true,intervalSeconds:1,revision:0});
  await assert.rejects(screens.ingest(request(1,1,generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey)));
  await screens.ingest(request(1,1));
  assert.equal((await screens.read(actor,org,id)).jpeg,jpeg);
  const stored=(await db.query('SELECT screen_ciphertext FROM servers WHERE id=$1',[id])).rows[0].screen_ciphertext;
  assert.notEqual(stored,jpeg);assert(!stored.includes(jpeg));
  await assert.rejects(screens.ingest(request(1,1)),/sequence/);
  await assert.rejects(screens.ingest(request(2,1)),/interval/);
  await assert.rejects(screens.ingest(request(2,1,pair.privateKey,'2020-01-01T00:00:00Z')),/recent/);
  await screens.configure(actor,org,id,{enabled:true,intervalSeconds:15,revision:1});
  assert.equal((await screens.read(actor,org,id)).jpeg,null);
  await assert.rejects(screens.ingest(request(2,1)),/changed/);
  await screens.ingest(request(2,2));
  await db.query("UPDATE servers SET screen_received_at=now()-interval '61 seconds' WHERE id=$1",[id]);
  assert.equal((await screens.read(actor,org,id)).jpeg,null,'old frame is hidden');
  await screens.configure(actor,org,id,{enabled:false,intervalSeconds:5,revision:2});
  assert.equal((await db.query('SELECT screen_ciphertext FROM servers WHERE id=$1',[id])).rows[0].screen_ciphertext,null);
  await assert.rejects(screens.ingest(request(3,3)),/disabled/);
  await screens.configure(actor,org,id,{enabled:true,intervalSeconds:10,revision:3});
  await db.query("UPDATE memberships SET role='VIEWER' WHERE organization_id=$1 AND user_id=$2",[org,owner]);
  await assert.rejects(screens.ingest(request(3,4)),/authorized/);
  await db.query("UPDATE memberships SET role='OWNER' WHERE organization_id=$1 AND user_id=$2",[org,owner]);
  await agents.revoke(actor,org,id);
  await assert.rejects(screens.ingest(request(3,4)));
 }finally{await db.close();}
});
