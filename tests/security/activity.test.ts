import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Database } from '../../apps/api/src/database';
import { ControlService, Actor } from '../../apps/api/src/service';
import { ActivityService, indiaDay } from '../../apps/api/src/activity';
import { eventSchema } from '../../apps/api/src/telemetry-model';

test('India-day activity windows use midnight IST, exclusive next midnight, and valid dates', () => {
  const now = Date.parse('2026-10-30T10:00:00Z');
  assert.equal(indiaDay(undefined, now).start, '2026-10-29T18:30:00.000Z');
  assert.equal(indiaDay('2026-10-29', now).end, '2026-10-29T18:30:00.000Z');
  for (const value of ['2026-02-30', '2026-10-31', '2020-01-01', 'not-a-date']) assert.throws(() => indiaDay(value, now));
});
test('activity observations reject ambiguous ping counts, addresses, ports and missing coverage', () => {
  const event = { sourceEventId: 'ping:test', kind: 'ICMP_ECHO', severity: 'INFO', occurredAt: new Date().toISOString(), payload: { source: 'fixture', peerIp: '192.0.2.8', direction: 'INBOUND', transport: 'ICMP', requestCount: '3' } };
  assert.equal(eventSchema.safeParse(event).success, true);
  for (const patch of [{ requestCount: '-1' }, { requestCount: '0' }, { peerIp: 'example.com' }, { direction: 'OUTBOUND' }, { transport: 'TCP' }]) assert.equal(eventSchema.safeParse({ ...event, payload: { ...event.payload, ...patch } }).success, false);
  assert.equal(eventSchema.safeParse({ ...event, kind: 'TELEMETRY_STATUS', payload: { source: 'fixture', collector: 'AUTH', collectorState: 'RUNNING' } }).success, false);
});
test('daily server activity isolates tenants and dates, aggregates repeated ping requests and exposes bounded detail', async () => {
  const db = await new Database().open(true);
  const control = new ControlService(db); const service = new ActivityService(db, control);
  const organization = randomUUID(), foreign = randomUUID(), user = randomUUID(), server = randomUUID(), other = randomUUID();
  try {
    await db.query("INSERT INTO organizations (id,name,updated_at) VALUES ($1,'Activity',now()),($2,'Foreign',now())", [organization, foreign]);
    await db.query("INSERT INTO users (id,name,email,password_hash) VALUES ($1,'Activity user','activity@example.test','unused')", [user]);
    await db.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'OWNER')", [organization, user]);
    await db.query("INSERT INTO servers (id,organization_id,hostname,os) VALUES ($1,$2,'activity-host','LINUX'),($3,$4,'foreign-host','LINUX')", [server, organization, other, foreign]);
    const day = new Date(Date.now() + 19800000 - 86400000).toISOString().slice(0, 10); const window = indiaDay(day); const start = Date.parse(window.start);
    async function add(kind: string, payload: object, time = start + 3600000, target = server, tenant = organization) { await db.query('INSERT INTO security_events (id,organization_id,server_id,source_event_id,kind,severity,occurred_at,payload) VALUES ($1,$2,$3,$4,$5,\'INFO\',$6,$7::jsonb)', [randomUUID(), tenant, target, randomUUID(), kind, new Date(time), JSON.stringify(payload)]); }
    await add('AUTH_SUCCESS', { source: 'fixture', service: 'SSH', sourceIp: '192.0.2.1', account: 'alice' });
    await add('AUTH_FAILURE', { source: 'fixture', service: 'SSH', sourceIp: '192.0.2.1', account: 'bob' });
    await add('NETWORK_CONNECTION', { source: 'fixture', peerIp: '192.0.2.2', direction: 'UNKNOWN', transport: 'TCP', localPort: '443', peerPort: '45678' });
    await add('ICMP_ECHO', { source: 'fixture', peerIp: '192.0.2.3', direction: 'INBOUND', transport: 'ICMP', requestCount: '7' });
    await add('ICMP_ECHO', { source: 'fixture', peerIp: '192.0.2.3', direction: 'INBOUND', transport: 'ICMP', requestCount: '2' });
    await add('AUTH_SUCCESS', { source: 'fixture', sourceIp: '192.0.2.99' }, start - 1);
    await add('AUTH_SUCCESS', { source: 'fixture', sourceIp: '192.0.2.99' }, Date.parse(window.end));
    await add('AUTH_SUCCESS', { source: 'fixture', sourceIp: '192.0.2.99' }, start + 1000, other, foreign);
    const actor = { id: user } as Actor;
    const report = await service.report(actor, organization, server, { date: day });
    assert.equal(report.summary.successful_logins, 1); assert.equal(report.summary.failed_logins, 1); assert.equal(report.summary.unique_observed_ips, 3); assert.equal(report.summary.unique_ping_ips, 1); assert.equal(report.summary.ping_requests, '9');
    assert.equal(report.logins.length, 2); assert.equal(report.connections.length, 1); assert.equal(report.collectors.length, 0); assert.equal(report.peers.length, 3);
    await assert.rejects(service.report(actor, foreign, other, { date: day }));
    await assert.rejects(service.report(actor, organization, other, { date: day }));
  } finally { await db.close(); }
});

test('login pagination traverses beyond 100 rows without gaps or duplicates at tied timestamps', async () => {
 const db=await new Database().open(true), org=randomUUID(), user=randomUUID(), server=randomUUID();
 try {
  await db.query("INSERT INTO organizations(id,name,updated_at) VALUES($1,'Pagination',now())",[org]);
  await db.query("INSERT INTO users(id,name,email,password_hash) VALUES($1,'Pages','pages@example.test','unused')",[user]);
  await db.query("INSERT INTO memberships(organization_id,user_id,role) VALUES($1,$2,'OWNER')",[org,user]);
  await db.query("INSERT INTO servers(id,organization_id,hostname,os) VALUES($1,$2,'pages','LINUX')",[server,org]);
  const day=new Date(Date.now()+19800000-86400000).toISOString().slice(0,10), time=new Date(Date.parse(indiaDay(day).start)+1000);
  for(let i=0;i<105;i++) await db.query("INSERT INTO security_events(id,organization_id,server_id,source_event_id,kind,severity,occurred_at,payload) VALUES($1,$2,$3,$4,'AUTH_SUCCESS','INFO',$5,'{}')",[randomUUID(),org,server,randomUUID(),time]);
  const service=new ActivityService(db,new ControlService(db)), seen=new Set<string>();
  let cursor: string|null=null;
  do {
   const page=await service.report({id:user} as Actor,org,server,{date:day,...(cursor?{loginCursor:cursor}:{})});
   assert.ok(page.logins.length<=10);
   for(const row of page.logins){assert.ok(!seen.has(row.id));seen.add(row.id);}
   cursor=page.nextLoginCursor;
  }while(cursor);
  assert.equal(seen.size,105);
  await assert.rejects(service.report({id:user} as Actor,org,server,{date:day,loginCursor:randomUUID()}));
 }finally{await db.close();}
});
