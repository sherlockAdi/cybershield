import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { createApp } from '../../apps/api/src/app';
import { Database } from '../../apps/api/src/database';
import { DetectionService } from '../../apps/api/src/detections';
import { ControlService } from '../../apps/api/src/service';
import { signingMessage } from '../../apps/api/src/agents';
import { defaultDetectionConfig } from '../../apps/api/src/detection-model';
import { normalizeJournal, normalizeWindows } from '../../apps/api/src/observations';
import { eventSchema } from '../../apps/api/src/telemetry-model';
import { totp } from '../../apps/api/src/security';

test('SSH journal normalization uses stable IDs and does not forward raw log fields', () => {
  const record = { __CURSOR: 's=stable-cursor', __REALTIME_TIMESTAMP: String(BigInt(Date.now()) * 1000n), _COMM: 'sshd', MESSAGE: 'Failed password for invalid user alice from 192.0.2.5 port 43210 ssh2', _CMDLINE: 'must-not-forward' };
  const event = normalizeJournal(record)!; assert.equal(event.kind, 'AUTH_FAILURE'); assert.equal(event.payload.service, 'SSH'); assert.equal(event.payload.account, 'alice');
  assert.equal(event.sourceEventId, normalizeJournal(record)!.sourceEventId); assert.equal(JSON.stringify(event).includes('must-not-forward'), false); assert.equal(event.payload.message, undefined);
  assert.equal(normalizeJournal({ ...record, _COMM: 'logger' }), null);
  assert.equal(normalizeJournal({ ...record, MESSAGE: 'Failed password for alice from not-an-ip port 1234' }), null);
  assert.equal(normalizeJournal({ ...record, MESSAGE: 'Accepted publickey for alice from 2001:db8::5 port 1234 ssh2' })?.kind, 'AUTH_SUCCESS');
});

test('Windows projection limits RDP to RemoteInteractive and extracts process metadata without arguments', () => {
  const record = { provider: 'Microsoft-Windows-Security-Auditing', channel: 'Security', computer: 'test-win', recordId: '123', eventId: 4625, timeCreated: new Date().toISOString(), data: { LogonType: '10', IpAddress: '192.0.2.9', TargetUserName: 'alice', Password: 'never-forward-this' } };
  assert.equal(normalizeWindows(record)?.payload.service, 'RDP'); assert.equal(normalizeWindows({ ...record, data: { ...record.data, LogonType: '3' } }), null);
  assert.equal(normalizeWindows({ ...record, provider: 'unknown' }), null);
  assert.equal(JSON.stringify(normalizeWindows(record)).includes('never-forward-this'), false);
  const process = normalizeWindows({ ...record, eventId: 4688, data: { NewProcessName: 'C:\\Tools\\MIMIKATZ.EXE', NewProcessId: '0x123', ParentProcessName: 'C:\\Windows\\cmd.exe', CommandLine: 'never-forward-arguments' } })!;
  assert.equal(process.kind, 'PROCESS_START'); assert.equal(process.payload.processId, '291'); assert.equal(process.payload.processName, 'mimikatz.exe'); assert.equal(JSON.stringify(process).includes('never-forward-arguments'), false);
});

test('strict observation schema bounds IPs, process identity and sensitive extra fields', () => {
  const event = { sourceEventId: 'test-id', kind: 'AUTH_FAILURE', severity: 'INFO', occurredAt: new Date().toISOString(), payload: { source: 'test', service: 'SSH', sourceIp: '2001:0DB8:0::1' } };
  assert.equal(eventSchema.parse(event).payload.sourceIp, '2001:db8::1');
  for (const payload of [{ ...event.payload, sourceIp: 'example.com' }, { ...event.payload, sourceIp: 'fe80::1%zone' }, { ...event.payload, password: 'secret' }, { ...event.payload, service: undefined }, { source: 'test', commandLine: 'secret' }]) assert.equal(eventSchema.safeParse({ ...event, kind: 'AUTH_SUCCESS', payload }).success, false);
  assert.equal(eventSchema.safeParse({ ...event, kind: 'PROCESS_START', payload: { source: 'test', processName: 'cmd.exe', processId: '4294967296' } }).success, false);
});

test('Week 8 detections, incidents and notification acceptance', async suite => {
  const db = await new Database().open(true); const { app } = await createApp(db); await app.listen(0, '127.0.0.1'); const base = await app.getUrl();
  const relay = app.get(DetectionService);
  class Browser {
    cookies = new Map<string, string>();
    async call(endpoint: string, method = 'GET', body?: unknown, csrf = true) {
      const response = await fetch(`${base}/api${endpoint}`, { method, headers: { Origin: 'http://127.0.0.1:3100', 'Content-Type': 'application/json', Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '), 'X-CSRF-Token': csrf ? this.cookies.get('sg_csrf') || '' : 'invalid' }, body: body === undefined ? undefined : JSON.stringify(body) });
      for (const cookie of response.headers.getSetCookie()) { const [name, value] = cookie.split(';')[0].split('='); this.cookies.set(name, value); }
      return { status: response.status, data: await response.json() as any };
    }
  }
  async function account(email: string) {
    const client = new Browser(); assert.equal((await client.call('/auth/register', 'POST', { name: 'Detection Tester', email, password: 'A long detection testing password!', organization: 'Detection Test' })).status, 201);
    const setup = await client.call('/auth/mfa/setup', 'POST', {}); assert.equal((await client.call('/auth/mfa/confirm', 'POST', { code: totp(setup.data.secret) })).status, 201);
    const me = (await client.call('/auth/me')).data; return { client, org: me.organizations[0].id as string, id: me.user.id as string };
  }
  const owner = await account('detect-owner@example.test'); const outsider = await account('detect-outsider@example.test');
  const root = `/organizations/${owner.org}`;
  let hostname = 0;
  async function agent(os = 'LINUX') {
    const record = (await owner.client.call(`${root}/servers`, 'POST', { hostname: `detect-host-${++hostname}`, os })).data;
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); let sequence = 0; let credentialId = '';
    async function request(endpoint: string, body: unknown, badSignature = false) {
      const raw = JSON.stringify(body); const timestamp = String(Math.floor(Date.now() / 1000)); const nonce = randomBytes(16).toString('base64url');
      const response = await fetch(`${base}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SG-Timestamp': timestamp, 'X-SG-Nonce': nonce, 'X-SG-Signature': sign('sha256', signingMessage(endpoint, timestamp, nonce, Buffer.from(raw)), badSignature ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey : pair.privateKey).toString('base64') }, body: raw });
      return { status: response.status, data: await response.json() as any };
    }
    const enrolled = await request('/api/agent/v1/enroll', { schemaVersion: 1, serverId: record.serverId, token: record.enrollmentToken, publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), hostname: `detect-host-${hostname}`, os, osVersion: 'Test OS', agentVersion: '0.8-test' }); assert.equal(enrolled.status, 201); credentialId = enrolled.data.credentialId;
    return { id: record.serverId as string, events: (events: unknown[], bad = false) => request('/api/agent/v1/events', { schemaVersion: 1, serverId: record.serverId, credentialId, sequence: ++sequence, events }, bad) };
  }
  const observation = (kind = 'AUTH_FAILURE', patch: Record<string, unknown> = {}, occurredAt = new Date().toISOString()) => ({ sourceEventId: randomUUID(), kind, severity: 'CRITICAL', occurredAt, payload: { source: 'acceptance-fixture', ...(kind.startsWith('AUTH_') ? { service: 'SSH', sourceIp: '192.0.2.55' } : { processName: 'mimikatz.exe', processId: '123' }), ...patch } });
  const linux = await agent(); const windows = await agent('WINDOWS'); const separate = await agent();
  let burstId: string; let successId: string;
  const count = async (serverId: string, rule: string) => (await db.query('SELECT count(*)::int AS count FROM incidents WHERE server_id=$1 AND rule_key=$2', [serverId, rule])).rows[0].count;
  try {
    await suite.test('SSH threshold, bounded evidence and durable outbox are atomic; notifications are not prematurely sent', async () => {
      assert.equal((await linux.events(Array.from({ length: 4 }, () => observation()))).status, 201); assert.equal(await count(linux.id, 'SSH_FAILURE_BURST'), 0);
      assert.equal((await linux.events([observation()])).status, 201); assert.equal(await count(linux.id, 'SSH_FAILURE_BURST'), 1);
      const incident = (await db.query("SELECT * FROM incidents WHERE server_id=$1 AND rule_key='SSH_FAILURE_BURST'", [linux.id])).rows[0]; burstId = incident.id;
      assert.equal(incident.severity, 'MEDIUM'); assert.equal(incident.evidence.failureCountAtDetection, 5); assert.ok(incident.evidence.eventIds.length <= 10);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM notifications')).rows[0].count, 0);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM outbox_events WHERE topic='security.incident_created' AND published_at IS NULL")).rows[0].count, 1);
    });
    await suite.test('burst cooldown survives resolution, retries and multiple source aliases without flooding', async () => {
      const event = observation(); assert.equal((await linux.events([event])).status, 201); assert.equal((await linux.events([event])).data.duplicateCount, 1);
      assert.equal((await owner.client.call(`${root}/incidents/${burstId}`, 'PATCH', { state: 'RESOLVED', reason: 'Investigated test source' })).status, 200);
      assert.equal((await linux.events([observation()])).status, 201); assert.equal(await count(linux.id, 'SSH_FAILURE_BURST'), 1);
      assert.equal((await separate.events(Array.from({ length: 4 }, () => observation()))).status, 201); assert.equal(await count(separate.id, 'SSH_FAILURE_BURST'), 0);
    });
    await suite.test('RDP correlation and success-after-failure indicators use service/source/host isolation', async () => {
      assert.equal((await windows.events(Array.from({ length: 5 }, (_, index) => observation('AUTH_FAILURE', { service: 'RDP', sourceIp: index % 2 ? '2001:0db8::9' : '2001:db8:0:0:0:0:0:9' })))).status, 201);
      assert.equal(await count(windows.id, 'RDP_FAILURE_BURST'), 1); assert.equal(await count(windows.id, 'SSH_FAILURE_BURST'), 0);
      assert.equal((await linux.events([observation('AUTH_SUCCESS', { sourceIp: '192.0.2.99' })])).status, 201); assert.equal(await count(linux.id, 'SSH_SUCCESS_AFTER_FAILURES'), 0);
      assert.equal((await linux.events([observation('AUTH_SUCCESS')])).status, 201); assert.equal(await count(linux.id, 'SSH_SUCCESS_AFTER_FAILURES'), 1);
      const incident = (await db.query("SELECT * FROM incidents WHERE server_id=$1 AND rule_key='SSH_SUCCESS_AFTER_FAILURES'", [linux.id])).rows[0]; successId = incident.id; assert.equal(incident.severity, 'HIGH');
    });
    await suite.test('process watchlist uses normalized basenames, ignores unlisted names and sets its own severity', async () => {
      assert.equal((await linux.events([observation('PROCESS_START', { processName: 'powershell.exe' })])).status, 201); assert.equal(await count(linux.id, 'PROCESS_WATCHLIST'), 0);
      const event = observation('PROCESS_START', { processName: 'MIMIKATZ.EXE' }); assert.equal((await linux.events([event])).status, 201);
      assert.equal((await linux.events([observation('PROCESS_START')])).status, 201); assert.equal(await count(linux.id, 'PROCESS_WATCHLIST'), 1);
      const incident = (await db.query("SELECT * FROM incidents WHERE server_id=$1 AND rule_key='PROCESS_WATCHLIST'", [linux.id])).rows[0]; assert.equal(incident.severity, 'MEDIUM'); assert.match(incident.evidence.caveat, /not a malware verdict/);
    });
    await suite.test('historical/future observations do not produce fresh detections and malformed/tampered reports fail closed', async () => {
      assert.equal((await separate.events(Array.from({ length: 5 }, () => observation('AUTH_FAILURE', { sourceIp: '198.51.100.1' }, new Date(Date.now() - 3600000).toISOString())))).status, 201);
      assert.equal((await separate.events(Array.from({ length: 5 }, () => observation('AUTH_FAILURE', { sourceIp: '198.51.100.2' }, new Date(Date.now() + 120000).toISOString())))).status, 201);
      assert.equal(await count(separate.id, 'SSH_FAILURE_BURST'), 0);
      assert.equal((await linux.events([observation('AUTH_SUCCESS', { sourceIp: 'hostname' })])).status, 400);
      assert.equal((await linux.events([observation('PROCESS_START', { commandLine: 'secret' })])).status, 400);
      assert.equal((await linux.events([observation('PROCESS_START')], true)).status, 401);
    });
    await suite.test('batch conflict rolls back triggering observations, incidents and outbox together', async () => {
      const before = (await db.query('SELECT count(*)::int AS count FROM outbox_events')).rows[0].count;
      const prior = observation('AUTH_FAILURE', { sourceIp: '203.0.113.9' }); assert.equal((await separate.events([prior, ...Array.from({ length: 3 }, () => observation('AUTH_FAILURE', { sourceIp: '203.0.113.9' }))])).status, 201);
      const conflict = { ...prior, payload: { ...prior.payload, sourceIp: '192.0.2.100' } };
      assert.equal((await separate.events([observation('AUTH_FAILURE', { sourceIp: '203.0.113.9' }), conflict])).status, 409);
      assert.equal(await count(separate.id, 'SSH_FAILURE_BURST'), 0); assert.equal((await db.query('SELECT count(*)::int AS count FROM outbox_events')).rows[0].count, before);
    });
    await suite.test('in-app relay is restart-safe and deduplicates deliveries; read status is personal and cannot impersonate', async () => {
      await relay.deliver(); const delivered = (await owner.client.call(`${root}/notifications`)).data; assert.ok(delivered.items.length >= 4); assert.equal(delivered.unreadCount, delivered.items.length);
      const total = delivered.items.length; await new DetectionService(db, app.get(ControlService)).deliver(); assert.equal((await owner.client.call(`${root}/notifications`)).data.items.length, total);
      const notificationId = delivered.items[0].id;
      assert.equal((await outsider.client.call(`${root}/notifications/${notificationId}/read`, 'PATCH', {})).status, 404);
      await db.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'VIEWER')", [owner.org, outsider.id]);
      assert.equal((await outsider.client.call(`${root}/notifications/${notificationId}/read`, 'PATCH', { actorId: owner.id })).status, 400);
      assert.equal((await outsider.client.call(`${root}/notifications/${notificationId}/read`, 'PATCH', {})).status, 200);
      assert.equal((await outsider.client.call(`${root}/notifications/${notificationId}/read`, 'PATCH', {})).status, 200);
      assert.equal((await owner.client.call(`${root}/notifications`)).data.unreadCount, total); assert.equal((await outsider.client.call(`${root}/notifications`)).data.unreadCount, total - 1);
      assert.equal('read_by' in delivered.items[0], false);
    });
    await suite.test('incident access, investigation and settings enforce tenant, role and CSRF', async () => {
      assert.equal((await owner.client.call(`/organizations/${outsider.org}/incidents/${burstId}`)).status, 404);
      assert.equal((await outsider.client.call(`${root}/incidents/${burstId}`, 'PATCH', { state: 'INVESTIGATING', reason: 'Viewer forbidden' })).status, 403);
      assert.equal((await outsider.client.call(`${root}/security/settings`, 'PATCH', defaultDetectionConfig)).status, 403);
      assert.equal((await owner.client.call(`${root}/security/settings`, 'PATCH', defaultDetectionConfig, false)).status, 403);
      await db.query("UPDATE memberships SET role='OPERATOR' WHERE organization_id=$1 AND user_id=$2", [owner.org, outsider.id]);
      assert.equal((await outsider.client.call(`${root}/incidents/${burstId}`, 'PATCH', { state: 'INVESTIGATING', reason: 'Investigating observed source' })).status, 200);
      assert.equal((await outsider.client.call(`${root}/security/settings`, 'PATCH', defaultDetectionConfig)).status, 403);
      const detail = (await owner.client.call(`${root}/incidents/${burstId}`)).data; assert.ok(detail.events.length > 0); assert.equal(detail.incident.resolved_at, null);
      assert.ok((await db.query("SELECT id FROM audit_logs WHERE organization_id=$1 AND resource_id=$2 AND action='incident.state_changed'", [owner.org, burstId])).rows.length >= 2);
    });
    await suite.test('disabled detectors store observations without new alerts; configured process names and inbox suppression work', async () => {
      const custom = { ...defaultDetectionConfig, enabled: false, processWatchlist: ['test-watch.exe'] };
      assert.equal((await owner.client.call(`${root}/security/settings`, 'PATCH', custom)).status, 200);
      assert.equal((await separate.events([observation('PROCESS_START', { processName: 'test-watch.exe' })])).status, 201); assert.equal(await count(separate.id, 'PROCESS_WATCHLIST'), 0);
      assert.equal((await owner.client.call(`${root}/security/settings`, 'PATCH', { ...custom, enabled: true })).status, 200);
      assert.equal((await separate.events([observation('PROCESS_START', { processName: 'test-watch.exe' })])).status, 201); assert.equal(await count(separate.id, 'PROCESS_WATCHLIST'), 1);
      const prior = (await db.query('SELECT count(*)::int AS count FROM notifications')).rows[0].count;
      await owner.client.call(`${root}/security/settings`, 'PATCH', { ...custom, enabled: true, inAppNotifications: false }); await relay.deliver(); assert.equal((await db.query('SELECT count(*)::int AS count FROM notifications')).rows[0].count, prior);
      assert.ok((await db.query("SELECT id FROM outbox_events WHERE last_error='DISABLED_BY_SETTINGS' AND published_at IS NOT NULL")).rows.length > 0);
      await owner.client.call(`${root}/security/settings`, 'PATCH', defaultDetectionConfig);
    });
    await suite.test('relay failures back off, exhaust, remain unsent and can be explicitly retried without duplicates', async () => {
      const id = randomUUID(); const foreign = randomUUID();
      await db.query("INSERT INTO incidents (id,organization_id,title,severity,evidence) VALUES ($1,$2,'Foreign incident','LOW','{}')", [foreign, outsider.org]);
      await db.query("INSERT INTO outbox_events (id,organization_id,topic,payload) VALUES ($1,$2,'security.incident_created',$3::jsonb)", [id, owner.org, JSON.stringify({ incidentId: foreign })]);
      await relay.deliver(); const failed = (await db.query('SELECT * FROM outbox_events WHERE id=$1', [id])).rows[0]; assert.equal(failed.attempts, 1); assert.equal(failed.published_at, null); assert.ok(failed.next_attempt_at); assert.equal(failed.last_error, 'IN_APP_DELIVERY_FAILED');
      await db.query("UPDATE outbox_events SET attempts=4,next_attempt_at=now()-interval '1 second' WHERE id=$1", [id]); await relay.deliver(); assert.equal((await db.query('SELECT attempts FROM outbox_events WHERE id=$1', [id])).rows[0].attempts, 5);
      assert.equal((await outsider.client.call(`${root}/security/deliveries/${id}/retry`, 'POST', {})).status, 403);
      await db.query('UPDATE outbox_events SET payload=$2::jsonb WHERE id=$1', [id, JSON.stringify({ incidentId: successId })]);
      const before = (await db.query('SELECT count(*)::int AS count FROM notifications')).rows[0].count;
      assert.equal((await owner.client.call(`${root}/security/deliveries/${id}/retry`, 'POST', {})).status, 201); await relay.deliver(); assert.ok((await db.query('SELECT published_at FROM outbox_events WHERE id=$1', [id])).rows[0].published_at);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM notifications')).rows[0].count, before);
    });
    await suite.test('incident/inbox cursors paginate without duplication and removed members lose inbox access', async () => {
      const first = (await owner.client.call(`${root}/incidents?limit=1`)).data; assert.ok(first.nextCursor); const next = (await owner.client.call(`${root}/incidents?limit=1&cursor=${first.nextCursor}`)).data; assert.notEqual(first.items[0].id, next.items[0].id);
      const inbox = (await owner.client.call(`${root}/notifications?limit=1`)).data; const older = (await owner.client.call(`${root}/notifications?limit=1&cursor=${inbox.nextCursor}`)).data; assert.notEqual(inbox.items[0].id, older.items[0].id);
      const filtered = (await owner.client.call(`${root}/incidents?severity=HIGH`)).data; assert.ok(filtered.items.every((incident: any) => incident.severity === 'HIGH'));
      await db.query('DELETE FROM memberships WHERE organization_id=$1 AND user_id=$2', [owner.org, outsider.id]); assert.equal((await outsider.client.call(`${root}/notifications`)).status, 404);
      await owner.client.call(`${root}/servers/${separate.id}/revoke`, 'POST', {}); assert.equal((await separate.events([observation('PROCESS_START')])).status, 401);
    });
  } finally { await app.close(); await db.close(); }
});
