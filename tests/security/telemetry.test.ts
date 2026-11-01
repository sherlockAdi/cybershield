import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { createApp } from '../../apps/api/src/app';
import { Database } from '../../apps/api/src/database';
import { signingMessage } from '../../apps/api/src/agents';
import { healthSummary, metricsSchema, resourceLevel } from '../../apps/api/src/telemetry-model';
import { totp } from '../../apps/api/src/security';

test('health states distinguish unavailable, stale, warning and critical data', () => {
  assert.equal(resourceLevel('CPU', 80), 'WARNING');
  assert.equal(resourceLevel('MEMORY', 85), 'WARNING');
  assert.equal(resourceLevel('DISK', 95), 'CRITICAL');
  assert.equal(resourceLevel('CPU', null), 'NO_DATA');
  assert.equal(healthSummary('ONLINE', null).state, 'NO_DATA');
  const sample = { cpu_percent: 10, memory_total_bytes: null, disk_total_bytes: null, received_at: new Date(Date.now() - 100000) };
  assert.equal(healthSummary('ONLINE', sample).state, 'STALE');
  assert.equal(healthSummary('UNKNOWN', { ...sample, cpu_percent: 100 }).state, 'UNKNOWN');
  assert.equal(metricsSchema.safeParse({ sampledAt: new Date().toISOString(), cpuPercent: null, memoryTotalBytes: 100, memoryUsedBytes: null, diskTotalBytes: null, diskUsedBytes: null }).success, false);
});

test('Week 4 inventory, metrics and event ingestion acceptance', async suite => {
  const db = await new Database().open(true);
  const { app } = await createApp(db);
  await app.listen(0, '127.0.0.1');
  const base = await app.getUrl();
  class Browser {
    cookies = new Map<string, string>();
    async call(endpoint: string, method = 'GET', value?: unknown) {
      const response = await fetch(`${base}/api${endpoint}`, { method, headers: { Origin: 'http://127.0.0.1:3100', 'Content-Type': 'application/json', Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '), 'X-CSRF-Token': this.cookies.get('sg_csrf') || '' }, body: value === undefined ? undefined : JSON.stringify(value) });
      for (const cookie of response.headers.getSetCookie()) { const [name, value] = cookie.split(';')[0].split('='); this.cookies.set(name, value); }
      return { status: response.status, data: await response.json() as any };
    }
  }
  async function account(email: string) {
    const client = new Browser();
    assert.equal((await client.call('/auth/register', 'POST', { name: 'Telemetry Test', email, password: 'A long telemetry test password!', organization: 'Telemetry Organization' })).status, 201);
    const setup = await client.call('/auth/mfa/setup', 'POST', {});
    assert.equal((await client.call('/auth/mfa/confirm', 'POST', { code: totp(setup.data.secret) })).status, 201);
    const me = (await client.call('/auth/me')).data;
    return { client, organizationId: me.organizations[0].id as string, userId: me.user.id as string };
  }
  const owner = await account('telemetry-owner@example.test');
  const outsider = await account('telemetry-outsider@example.test');
  const organization = `/organizations/${owner.organizationId}`;
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  let registration: any;
  let credentialId: string;
  let sequence = 0;
  const metrics = () => ({ sampledAt: new Date().toISOString(), cpuPercent: 10, memoryTotalBytes: 1024, memoryUsedBytes: 512, diskTotalBytes: 4096, diskUsedBytes: 3072 });
  async function signed(endpoint: string, value: unknown, wrongKey = false) {
    const body = JSON.stringify(value);
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = randomBytes(16).toString('base64url');
    const key = wrongKey ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey : pair.privateKey;
    const signature = sign('sha256', signingMessage(endpoint, timestamp, nonce, Buffer.from(body)), key).toString('base64');
    const response = await fetch(`${base}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SG-Timestamp': timestamp, 'X-SG-Nonce': nonce, 'X-SG-Signature': signature }, body });
    return { status: response.status, data: await response.json() as any };
  }
  function identity() { return { schemaVersion: 1, serverId: registration.serverId, credentialId, sequence: ++sequence }; }
  function report(sample: unknown = metrics()) {
    return { ...identity(), hostname: 'telemetry-vm', os: 'LINUX', osVersion: 'Ubuntu test', agentVersion: '0.4.0-prototype', uptimeSeconds: 10, inventory: { architecture: 'amd64', logicalCpuCount: 4 }, metrics: sample };
  }
  function event(sourceEventId = randomUUID()) { return { sourceEventId, kind: 'AGENT_STARTED', severity: 'INFO', occurredAt: new Date().toISOString(), payload: { source: 'test-agent', message: 'Agent process started' } }; }
  try {
    registration = (await owner.client.call(`${organization}/servers`, 'POST', { hostname: 'telemetry-vm', os: 'LINUX' })).data;
    const enrolled = await signed('/api/agent/v1/enroll', { schemaVersion: 1, serverId: registration.serverId, token: registration.enrollmentToken, publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), hostname: 'telemetry-vm', os: 'LINUX', osVersion: 'Ubuntu test', agentVersion: '0.4.0-prototype' });
    assert.equal(enrolled.status, 201);
    credentialId = enrolled.data.credentialId;

    await suite.test('legacy reports do not invent resource measurements', async () => {
      const legacy = report(); delete (legacy as any).metrics; delete (legacy as any).inventory;
      assert.equal((await signed('/api/agent/v1/heartbeat', legacy)).status, 201);
      const inventory = await owner.client.call(`${organization}/inventory`);
      assert.equal(inventory.status, 200);
      assert.equal(inventory.data.items[0].health.state, 'NO_DATA');
      assert.equal(inventory.data.items[0].latest_metrics, null);
    });
    await suite.test('validated metrics and inventory are stored atomically and bucketed for history', async () => {
      assert.equal((await signed('/api/agent/v1/heartbeat', report())).status, 201);
      const inventory = await owner.client.call(`${organization}/inventory`);
      assert.equal(inventory.data.items[0].logical_cpu_count, 4);
      assert.equal(inventory.data.items[0].architecture, 'amd64');
      assert.equal(inventory.data.items[0].health.state, 'NORMAL');
      assert.equal(inventory.data.items[0].health.resources.MEMORY, 50);
      const history = await owner.client.call(`${organization}/servers/${registration.serverId}/metrics?hours=24`);
      assert.equal(history.status, 200);
      assert.equal(history.data.bucketSeconds, 600);
      assert.equal(history.data.points[0].cpu_percent, 10);
      assert.equal(history.data.points[0].memory_percent, 50);
    });
    await suite.test('invalid ranges, times, payloads and signatures cannot advance metrics', async () => {
      for (const invalid of [{ ...metrics(), cpuPercent: 101 }, { ...metrics(), memoryUsedBytes: 1025 }, { ...metrics(), memoryTotalBytes: null }, { ...metrics(), diskTotalBytes: 0 }, { ...metrics(), sampledAt: new Date(Date.now() - 3600000).toISOString() }]) assert.equal((await signed('/api/agent/v1/heartbeat', report(invalid))).status, 400);
      assert.equal((await signed('/api/agent/v1/heartbeat', report(), true)).status, 401);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM metric_samples')).rows[0].count, 1);
    });
    await suite.test('threshold events occur on transitions, including recovery, without repeated-state floods', async () => {
      assert.equal((await signed('/api/agent/v1/heartbeat', report({ ...metrics(), cpuPercent: 96 }))).status, 201);
      assert.equal((await signed('/api/agent/v1/heartbeat', report({ ...metrics(), cpuPercent: 96 }))).status, 201);
      assert.equal((await signed('/api/agent/v1/heartbeat', report())).status, 201);
      const events = await owner.client.call(`${organization}/events?kind=HEALTH_THRESHOLD`);
      assert.equal(events.status, 200);
      assert.equal(events.data.items.length, 2);
      assert.deepEqual(new Set(events.data.items.map((item: any) => item.payload.level)), new Set(['CRITICAL', 'NORMAL']));
    });
    await suite.test('event batches share heartbeat replay authority and deduplicate stable source IDs', async () => {
      const item = event();
      const batch = { ...identity(), events: [item] };
      const accepted = await signed('/api/agent/v1/events', batch);
      assert.equal(accepted.status, 201);
      assert.equal(accepted.data.acceptedCount, 1);
      assert.equal((await signed('/api/agent/v1/events', batch)).status, 409);
      const retry = await signed('/api/agent/v1/events', { ...identity(), events: [item] });
      assert.equal(retry.status, 201);
      assert.equal(retry.data.acceptedCount, 0);
      assert.equal(retry.data.duplicateCount, 1);
      assert.equal((await signed('/api/agent/v1/heartbeat', { ...report(), sequence: batch.sequence })).status, 409);
    });
    await suite.test('event conflict rolls back the entire batch and does not refresh liveness', async () => {
      const first = event();
      const before = (await db.query('SELECT last_heartbeat_at FROM servers WHERE id=$1', [registration.serverId])).rows[0].last_heartbeat_at;
      const response = await signed('/api/agent/v1/events', { ...identity(), events: [first, { ...first, payload: { ...first.payload, message: 'Changed content' } }] });
      assert.equal(response.status, 409);
      assert.equal((await db.query('SELECT id FROM security_events WHERE source_event_id=$1', [first.sourceEventId])).rows.length, 0);
      assert.equal(new Date((await db.query('SELECT last_heartbeat_at FROM servers WHERE id=$1', [registration.serverId])).rows[0].last_heartbeat_at).getTime(), new Date(before).getTime());
    });
    await suite.test('event schema, retention bounds, size limits and agent signatures are enforced', async () => {
      for (const invalid of [{ ...event(), occurredAt: new Date(Date.now() - 31 * 86400000).toISOString() }, { ...event(), occurredAt: new Date(Date.now() + 3600000).toISOString() }, { ...event(), sourceEventId: 'sg:reserved' }, { ...event(), payload: { source: 'test', password: 'forbidden' } }]) assert.equal((await signed('/api/agent/v1/events', { ...identity(), events: [invalid] })).status, 400);
      assert.equal((await signed('/api/agent/v1/events', { ...identity(), events: Array.from({ length: 101 }, () => event()) })).status, 400);
      assert.equal((await signed('/api/agent/v1/events', { ...identity(), events: [event()] }, true)).status, 401);
      const response = await fetch(`${base}/api/agent/v1/events`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oversized: 'x'.repeat(70000) }) });
      assert.equal(response.status, 413);
    });
    await suite.test('labels, group membership and metadata changes enforce tenant and role bounds', async () => {
      const group = await owner.client.call(`${organization}/groups`, 'POST', { name: 'Production' });
      assert.equal(group.status, 201);
      assert.equal((await owner.client.call(`${organization}/servers/${registration.serverId}/metadata`, 'PATCH', { labels: { env: 'production' }, groupIds: [group.data.id] })).status, 200);
      const inventory = await owner.client.call(`${organization}/inventory?q=production&groupId=${group.data.id}`);
      assert.equal(inventory.data.items[0].labels.env, 'production');
      assert.equal(inventory.data.items[0].groups[0].name, 'Production');
      assert.equal((await outsider.client.call(`${organization}/inventory`)).status, 404);
      assert.equal((await outsider.client.call(`${organization}/events`)).status, 404);
      assert.equal((await outsider.client.call(`${organization}/servers/${registration.serverId}/metrics`)).status, 404);
      const foreignGroup = (await outsider.client.call(`/organizations/${outsider.organizationId}/groups`, 'POST', { name: 'Foreign' })).data.id;
      assert.equal((await owner.client.call(`${organization}/servers/${registration.serverId}/metadata`, 'PATCH', { labels: {}, groupIds: [foreignGroup] })).status, 404);
      await db.query('INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,\'VIEWER\')', [owner.organizationId, outsider.userId]);
      assert.equal((await outsider.client.call(`${organization}/inventory`)).status, 200);
      assert.equal((await outsider.client.call(`${organization}/groups`, 'POST', { name: 'Denied' })).status, 403);
      assert.equal((await outsider.client.call(`${organization}/servers/${registration.serverId}/metadata`, 'PATCH', { labels: {}, groupIds: [] })).status, 403);
    });
    await suite.test('inventory and event cursors paginate without duplication or foreign anchors', async () => {
      await owner.client.call(`${organization}/servers`, 'POST', { hostname: 'second-host', os: 'WINDOWS' });
      const first = await owner.client.call(`${organization}/inventory?limit=1`);
      assert.ok(first.data.nextCursor);
      const next = await owner.client.call(`${organization}/inventory?limit=1&cursor=${first.data.nextCursor}`);
      assert.notEqual(next.data.items[0].id, first.data.items[0].id);
      assert.equal((await owner.client.call(`${organization}/inventory?cursor=${randomUUID()}`)).status, 400);
      const firstEvents = await owner.client.call(`${organization}/events?limit=1`);
      const nextEvents = await owner.client.call(`${organization}/events?limit=1&cursor=${firstEvents.data.nextCursor}`);
      assert.notEqual(firstEvents.data.items[0].id, nextEvents.data.items[0].id);
      assert.equal((await owner.client.call(`${organization}/events?severity=INVALID`)).status, 400);
    });
    await suite.test('revoked agents cannot ingest events and old liveness cannot hide revocation', async () => {
      assert.equal((await owner.client.call(`${organization}/servers/${registration.serverId}/revoke`, 'POST', {})).status, 201);
      assert.equal((await signed('/api/agent/v1/events', { ...identity(), events: [event()] })).status, 401);
      const inventory = await owner.client.call(`${organization}/inventory?os=LINUX`);
      assert.equal(inventory.data.items[0].health.state, 'REVOKED_OR_EXPIRED');
    });
  } finally { await app.close(); await db.close(); }
});
