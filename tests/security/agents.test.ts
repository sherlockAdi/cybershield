import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign, verify, createPublicKey, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { Database } from '../../apps/api/src/database';
import { createApp } from '../../apps/api/src/app';
import { TelemetryService } from '../../apps/api/src/telemetry';
import { signingMessage, agentStatus } from '../../apps/api/src/agents';
import { totp, digest } from '../../apps/api/src/security';
import { root } from '../../apps/api/src/config';

function keyPair() { return generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); }
function execute(command: string, args: string[], cwd = root): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env: process.env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let errors = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('Native agent test timed out')); }, 60000);
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { errors += data; });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('exit', code => { clearTimeout(timer); code === 0 ? resolve(output) : reject(new Error(`Native process exited ${code}: ${errors.slice(0, 1000)}`)); });
  });
}

test('agent liveness boundaries use server receipt time and credential state', () => {
  const now = Date.now();
  const server = { credential_id: randomUUID(), last_heartbeat_at: new Date(now - 90000) };
  assert.equal(agentStatus(server, now), 'ONLINE');
  assert.equal(agentStatus({ ...server, last_heartbeat_at: new Date(now - 90001) }, now), 'STALE');
  assert.equal(agentStatus({ ...server, last_heartbeat_at: new Date(now - 300001) }, now), 'UNKNOWN');
  assert.equal(agentStatus({ credential_id: null }, now), 'PENDING_ENROLLMENT');
  assert.equal(agentStatus({ credential_id: null, had_credentials: true }, now), 'REVOKED_OR_EXPIRED');
  assert.equal(agentStatus({ credential_id: 'credential', last_heartbeat_at: null }, now), 'AWAITING_HEARTBEAT');
  assert.equal(agentStatus({ decommissioned_at: new Date() }, now), 'DECOMMISSIONED');
});

test('Week 3 enrollment and heartbeat security acceptance', async suite => {
  const db = await new Database().open(true);
  const { app } = await createApp(db);
  await app.listen(0, '127.0.0.1');
  const base = await app.getUrl();
  class Browser {
    cookies = new Map<string, string>();
    async call(endpoint: string, method = 'GET', body?: unknown) {
      const response = await fetch(`${base}/api${endpoint}`, { method, headers: { Origin: 'http://127.0.0.1:3100', 'Content-Type': 'application/json', Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '), 'X-CSRF-Token': this.cookies.get('sg_csrf') || '' }, body: body === undefined ? undefined : JSON.stringify(body) });
      for (const cookie of response.headers.getSetCookie()) { const [name, value] = cookie.split(';')[0].split('='); this.cookies.set(name, value); }
      return { status: response.status, data: await response.json() as any };
    }
  }
  async function account(email: string) {
    const client = new Browser();
    assert.equal((await client.call('/auth/register', 'POST', { name: 'Agent Test', email, password: 'A long agent test password!', organization: 'Agent Test Organization' })).status, 201);
    const setup = await client.call('/auth/mfa/setup', 'POST', {});
    assert.equal((await client.call('/auth/mfa/confirm', 'POST', { code: totp(setup.data.secret) })).status, 201);
    const me = (await client.call('/auth/me')).data;
    return { client, organizationId: me.organizations[0].id as string, userId: me.user.id as string };
  }
  const owner = await account('agent-owner@example.test');
  const viewer = await account('agent-viewer@example.test');
  const pair = keyPair();
  let registration: any;
  let credential: any;
  async function createServer(os = 'LINUX') {
    const response = await owner.client.call(`/organizations/${owner.organizationId}/servers`, 'POST', { hostname: 'prototype-vm', os });
    assert.equal(response.status, 201);
    return response.data;
  }
  function enrollment(record: any, key = pair, os = 'LINUX') {
    return { schemaVersion: 1, serverId: record.serverId, token: record.enrollmentToken, publicKey: key.publicKey.export({ format: 'pem', type: 'spki' }).toString(), hostname: 'prototype-vm', os, osVersion: 'Test operating system', agentVersion: '0.3.0-prototype' };
  }
  function heartbeat(sequence: number, record = registration, identity = credential, os = 'LINUX') {
    return { schemaVersion: 1, serverId: record.serverId, credentialId: identity.credentialId, sequence, hostname: 'prototype-vm', os, osVersion: 'Test operating system', agentVersion: '0.3.0-prototype', uptimeSeconds: 123 };
  }
  async function signed(endpoint: string, value: unknown, key = pair, options: { timestamp?: number; signBody?: string; origin?: string } = {}) {
    const body = JSON.stringify(value);
    const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1000));
    const nonce = randomBytes(16).toString('base64url');
    const signature = sign('sha256', signingMessage(endpoint, timestamp, nonce, Buffer.from(options.signBody ?? body)), key.privateKey).toString('base64');
    const response = await fetch(`${base}${endpoint}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-SG-Timestamp': timestamp, 'X-SG-Nonce': nonce, 'X-SG-Signature': signature, ...(options.origin ? { Origin: options.origin } : {}) }, body });
    return { status: response.status, data: await response.json() as any };
  }
  try {
    await suite.test('only tenant administrators can register servers and issue enrollment tokens', async () => {
      assert.equal((await viewer.client.call(`/organizations/${owner.organizationId}/servers`)).status, 404);
      await db.query('INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,\'VIEWER\')', [owner.organizationId, viewer.userId]);
      assert.equal((await viewer.client.call(`/organizations/${owner.organizationId}/servers`)).status, 200);
      assert.equal((await viewer.client.call(`/organizations/${owner.organizationId}/servers`, 'POST', { hostname: 'forbidden', os: 'LINUX' })).status, 403);
      registration = await createServer();
      assert.equal((await viewer.client.call(`/organizations/${owner.organizationId}/servers/${registration.serverId}/enrollment`, 'POST', {})).status, 403);
      assert.equal((await viewer.client.call(`/organizations/${owner.organizationId}/servers/${registration.serverId}/revoke`, 'POST', {})).status, 403);
      const saved = (await db.query('SELECT token_hash FROM enrollment_tokens WHERE server_id=$1', [registration.serverId])).rows[0];
      assert.equal(saved.token_hash, digest(registration.enrollmentToken));
      assert.notEqual(saved.token_hash, registration.enrollmentToken);
    });
    await suite.test('enrollment checks OS, server binding, timestamps and key proof', async () => {
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(registration, pair, 'WINDOWS'))).status, 401);
      assert.equal((await signed('/api/agent/v1/enroll', { ...enrollment(registration), serverId: randomUUID() })).status, 401);
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(registration), pair, { timestamp: Math.floor(Date.now() / 1000) - 1000 })).status, 401);
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(registration), keyPair())).status, 401);
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(registration), pair, { origin: 'http://127.0.0.1:3100' })).status, 403);
      const accepted = await signed('/api/agent/v1/enroll', enrollment(registration));
      assert.equal(accepted.status, 201);
      credential = accepted.data;
      const inventory = await owner.client.call(`/organizations/${owner.organizationId}/servers`);
      assert.equal(inventory.data[0].status, 'AWAITING_HEARTBEAT');
      assert.equal(inventory.data[0].last_heartbeat_at, null);
    });
    await suite.test('consumed token binds exactly one identity and supports same-key response recovery', async () => {
      const retry = await signed('/api/agent/v1/enroll', enrollment(registration));
      assert.equal(retry.status, 201);
      assert.equal(retry.data.credentialId, credential.credentialId);
      const attacker = keyPair();
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(registration, attacker), attacker)).status, 401);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM agent_credentials WHERE server_id=$1', [registration.serverId])).rows[0].count, 1);
    });
    await suite.test('signed heartbeat updates health with receipt time and native metadata', async () => {
      const accepted = await signed('/api/agent/v1/heartbeat', heartbeat(1));
      assert.equal(accepted.status, 201);
      assert.equal(accepted.data.acceptedSequence, 1);
      const inventory = await owner.client.call(`/organizations/${owner.organizationId}/servers`);
      assert.equal(inventory.data[0].status, 'ONLINE');
      assert.equal(inventory.data[0].uptime_seconds, '123');
      assert.ok(new Date(inventory.data[0].last_heartbeat_at).getTime() <= Date.now());
    });
    await suite.test('replay, altered bodies, wrong identities and stale timestamps cannot advance health', async () => {
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(1))).status, 409);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(2), pair, { signBody: JSON.stringify(heartbeat(1)) })).status, 401);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(2), keyPair())).status, 401);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(2), pair, { timestamp: Math.floor(Date.now() / 1000) + 1000 })).status, 401);
      assert.equal((await signed('/api/agent/v1/heartbeat', { ...heartbeat(2), serverId: randomUUID() })).status, 401);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(2, registration, credential, 'WINDOWS'))).status, 401);
      assert.equal((await signed('/api/agent/v1/heartbeat', { ...heartbeat(2), command: 'forbidden' })).status, 400);
      assert.equal((await db.query('SELECT last_sequence::text FROM agent_credentials WHERE id=$1', [credential.credentialId])).rows[0].last_sequence, '1');
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(3))).status, 201);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(2))).status, 409);
    });
    await suite.test('expired tokens and non-P256 keys cannot enroll', async () => {
      const expired = await createServer();
      await db.query('UPDATE enrollment_tokens SET expires_at=now()-interval \'1 minute\' WHERE server_id=$1', [expired.serverId]);
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(expired))).status, 401);
      const other = await createServer();
      const wrongCurve = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(other, wrongCurve), wrongCurve)).status, 400);
    });
    await suite.test('disabled or demoted token issuers cannot authorize enrollment', async () => {
      const issued = await viewer.client.call(`/organizations/${viewer.organizationId}/servers`, 'POST', { hostname: 'issuer-test', os: 'LINUX' });
      assert.equal(issued.status, 201);
      const fresh = keyPair();
      await db.query('UPDATE users SET disabled_at=now() WHERE id=$1', [viewer.userId]);
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(issued.data, fresh), fresh)).status, 401);
      await db.query('UPDATE users SET disabled_at=NULL WHERE id=$1', [viewer.userId]);
      await db.query('INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,\'OWNER\')', [viewer.organizationId, owner.userId]);
      assert.equal((await viewer.client.call(`/organizations/${viewer.organizationId}/members/${viewer.userId}`, 'PATCH', { role: 'VIEWER' })).status, 200);
      assert.equal((await signed('/api/agent/v1/enroll', enrollment(issued.data, fresh), fresh)).status, 401);
    });
    await suite.test('competing enrollments cannot claim the same token with different keys', async () => {
      const record = await createServer();
      const first = keyPair();
      const second = keyPair();
      const results = await Promise.all([signed('/api/agent/v1/enroll', enrollment(record, first), first), signed('/api/agent/v1/enroll', enrollment(record, second), second)]);
      assert.deepEqual(results.map(result => result.status).sort(), [201, 401]);
    });
    await suite.test('re-enrollment retires the old key only after new proof succeeds', async () => {
      const issued = await owner.client.call(`/organizations/${owner.organizationId}/servers/${registration.serverId}/enrollment`, 'POST', {});
      assert.equal(issued.status, 201);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(4))).status, 201);
      const replacement = keyPair();
      const accepted = await signed('/api/agent/v1/enroll', enrollment(issued.data, replacement), replacement);
      assert.equal(accepted.status, 201);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(5))).status, 401);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(1, registration, accepted.data), replacement)).status, 201);
      assert.equal((await owner.client.call(`/organizations/${owner.organizationId}/servers/${registration.serverId}/revoke`, 'POST', {})).status, 201);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(2, registration, accepted.data), replacement)).status, 401);
    });
    await suite.test('expired credentials and decommissioned servers cannot send heartbeats', async () => {
      const record = await createServer();
      const fresh = keyPair();
      const accepted = await signed('/api/agent/v1/enroll', enrollment(record, fresh), fresh);
      await db.query('UPDATE agent_credentials SET expires_at=now()-interval \'1 second\' WHERE id=$1', [accepted.data.credentialId]);
      assert.equal((await signed('/api/agent/v1/heartbeat', heartbeat(1, record, accepted.data), fresh)).status, 401);
      assert.equal((await owner.client.call(`/organizations/${owner.organizationId}/servers/${record.serverId}/decommission`, 'POST', {})).status, 201);
      assert.equal((await owner.client.call(`/organizations/${owner.organizationId}/servers/${record.serverId}/enrollment`, 'POST', {})).status, 404);
      const inventory = await owner.client.call(`/organizations/${owner.organizationId}/servers`);
      assert.equal(inventory.data.find((item: any) => item.id === record.serverId).status, 'DECOMMISSIONED');
    });
    await suite.test('native Windows agent enrolls, heartbeats, and resumes its persisted sequence', { skip: process.env.RUN_NATIVE_AGENT_TESTS !== '1' || process.platform !== 'win32' }, async () => {
      const record = await createServer('WINDOWS');
      const directory = path.join(root, '.runtime', 'native-agent-tests', randomUUID());
      await fs.mkdir(directory, { recursive: true });
      const tokenPath = path.join(directory, 'enrollment.token');
      await fs.writeFile(tokenPath, record.enrollmentToken);
      const identity = (await execute('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value'])).trim();
      assert.match(identity, /^S-1-[0-9-]+$/);
      await execute('icacls.exe', [tokenPath, '/inheritance:r', '/grant:r', `*${identity}:(F)`]);
      const eventsPath = path.join(directory, 'events.jsonl');
      await fs.writeFile(eventsPath, Array.from({ length: 5 }, () => JSON.stringify({ sourceEventId: randomUUID(), kind: 'AUTH_FAILURE', severity: 'INFO', occurredAt: new Date().toISOString(), payload: { source: 'native-acceptance', service: 'RDP', sourceIp: '192.0.2.50' } })).join('\n'));
      await execute('icacls.exe', [eventsPath, '/inheritance:r', '/grant:r', `*${identity}:(F)`]);
      const dll = path.join(root, 'agents/windows-agent/bin/Release/net10.0/ServerGuard.Agent.dll');
      const args = [dll, '--api', base, '--server-id', record.serverId, '--token-file', tokenPath, '--state-dir', path.join(directory, 'state'), '--events-file', eventsPath, '--allow-loopback-http', '--once'];
      await execute('dotnet', args);
      assert.equal((await db.query('SELECT last_sequence::text FROM agent_credentials WHERE server_id=$1 AND revoked_at IS NULL', [record.serverId])).rows[0].last_sequence, '2');
      assert.equal((await db.query('SELECT count(*)::int AS count FROM metric_samples WHERE server_id=$1', [record.serverId])).rows[0].count, 1);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM security_events WHERE server_id=$1 AND kind=\'AGENT_STARTED\'', [record.serverId])).rows[0].count, 1);
      assert.equal((await db.query("SELECT count(*)::int AS count FROM incidents WHERE server_id=$1 AND rule_key='RDP_FAILURE_BURST'", [record.serverId])).rows[0].count, 1);
      await execute('dotnet', args);
      assert.equal((await db.query('SELECT last_sequence::text FROM agent_credentials WHERE server_id=$1 AND revoked_at IS NULL', [record.serverId])).rows[0].last_sequence, '4');
      assert.equal((await db.query("SELECT count(*)::int AS count FROM security_events WHERE server_id=$1 AND kind='AUTH_FAILURE'", [record.serverId])).rows[0].count, 5);
      const statePath = path.join(directory, 'state', 'state.json');
      const recoverable = await fs.readFile(statePath);
      for (const corruption of [Buffer.from('{broken'), Buffer.alloc(131073, 120), Buffer.from(JSON.stringify({ ...JSON.parse(recoverable.toString()), Sequence: -1 })), Buffer.from(JSON.stringify({ ...JSON.parse(recoverable.toString()), Sequence: undefined })), Buffer.from(JSON.stringify({ ...JSON.parse(recoverable.toString()), PendingEvents: null })), Buffer.from(JSON.stringify({ ...JSON.parse(recoverable.toString()), ProtectedKey: 'corrupt-key' }))]) {
        await fs.writeFile(statePath, corruption);
        await assert.rejects(execute('dotnet', args), /Native process exited 1/);
        assert.deepEqual(await fs.readFile(statePath), corruption);
      }
      await fs.writeFile(statePath, recoverable);
      await execute('dotnet', args);
      assert.equal((await db.query('SELECT last_sequence::text FROM agent_credentials WHERE server_id=$1 AND revoked_at IS NULL', [record.serverId])).rows[0].last_sequence, '6');
      assert.equal((await db.query('SELECT count(*)::int AS count FROM agent_credentials WHERE server_id=$1', [record.serverId])).rows[0].count, 1);
      const telemetry = app.get(TelemetryService);
      const ingest = telemetry.ingest.bind(telemetry);
      let dropAcknowledgement = true;
      telemetry.ingest = async request => {
        const result = await ingest(request);
        if (dropAcknowledgement) { dropAcknowledgement = false; request.res?.destroy(); }
        return result;
      };
      try {
        await assert.rejects(execute('dotnet', args), /Native process exited 1/);
        const interrupted = JSON.parse((await fs.readFile(statePath)).toString());
        assert.ok(interrupted.PendingEvents.length > 0);
        const stableId = interrupted.PendingEvents[0].sourceEventId;
        assert.equal((await db.query('SELECT count(*)::int AS count FROM security_events WHERE server_id=$1 AND source_event_id=$2', [record.serverId, stableId])).rows[0].count, 1);
        await execute('dotnet', args);
        assert.equal(JSON.parse((await fs.readFile(statePath)).toString()).PendingEvents.length, 0);
        assert.equal((await db.query('SELECT count(*)::int AS count FROM security_events WHERE server_id=$1 AND source_event_id=$2', [record.serverId, stableId])).rows[0].count, 1);
        assert.equal((await db.query("SELECT count(*)::int AS count FROM incidents WHERE server_id=$1 AND rule_key='RDP_FAILURE_BURST'", [record.serverId])).rows[0].count, 1);
      } finally { telemetry.ingest = ingest; }
      assert.equal((await owner.client.call(`/organizations/${owner.organizationId}/servers/${record.serverId}/revoke`, 'POST', {})).status, 201);
      await assert.rejects(execute('dotnet', args), /Native process exited 1/);
    });
  } finally { await app.close(); await db.close(); }
});

test('Go and .NET produce the same signing transcript and Node-verifiable DER signatures', { skip: process.env.RUN_NATIVE_AGENT_TESTS !== '1' }, async () => {
  const go = process.env.GO_BINARY || path.join(root, '.runtime/tools/go/bin/go.exe');
  const vectors = [
    JSON.parse(await execute(go, ['run', '.', '--self-test'], path.join(root, 'agents/linux-agent'))),
    JSON.parse(await execute('dotnet', [path.join(root, 'agents/windows-agent/bin/Release/net10.0/ServerGuard.Agent.dll'), '--self-test'])),
  ];
  const expected = signingMessage('/api/agent/v1/heartbeat', '1700000000', 'abcdefghijklmnopqrstuv', Buffer.from('{"schemaVersion":1}')).toString();
  for (const vector of vectors) {
    assert.equal(vector.message, expected);
    assert.equal(verify('sha256', Buffer.from(vector.message), createPublicKey(vector.publicKey), Buffer.from(vector.signature, 'base64')), true);
  }
});
