import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApp } from '../../apps/api/src/app';
import { Database } from '../../apps/api/src/database';
import { ControlService } from '../../apps/api/src/service';
import { RolloutService } from '../../apps/api/src/rollouts';
import { FirewallService } from '../../apps/api/src/firewall';
import { totp } from '../../apps/api/src/security';

test('Week 7 approvals and simulation rollout safety acceptance', async suite => {
  const db = await new Database().open(true); const { app } = await createApp(db); await app.listen(0, '127.0.0.1'); const base = await app.getUrl();
  const runner = app.get(RolloutService);
  class Browser {
    cookies = new Map<string, string>();
    async call(endpoint: string, method = 'GET', body?: unknown, csrf = true) {
      const response = await fetch(`${base}/api${endpoint}`, { method, headers: { Origin: 'http://127.0.0.1:3100', 'Content-Type': 'application/json', Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '), 'X-CSRF-Token': csrf ? this.cookies.get('sg_csrf') || '' : 'invalid' }, body: body === undefined ? undefined : JSON.stringify(body) });
      for (const cookie of response.headers.getSetCookie()) { const [name, value] = cookie.split(';')[0].split('='); this.cookies.set(name, value); }
      return { status: response.status, data: await response.json() as any };
    }
  }
  async function account(email: string) {
    const client = new Browser(); assert.equal((await client.call('/auth/register', 'POST', { name: 'Rollout Tester', email, password: 'A long rollout testing password!', organization: 'Rollout Test' })).status, 201);
    const setup = await client.call('/auth/mfa/setup', 'POST', {}); assert.equal((await client.call('/auth/mfa/confirm', 'POST', { code: totp(setup.data.secret) })).status, 201);
    const me = (await client.call('/auth/me')).data; return { client, org: me.organizations[0].id as string, id: me.user.id as string };
  }
  const owner = await account('rollout-owner@example.test'); const admin = await account('rollout-admin@example.test'); const viewer = await account('rollout-viewer@example.test');
  await db.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'ADMIN'),($1,$3,'VIEWER')", [owner.org, admin.id, viewer.id]);
  const root = `/organizations/${owner.org}`; const path = `${root}/rollouts`;
  const fixtureActor = { id: owner.id, session_id: randomUUID(), family_id: randomUUID(), name: 'Fixture author', email: 'rollout-owner@example.test', mfa_enabled: true, mfa_verified: true };
  let counter = 0;
  async function fixture(count = 1, servers?: string[]) {
    const ids = servers || [];
    if (!servers) for (let index = 0; index < count; index++) ids.push((await owner.client.call(`${root}/servers`, 'POST', { hostname: `rollout-${++counter}`, os: index % 2 ? 'WINDOWS' : 'LINUX' })).data.serverId);
    let target = { type: 'SERVER', id: ids[0] };
    if (ids.length > 1) {
      const group = (await owner.client.call(`${root}/groups`, 'POST', { name: `Rollout group ${++counter}` })).data.id;
      for (const server of ids) await owner.client.call(`${root}/servers/${server}/metadata`, 'PATCH', { labels: {}, groupIds: [group] });
      target = { type: 'GROUP', id: group };
    }
    const policy = { data: await app.get(FirewallService).create(fixtureActor, owner.org, { name: `Rollout policy ${counter}`, target, rules: [{ id: randomUUID(), cidr: '192.0.2.0/24', action: 'BLOCK', direction: 'INBOUND', protocol: 'TCP', portStart: 8080, portEnd: 8080, expiresAt: null, reason: 'Simulation acceptance rule' }] }) };
    await app.get(FirewallService).submit(fixtureActor, owner.org, policy.data.policyId, policy.data.versionId, { expectedChecksum: policy.data.checksum });
    const request = { mode: 'SIMULATION', versionId: policy.data.versionId, expectedChecksum: policy.data.checksum, canaryServerIds: [ids[0]], batchSize: 1, canaryTimeoutSeconds: 300, reason: 'Exercise sandbox rollout' };
    const created = await owner.client.call(path, 'POST', request); assert.equal(created.status, 201);
    return { id: created.data.deploymentId as string, ids, request, policy: policy.data };
  }
  async function detail(id: string) { const result = await owner.client.call(`${path}/${id}`); assert.equal(result.status, 200); return result.data; }
  async function approve(item: Awaited<ReturnType<typeof fixture>>) { const result = await admin.client.call(`${path}/${item.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: item.policy.checksum, reason: 'Independent sandbox review' }); assert.equal(result.status, 201); }
  async function action(id: string, action: string) { return owner.client.call(`${path}/${id}/actions`, 'POST', { action, reason: 'Acceptance control action' }); }
  async function scenario(id: string, targetId: string, online: boolean, failureMode = 'NONE') { const result = await owner.client.call(`${path}/${id}/targets/${targetId}/scenario`, 'PATCH', { online, failureMode, reason: 'Injected simulation condition' }); assert.equal(result.status, 200); }
  async function step(id: string, times = 1) { for (let index = 0; index < times; index++) await runner.reconcile(owner.org, id); return detail(id); }
  async function canaryVerified(item: Awaited<ReturnType<typeof fixture>>) { await approve(item); const result = await step(item.id, 3); assert.equal(result.targets.find((target: any) => target.is_canary).state, 'VERIFIED'); return result; }
  try {
    await suite.test('live mode, self-approval, author approval, roles, CSRF and foreign tenant access fail closed', async () => {
      const item = await fixture();
      assert.equal((await owner.client.call(path, 'POST', { ...item.request, mode: 'LIVE' })).status, 400);
      assert.equal((await owner.client.call(path, 'POST', { ...item.request, canaryServerIds: [randomUUID()] })).status, 400);
      assert.equal((await owner.client.call(`${path}/${item.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: item.policy.checksum, reason: 'Self approval denied' })).status, 403);
      assert.equal((await viewer.client.call(`${path}/${item.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: item.policy.checksum, reason: 'Viewer approval denied' })).status, 403);
      assert.equal((await admin.client.call(`${path}/${item.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: '0'.repeat(64), reason: 'Wrong checksum denied' })).status, 409);
      assert.equal((await admin.client.call(`${path}/${item.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: item.policy.checksum, reason: 'CSRF denied' }, false)).status, 403);
      assert.equal((await owner.client.call(`/organizations/${admin.org}/rollouts/${item.id}`)).status, 404);
      assert.equal((await viewer.client.call(`${path}/${item.id}`)).status, 200);
      assert.equal((await viewer.client.call(`${path}/${item.id}/targets/${(await detail(item.id)).targets[0].id}/scenario`, 'PATCH', { online: false, failureMode: 'NONE', reason: 'Not allowed' })).status, 403);
      const second = (await admin.client.call(path, 'POST', item.request)).data.deploymentId;
      assert.equal((await owner.client.call(`${path}/${second}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: item.policy.checksum, reason: 'Author cannot approve different requester' })).status, 403);
      await action(item.id, 'CANCEL'); await action(second, 'CANCEL');
    });
    await suite.test('distinct approval is single-use and rejection never dispatches jobs', async () => {
      const item = await fixture(); await approve(item);
      assert.equal((await admin.client.call(`${path}/${item.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: item.policy.checksum, reason: 'Repeated decision' })).status, 409);
      await action(item.id, 'CANCEL');
      const rejected = await fixture();
      assert.equal((await admin.client.call(`${path}/${rejected.id}/decision`, 'POST', { decision: 'REJECT', expectedChecksum: rejected.policy.checksum, reason: 'Reject unsafe experiment' })).status, 201);
      const state = await step(rejected.id); assert.equal(state.deployment.state, 'CANCELLED'); assert.equal(state.jobs.length, 0); assert.ok(state.targets.every((target: any) => target.state === 'CANCELLED'));
    });
    await suite.test('canary verification does not automatically fan out; explicit promotion respects batch bounds', async () => {
      const item = await fixture(3); await approve(item);
      const dispatch = await step(item.id); assert.equal(dispatch.deployment.state, 'CANARY'); assert.equal(dispatch.targets.filter((target: any) => target.state === 'DISPATCHED').length, 1);
      assert.ok(dispatch.targets.filter((target: any) => !target.is_canary).every((target: any) => target.state === 'PENDING'));
      assert.equal((await action(item.id, 'PROMOTE')).status, 409);
      const applied = await step(item.id); assert.equal(applied.targets.find((target: any) => target.is_canary).state, 'APPLIED');
      const confirmed = await step(item.id); assert.equal(confirmed.targets.find((target: any) => target.is_canary).state, 'VERIFIED'); assert.equal(confirmed.deployment.state, 'CANARY');
      assert.equal((await step(item.id)).jobs.filter((job: any) => job.operation === 'APPLY_POLICY').length, 1);
      assert.equal((await action(item.id, 'PROMOTE')).status, 201);
      let latest: any;
      for (let count = 0; count < 10; count++) { latest = await step(item.id); assert.ok(latest.targets.filter((target: any) => ['DISPATCHED', 'APPLIED'].includes(target.state)).length <= 1); if (latest.deployment.state === 'SUCCEEDED') break; }
      assert.equal(latest.deployment.state, 'SUCCEEDED'); assert.equal(latest.jobs.filter((job: any) => job.operation === 'APPLY_POLICY').length, 3);
      assert.ok(latest.targets.every((target: any) => target.confirmed_at && !target.watchdog_deadline_at && target.verification_evidence.mode === 'SIMULATION' && target.verification_evidence.hostAttestation === false));
      assert.equal((await db.query('SELECT count(*)::int AS count FROM servers WHERE organization_id=$1 AND observed_checksum IS NOT NULL', [owner.org])).rows[0].count, 0);
      assert.equal((await action(item.id, 'CANCEL')).status, 409);
      assert.equal((await action(item.id, 'ROLLBACK')).status, 201); const restored = await step(item.id);
      assert.equal(restored.deployment.state, 'ROLLED_BACK'); assert.ok(restored.targets.every((target: any) => target.state === 'ROLLED_BACK'));
      assert.ok((await db.query('SELECT simulation_firewall_state FROM servers WHERE id=ANY($1::uuid[])', [item.ids])).rows.every(server => server.simulation_firewall_state.hash === null));
    });
    await suite.test('failed canary verification pauses fan-out and retained watchdog later restores the sandbox', async () => {
      const item = await fixture(2); await approve(item); const initial = await detail(item.id); const canary = initial.targets.find((target: any) => target.is_canary);
      await scenario(item.id, canary.id, true, 'VERIFY'); const failed = await step(item.id, 3);
      assert.equal(failed.deployment.state, 'PAUSED'); assert.equal(failed.targets.find((target: any) => target.is_canary).state, 'FAILED');
      assert.equal((await action(item.id, 'RESUME')).status, 409); assert.ok(failed.targets.filter((target: any) => !target.is_canary).every((target: any) => target.state === 'PENDING'));
      await db.query("UPDATE deployment_targets SET watchdog_deadline_at=now()-interval '1 second' WHERE id=$1", [canary.id]);
      const restored = await step(item.id); assert.equal(restored.targets.find((target: any) => target.is_canary).state, 'ROLLED_BACK');
      assert.ok(restored.history.some((event: any) => event.action === 'rollout.watchdog_expired'));
      assert.equal((await action(item.id, 'ROLLBACK')).status, 201); assert.equal((await step(item.id)).deployment.state, 'ROLLED_BACK');
    });
    await suite.test('offline pre-dispatch work remains pending, stage timeout pauses, and explicit resume is required', async () => {
      const item = await fixture(); const target = (await detail(item.id)).targets[0]; await scenario(item.id, target.id, false); await approve(item);
      const offline = await step(item.id); assert.equal(offline.targets[0].state, 'PENDING'); assert.equal(offline.jobs.length, 0);
      await db.query("UPDATE policy_deployments SET stage_deadline_at=now()-interval '1 second' WHERE id=$1", [item.id]); assert.equal((await step(item.id)).deployment.state, 'PAUSED');
      await scenario(item.id, target.id, true); assert.equal((await step(item.id)).targets[0].state, 'PENDING');
      assert.equal((await action(item.id, 'RESUME')).status, 201); assert.equal((await step(item.id, 3)).targets[0].state, 'VERIFIED');
      await action(item.id, 'ROLLBACK'); await step(item.id);
      const late = await fixture(); await approve(late); await step(late.id, 2);
      await db.query("UPDATE policy_deployments SET stage_deadline_at=now()-interval '1 second' WHERE id=$1", [late.id]);
      const expired = await step(late.id); assert.equal(expired.deployment.state, 'PAUSED'); assert.equal(expired.targets[0].state, 'APPLIED'); assert.equal(expired.targets[0].confirmed_at, null);
      await action(late.id, 'ROLLBACK'); await step(late.id);
    });
    await suite.test('disconnect after dispatch expires work as UNKNOWN without replay or fabricated verification', async () => {
      const item = await fixture(); await approve(item); const dispatched = await step(item.id); const target = dispatched.targets[0]; await scenario(item.id, target.id, false);
      await db.query("UPDATE deployment_targets SET dispatch_deadline_at=now()-interval '1 second' WHERE id=$1", [target.id]);
      const unknown = await step(item.id); assert.equal(unknown.targets[0].state, 'UNKNOWN'); assert.equal(unknown.deployment.state, 'PAUSED'); assert.equal(unknown.jobs[0].state, 'EXPIRED');
      await scenario(item.id, target.id, true); assert.equal((await step(item.id)).targets[0].state, 'UNKNOWN');
      assert.equal((await action(item.id, 'ROLLBACK')).status, 201); assert.equal((await step(item.id)).deployment.state, 'ROLLED_BACK');
    });
    await suite.test('persisted watchdog survives reconciler recreation and disconnected confirmation', async () => {
      const item = await fixture(); await approve(item); const applied = await step(item.id, 2); const target = applied.targets[0];
      assert.equal(target.state, 'APPLIED'); const deadline = target.watchdog_deadline_at;
      await scenario(item.id, target.id, false); await step(item.id); assert.equal((await detail(item.id)).targets[0].watchdog_deadline_at, deadline);
      await action(item.id, 'PAUSE'); await db.query("UPDATE deployment_targets SET watchdog_deadline_at=now()-interval '1 second' WHERE id=$1", [target.id]);
      const restarted = new RolloutService(db, app.get(ControlService)); await restarted.reconcile(owner.org, item.id);
      const recovered = await detail(item.id); assert.equal(recovered.targets[0].state, 'ROLLED_BACK'); assert.equal(recovered.targets[0].confirmed_at, null);
      assert.equal(recovered.deployment.state, 'PAUSED'); await action(item.id, 'ROLLBACK'); await step(item.id);
    });
    await suite.test('offline confirmed rollback cannot claim success; timeout records rollback failure', async () => {
      const item = await fixture(); const confirmed = await canaryVerified(item); const target = confirmed.targets[0]; await scenario(item.id, target.id, false);
      assert.equal((await action(item.id, 'ROLLBACK')).status, 201); assert.equal((await step(item.id)).deployment.state, 'ROLLING_BACK');
      await db.query("UPDATE agent_jobs SET expires_at=now()-interval '1 second' WHERE target_id=$1 AND operation='ROLLBACK_POLICY'", [target.id]);
      const failed = await step(item.id); assert.equal(failed.deployment.state, 'FAILED'); assert.equal(failed.targets[0].state, 'ROLLBACK_FAILED'); assert.equal(failed.targets[0].error_code, 'OFFLINE_ROLLBACK_TIMEOUT');
      assert.equal((await action(item.id, 'ROLLBACK')).status, 409);
    });
    await suite.test('native-state mismatch and explicit rollback errors never overwrite a different sandbox version', async () => {
      const item = await fixture(); await canaryVerified(item);
      const other = 'f'.repeat(64); await db.query('UPDATE servers SET simulation_firewall_state=$2::jsonb WHERE id=$1', [item.ids[0], JSON.stringify({ hash: other, versionId: randomUUID() })]);
      await action(item.id, 'ROLLBACK'); const failed = await step(item.id); assert.equal(failed.targets[0].state, 'ROLLBACK_FAILED');
      assert.equal((await db.query('SELECT simulation_firewall_state FROM servers WHERE id=$1', [item.ids[0]])).rows[0].simulation_firewall_state.hash, other);
    });
    await suite.test('partial rollback failure does not abandon another unsettled target or report success', async () => {
      const item = await fixture(2); await canaryVerified(item);
      await runner.action(fixtureActor, owner.org, item.id, { action: 'PROMOTE', reason: 'Exercise mixed recovery' });
      await step(item.id, 4);
      const targets = (await detail(item.id)).targets;
      assert.ok(targets.every((target: any) => target.state === 'VERIFIED'));
      await runner.scenario(fixtureActor, owner.org, item.id, targets[0].id, { online: true, failureMode: 'ROLLBACK', reason: 'Simulated restore error' });
      await runner.scenario(fixtureActor, owner.org, item.id, targets[1].id, { online: false, failureMode: 'NONE', reason: 'Temporary disconnection' });
      await runner.action(fixtureActor, owner.org, item.id, { action: 'ROLLBACK', reason: 'Retain unfinished recovery' });
      const partial = await step(item.id); assert.equal(partial.deployment.state, 'ROLLING_BACK'); assert.ok(partial.targets.some((target: any) => target.state === 'ROLLBACK_FAILED'));
      await runner.scenario(fixtureActor, owner.org, item.id, targets[1].id, { online: true, failureMode: 'NONE', reason: 'Restore connectivity' });
      const settled = await step(item.id); assert.equal(settled.deployment.state, 'FAILED'); assert.equal(settled.targets.find((target: any) => target.id === targets[1].id).state, 'ROLLED_BACK');
    });
    await suite.test('approval expiry and changing administrator authority prevent dispatch', async () => {
      const expired = await fixture(); await db.query("UPDATE approval_requests SET expires_at=now()-interval '1 second' WHERE deployment_id=$1", [expired.id]);
      assert.equal((await admin.client.call(`${path}/${expired.id}/decision`, 'POST', { decision: 'APPROVE', expectedChecksum: expired.policy.checksum, reason: 'Too late' })).status, 409);
      const result = await step(expired.id); assert.equal(result.approval.state, 'EXPIRED'); assert.equal(result.deployment.state, 'CANCELLED');
      const demoted = await fixture(); await approve(demoted); await db.query("UPDATE memberships SET role='VIEWER' WHERE organization_id=$1 AND user_id=$2", [owner.org, admin.id]);
      try { const state = await step(demoted.id); assert.equal(state.deployment.state, 'PAUSED'); assert.equal(state.jobs.length, 0); } finally { await db.query("UPDATE memberships SET role='ADMIN' WHERE organization_id=$1 AND user_id=$2", [owner.org, admin.id]); }
      await action(demoted.id, 'CANCEL');
    });
    await suite.test('competing rollout target ownership serializes without queued-to-queued deadlock', async () => {
      const first = await fixture(); const second = await fixture(1, first.ids); await approve(first); await approve(second);
      await step(first.id); const waiting = await step(second.id); assert.equal(waiting.deployment.state, 'QUEUED'); assert.equal(waiting.jobs.length, 0);
      await action(first.id, 'CANCEL'); assert.equal((await step(second.id)).deployment.state, 'CANARY'); await action(second.id, 'CANCEL');
    });
    await suite.test('durable jobs and audit remain tenant-scoped, idempotent and bounded for reads', async () => {
      const item = await fixture(); await approve(item); await step(item.id, 6); const current = await detail(item.id);
      assert.equal(current.jobs.filter((job: any) => job.operation === 'APPLY_POLICY').length, 1); assert.equal(current.jobs.filter((job: any) => job.operation === 'INSPECT_POLICY').length, 1);
      assert.ok(current.history.every((event: any) => event.metadata.mode === 'SIMULATION'));
      await assert.rejects(db.query('UPDATE audit_logs SET action=$2 WHERE id=$1', [current.history[0].id, 'tamper']), /append.only/);
      const first = (await owner.client.call(`${path}?limit=1`)).data; assert.ok(first.nextCursor); const next = (await owner.client.call(`${path}?limit=1&cursor=${first.nextCursor}`)).data; assert.notEqual(first.items[0].id, next.items[0].id);
      assert.equal((await owner.client.call(`${path}?cursor=${randomUUID()}`)).status, 400);
      assert.equal((await owner.client.call(`${path}/${item.id}/verify`, 'POST', { verified: true })).status, 404);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM agent_jobs WHERE payload->>\'mode\' IS DISTINCT FROM \'SIMULATION\'')).rows[0].count, 0);
      await action(item.id, 'ROLLBACK'); await step(item.id);
    });
  } finally { await app.close(); await db.close(); }
});
