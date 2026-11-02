import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Database } from '../../apps/api/src/database';
import { createApp } from '../../apps/api/src/app';
import { totp, digest, encryptSecret, decryptSecret } from '../../apps/api/src/security';

test('TOTP matches RFC 6238 SHA-1 vector and encrypted secrets reject tampering', () => {
  assert.equal(totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1), '287082');
  const encrypted = encryptSecret('secret-value');
  assert.equal(decryptSecret(encrypted), 'secret-value');
  const modified = Buffer.from(encrypted, 'base64');
  modified[modified.length - 1] ^= 1;
  assert.throws(() => decryptSecret(modified.toString('base64')));
});

test('Week 1 migrations and Week 2 HTTP security acceptance', async suite => {
  const db = await new Database().open(true);
  const { app } = await createApp(db);
  await app.listen(0, '127.0.0.1');
  const base = await app.getUrl();
  class Client {
    jar = new Map<string, string>();
    async call(path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) {
      const response = await fetch(`${base}/api${path}`, { method, headers: {
        Origin: 'http://127.0.0.1:3100', 'Content-Type': 'application/json',
        Cookie: [...this.jar].map(([key, value]) => `${key}=${value}`).join('; '),
        'X-CSRF-Token': this.jar.get('sg_csrf') || '', ...headers,
      }, body: body === undefined ? undefined : JSON.stringify(body) });
      for (const cookie of response.headers.getSetCookie()) {
        const [key, value] = cookie.split(';')[0].split('=');
        this.jar.set(key, value);
      }
      return { status: response.status, data: await response.json() as any };
    }
  }
  const owner = new Client();
  const other = new Client();
  const anonymous = new Client();
  let ownerId: string;
  let otherId: string;
  let organizationId: string;
  let otherOrganizationId: string;
  let ownerCodes: string[] = [];
  let otherCodes: string[] = [];
  async function enrollMfa(client: Client) {
    const setup = await client.call('/auth/mfa/setup', 'POST', {});
    assert.equal(setup.status, 201);
    const confirmation = await client.call('/auth/mfa/confirm', 'POST', { code: totp(setup.data.secret) });
    assert.equal(confirmation.status, 201);
    assert.equal(confirmation.data.recoveryCodes.length, 10);
    return confirmation.data.recoveryCodes as string[];
  }
  try {
    await suite.test('schema creates all 25 domain tables', async () => {
      const tables = await db.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name<>'_serverguard_migrations'");
      assert.equal(tables.rows.length, 25);
      assert.equal((await anonymous.call('/health')).status, 200);
      assert.equal((await anonymous.call('/auth/me')).status, 401);
    });
    await suite.test('registration creates owner membership but blocks access until MFA', async () => {
      assert.equal((await owner.call('/auth/register', 'POST', { name: 'Owner One', email: 'OWNER@example.test', password: 'A long test password 123!', organization: 'Alpha Infrastructure' })).status, 201);
      const me = await owner.call('/auth/me');
      ownerId = me.data.user.id;
      organizationId = me.data.organizations[0].id;
      assert.equal(me.data.user.email, 'owner@example.test');
      assert.equal(me.data.organizations[0].role, 'OWNER');
      assert.equal((await owner.call(`/organizations/${organizationId}/overview`)).status, 403);
      const stored = (await db.query('SELECT password_hash FROM users WHERE id=$1', [ownerId])).rows[0];
      assert.ok(stored.password_hash.startsWith('$argon2id$'));
      const sessions = await db.query('SELECT access_hash FROM sessions WHERE user_id=$1', [ownerId]);
      assert.equal(sessions.rows[0].access_hash, digest(owner.jar.get('sg_access')!));
    });
    await suite.test('strict validation rejects privilege injection and weak passwords', async () => {
      assert.equal((await anonymous.call('/auth/register', 'POST', { name: 'Injected User', email: 'inject@example.test', password: 'long password here', organization: 'Injected Org', role: 'OWNER' })).status, 400);
      assert.equal((await anonymous.call('/auth/register', 'POST', { name: 'Weak User', email: 'weak@example.test', password: 'short', organization: 'Weak Org' })).status, 400);
    });
    await suite.test('CSRF and origin checks protect writes including onboarding', async () => {
      assert.equal((await owner.call('/auth/mfa/setup', 'POST', {}, { 'X-CSRF-Token': 'invalid' })).status, 403);
      assert.equal((await owner.call('/auth/mfa/setup', 'POST', {}, { Origin: 'https://attacker.invalid' })).status, 403);
      ownerCodes = await enrollMfa(owner);
      assert.equal((await owner.call(`/organizations/${organizationId}/overview`)).status, 200);
      const user = (await db.query('SELECT mfa_secret_encrypted,mfa_pending_encrypted FROM users WHERE id=$1', [ownerId])).rows[0];
      assert.ok(user.mfa_secret_encrypted);
      assert.equal(user.mfa_pending_encrypted, null);
      const codes = await db.query('SELECT code_hash FROM mfa_recovery_codes WHERE user_id=$1', [ownerId]);
      assert.ok(codes.rows.every(row => !ownerCodes.includes(row.code_hash)));
    });
    await suite.test('another organization cannot read or mutate tenant data', async () => {
      assert.equal((await other.call('/auth/register', 'POST', { name: 'Other Person', email: 'other@example.test', password: 'Other long password 123!', organization: 'Beta Infrastructure' })).status, 201);
      const me = await other.call('/auth/me');
      otherId = me.data.user.id;
      otherOrganizationId = me.data.organizations[0].id;
      otherCodes = await enrollMfa(other);
      assert.equal((await other.call(`/organizations/${organizationId}/overview`)).status, 404);
      assert.equal((await other.call(`/organizations/${organizationId}/members`)).status, 404);
      assert.equal((await other.call(`/organizations/${organizationId}`, 'PATCH', { name: 'Stolen organization' })).status, 404);
    });
    await suite.test('last owner cannot be demoted or removed', async () => {
      assert.equal((await owner.call(`/organizations/${organizationId}/members/${ownerId}`, 'PATCH', { role: 'VIEWER' })).status, 409);
      assert.equal((await owner.call(`/organizations/${organizationId}/members/${ownerId}`, 'DELETE')).status, 409);
    });
    await suite.test('invitations bind email, are single-use, and confer only the assigned role', async () => {
      const invitation = await owner.call(`/organizations/${organizationId}/invitations`, 'POST', { email: 'other@example.test', role: 'VIEWER' });
      assert.equal(invitation.status, 201);
      assert.equal((await owner.call('/invitations/accept', 'POST', { token: invitation.data.token })).status, 404);
      assert.equal((await other.call('/invitations/accept', 'POST', { token: invitation.data.token })).status, 201);
      assert.equal((await other.call('/invitations/accept', 'POST', { token: invitation.data.token })).status, 404);
      assert.equal((await other.call(`/organizations/${organizationId}/overview`)).status, 200);
      assert.equal((await other.call(`/organizations/${organizationId}`, 'PATCH', { name: 'Viewer update' })).status, 403);
      assert.equal((await other.call(`/organizations/${organizationId}/invitations`, 'POST', { email: 'third@example.test', role: 'ADMIN' })).status, 403);
      assert.equal((await other.call(`/organizations/${organizationId}/members/${otherId}`, 'PATCH', { role: 'OWNER' })).status, 403);
    });
    await suite.test('administrator can edit settings but cannot change ownership', async () => {
      assert.equal((await owner.call(`/organizations/${organizationId}/members/${otherId}`, 'PATCH', { role: 'ADMIN' })).status, 200);
      assert.equal((await other.call(`/organizations/${organizationId}`, 'PATCH', { name: 'Alpha Updated' })).status, 200);
      assert.equal((await other.call(`/organizations/${organizationId}/members/${ownerId}`, 'PATCH', { role: 'VIEWER' })).status, 403);
      assert.equal((await other.call(`/organizations/${organizationId}/invitations`, 'POST', { email: 'third@example.test', role: 'OWNER' })).status, 403);
    });
    await suite.test('a demoted invitation issuer cannot retain delegated access', async () => {
      const invitation = await other.call(`/organizations/${organizationId}/invitations`, 'POST', { email: 'third@example.test', role: 'VIEWER' });
      assert.equal(invitation.status, 201);
      assert.equal((await owner.call(`/organizations/${organizationId}/members/${otherId}`, 'PATCH', { role: 'VIEWER' })).status, 200);
      const third = new Client();
      assert.equal((await third.call('/auth/register', 'POST', { name: 'Third Person', email: 'third@example.test', password: 'Third long password 123!', organization: 'Third Infrastructure' })).status, 201);
      await enrollMfa(third);
      assert.equal((await third.call('/invitations/accept', 'POST', { token: invitation.data.token })).status, 403);
    });
    await suite.test('concurrent ownership changes retain at least one owner', async () => {
      const created = await owner.call('/organizations', 'POST', { name: 'Concurrency Test' });
      const id = created.data.id;
      const invitation = await owner.call(`/organizations/${id}/invitations`, 'POST', { email: 'other@example.test', role: 'OWNER' });
      assert.equal((await other.call('/invitations/accept', 'POST', { token: invitation.data.token })).status, 201);
      const results = await Promise.all([
        owner.call(`/organizations/${id}/members/${ownerId}`, 'PATCH', { role: 'VIEWER' }),
        other.call(`/organizations/${id}/members/${otherId}`, 'PATCH', { role: 'VIEWER' }),
      ]);
      assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
      const owners = await db.query('SELECT count(*)::int AS count FROM memberships WHERE organization_id=$1 AND role=\'OWNER\'', [id]);
      assert.equal(owners.rows[0].count, 1);
    });
    await suite.test('removed members lose access immediately with existing sessions', async () => {
      assert.equal((await owner.call(`/organizations/${organizationId}/members/${otherId}`, 'DELETE')).status, 200);
      assert.equal((await other.call(`/organizations/${organizationId}/overview`)).status, 404);
      assert.equal((await other.call(`/organizations/${otherOrganizationId}/overview`)).status, 200);
    });
    await suite.test('expired and revoked invitations cannot be accepted', async () => {
      const expired = await owner.call(`/organizations/${organizationId}/invitations`, 'POST', { email: 'other@example.test', role: 'VIEWER' });
      await db.query('UPDATE invitations SET expires_at=now()-interval \'1 minute\' WHERE id=$1', [expired.data.id]);
      assert.equal((await other.call('/invitations/accept', 'POST', { token: expired.data.token })).status, 404);
      const revoked = await owner.call(`/organizations/${organizationId}/invitations`, 'POST', { email: 'other@example.test', role: 'VIEWER' });
      assert.equal((await owner.call(`/organizations/${organizationId}/invitations/${revoked.data.id}`, 'DELETE')).status, 200);
      assert.equal((await other.call('/invitations/accept', 'POST', { token: revoked.data.token })).status, 404);
    });
    await suite.test('audit rows reject UPDATE and DELETE at the database boundary', async () => {
      await assert.rejects(db.query('UPDATE audit_logs SET action=\'tampered\' WHERE organization_id=$1', [organizationId]), /append-only/);
      await assert.rejects(db.query('DELETE FROM audit_logs WHERE organization_id=$1', [organizationId]), /append-only/);
    });
    await suite.test('composite foreign keys reject cross-tenant server membership', async () => {
      const serverId = randomUUID();
      const groupId = randomUUID();
      await db.query('INSERT INTO servers (id,organization_id,hostname,os) VALUES ($1,$2,\'test-vm\',\'LINUX\')', [serverId, organizationId]);
      await db.query('INSERT INTO server_groups (id,organization_id,name) VALUES ($1,$2,\'Beta group\')', [groupId, otherOrganizationId]);
      await assert.rejects(db.query('INSERT INTO server_group_members (organization_id,group_id,server_id) VALUES ($1,$2,$3)', [otherOrganizationId, groupId, serverId]), /foreign key/);
    });
    await suite.test('sealed policy content and rules cannot be modified', async () => {
      const policyId = randomUUID();
      const versionId = randomUUID();
      await db.query('INSERT INTO firewall_policies (id,organization_id,name) VALUES ($1,$2,\'Test policy\')', [policyId, organizationId]);
      await db.query('INSERT INTO policy_versions (id,organization_id,policy_id,version,target,created_by) VALUES ($1,$2,$3,1,\'{}\',$4)', [versionId, organizationId, policyId, ownerId]);
      await db.query('UPDATE policy_versions SET sealed_at=now(),checksum=$2,state=\'PENDING_APPROVAL\' WHERE id=$1', [versionId, 'a'.repeat(64)]);
      await assert.rejects(db.query('UPDATE policy_versions SET target=\'{"altered":true}\' WHERE id=$1', [versionId]), /immutable/);
      await assert.rejects(db.query('INSERT INTO firewall_rules (id,organization_id,policy_version_id,cidr,action,direction,protocol,port_start,port_end,reason) VALUES ($1,$2,$3,\'192.0.2.0/24\',\'BLOCK\',\'INBOUND\',\'TCP\',22,22,\'test\')', [randomUUID(), organizationId, versionId]), /immutable/);
    });
    await suite.test('refresh rotates credentials and replay revokes the whole family', async () => {
      const original = new Map(owner.jar);
      assert.equal((await owner.call('/auth/refresh', 'POST', {})).status, 201);
      const newJar = new Map(owner.jar);
      assert.notEqual(original.get('sg_refresh'), newJar.get('sg_refresh'));
      const replay = new Client(); replay.jar = original;
      assert.equal((await replay.call('/auth/refresh', 'POST', {})).status, 401);
      assert.equal((await owner.call('/auth/me')).status, 401);
    });
    await suite.test('MFA recovery codes are single-use and logout revokes access', async () => {
      const login = await owner.call('/auth/login', 'POST', { email: 'owner@example.test', password: 'A long test password 123!', code: ownerCodes[0] });
      assert.equal(login.status, 201);
      assert.equal((await anonymous.call('/auth/login', 'POST', { email: 'owner@example.test', password: 'A long test password 123!', code: ownerCodes[0] })).status, 401);
      const oldCookies = new Map(owner.jar);
      assert.equal((await owner.call('/auth/logout', 'POST', {})).status, 201);
      owner.jar = oldCookies;
      assert.equal((await owner.call('/auth/me')).status, 401);
    });
    await suite.test('disabled accounts cannot use existing sessions', async () => {
      assert.equal((await other.call('/auth/login', 'POST', { email: 'other@example.test', password: 'Other long password 123!', code: otherCodes[0] })).status, 201);
      await db.query('UPDATE users SET disabled_at=now() WHERE id=$1', [otherId]);
      assert.equal((await other.call('/auth/me')).status, 401);
    });
  } finally { await app.close(); await db.close(); }
});
