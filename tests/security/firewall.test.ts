import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApp } from '../../apps/api/src/app';
import { Database } from '../../apps/api/src/database';
import { totp } from '../../apps/api/src/security';
import { canonical, contentSchema, nativePlan, network, packetSchema, policyChecksum, risks, ruleSchema, simulate, type FirewallRule } from '../../apps/api/src/firewall-model';

const rule = (patch: Partial<FirewallRule> = {}): FirewallRule => ({ id: randomUUID(), action: 'BLOCK', direction: 'INBOUND', cidr: '192.0.2.0/24', protocol: 'TCP', portStart: 8080, portEnd: 8080, expiresAt: null, reason: 'Block test application', ...patch });

test('network parser validates IPv4/IPv6 boundary networks and canonicalizes safe hosts', () => {
  for (const [source, expected] of [['192.0.2.1', '192.0.2.1/32'], ['0.0.0.0/0', '0.0.0.0/0'], ['2001:0DB8::/32', '2001:db8::/32'], ['::/0', '::/0'], ['::1', '::1/128']]) assert.equal(network(source).cidr, expected);
  for (const invalid of ['192.0.2.1/24', '10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/00', '01.2.3.4', 'example.com', '2001:db8::1/64', '::/129', 'fe80::%eth0', '::ffff:192.0.2.1', '::ffff:c000:201', '1.2.3.4/32/32', '1.2.3.4;flush ruleset', '2001:::1']) assert.throws(() => network(invalid), undefined, invalid);
});

test('strict rule combinations, duplicate IDs, timestamps and injection are rejected', () => {
  assert.equal(ruleSchema.parse(rule({ cidr: '192.0.2.1' })).cidr, '192.0.2.1/32');
  for (const invalid of [rule({ portStart: 0 }), rule({ portEnd: 65536 }), rule({ portStart: 8081 }), rule({ protocol: 'ICMP' }), rule({ portStart: null }), { ...rule(), command: 'arbitrary' }, rule({ expiresAt: 'tomorrow' }), rule({ reason: '' })]) assert.equal(ruleSchema.safeParse(invalid).success, false);
  assert.equal(ruleSchema.safeParse(rule({ protocol: 'ICMP', portStart: null, portEnd: null, cidr: '2001:db8::/64' })).success, true);
  const duplicate = rule(); assert.equal(contentSchema.safeParse({ target: { type: 'SERVER', id: randomUUID() }, rules: [duplicate, duplicate] }).success, false);
  assert.equal(packetSchema.safeParse({ address: 'example.com', direction: 'INBOUND', protocol: 'ICMP', port: null }).success, false);
  for (const address of ['::ffff:c000:201', '192.0.2.0/24', 'fe80::1%zone']) assert.equal(packetSchema.safeParse({ address, direction: 'INBOUND', protocol: 'ICMP', port: null }).success, false);
});

test('canonical checksums are order-independent and bind targets and exact content', () => {
  assert.equal(canonical({ z: 2, a: { y: 'string', b: null } }), '{"a":{"b":null,"y":"string"},"z":2}');
  const content = { target: { type: 'SERVER' as const, id: randomUUID() }, rules: [rule(), rule()] };
  const servers = [randomUUID(), randomUUID()];
  const hash = policyChecksum(content, servers);
  assert.equal(hash, policyChecksum({ ...content, rules: [...content.rules].reverse() }, [...servers].reverse()));
  assert.notEqual(hash, policyChecksum(content, [servers[0]]));
  assert.notEqual(hash, policyChecksum({ ...content, rules: content.rules.map(item => ({ ...item, reason: 'Changed reason' })) }, servers));
});

test('packet simulation honors BLOCK precedence, expiry, IPv6 and destination ports', () => {
  const rules = [rule({ action: 'ALLOW', cidr: '0.0.0.0/0' }), rule(), rule({ expiresAt: new Date(0).toISOString(), portStart: 443, portEnd: 443 }), rule({ cidr: '2001:db8::/64', protocol: 'ICMP', portStart: null, portEnd: null })];
  const packet = { address: '192.0.2.5', direction: 'INBOUND' as const, protocol: 'TCP' as const, port: 8080 };
  assert.equal(simulate(rules, packet).managedVerdict, 'BLOCK');
  assert.equal(simulate([...rules].reverse(), packet).managedVerdict, 'BLOCK');
  assert.equal(simulate(rules, { ...packet, address: '198.51.100.2' }).managedVerdict, 'ALLOW');
  assert.equal(simulate(rules, { ...packet, port: 443 }).managedVerdict, 'NO_MATCH');
  assert.equal(simulate(rules, { ...packet, direction: 'OUTBOUND' }).managedVerdict, 'NO_MATCH');
  assert.equal(simulate(rules, { address: '2001:db8::123', direction: 'INBOUND', protocol: 'ICMP', port: null }).managedVerdict, 'BLOCK');
});

test('native plan adapters preserve scope, compile precedence/IPv6 and never enable execution', () => {
  const id = randomUUID();
  const rules = [rule({ action: 'ALLOW' }), rule(), rule({ direction: 'OUTBOUND', cidr: '2001:db8::/64', protocol: 'ICMP', portStart: null, portEnd: null }), rule({ reason: '"; Remove-NetFirewallRule -All; #', portStart: 5000, portEnd: 5020 }), rule({ expiresAt: new Date(0).toISOString(), portStart: 99, portEnd: 99 })];
  const linux = nativePlan(id, 'LINUX', rules);
  assert.equal(linux.executable, false); assert.equal(linux.status, 'UNVERIFIED');
  assert.match(linux.artifact!, /ip6 daddr 2001:db8::\/64 meta l4proto ipv6-icmp drop/);
  assert.match(linux.artifact!, /tcp dport 5000-5020 drop/);
  assert.ok(linux.artifact!.indexOf('tcp dport 8080 drop') < linux.artifact!.indexOf('tcp dport 8080 accept'));
  assert.doesNotMatch(linux.artifact!, /flush|Remove-NetFirewallRule|dport 99/);
  const windows = nativePlan(id, 'WINDOWS', rules);
  assert.equal(windows.executable, false);
  const commands = windows.commands!;
  assert.equal(commands.find(command => command.parameters.Protocol === 'ICMPv6')?.parameters.RemoteAddress, '2001:db8::/64');
  const outbound = nativePlan(id, 'WINDOWS', [rule({ direction: 'OUTBOUND' })]).commands![0];
  assert.equal(outbound.parameters.RemotePort, '8080'); assert.equal(outbound.parameters.LocalPort, undefined);
  assert.ok(commands.every(command => command.parameters.Group === windows.namespace));
  assert.ok(risks([rule({ portStart: 22, portEnd: 22 })], 1).blockers.length);
  assert.ok(risks([rule({ direction: 'OUTBOUND' })], 1).blockers.length);
  assert.equal(risks([rule()], 6).highImpact, true);
});

test('Week 5 firewall API acceptance', async suite => {
  const db = await new Database().open(true); const { app } = await createApp(db); await app.listen(0, '127.0.0.1'); const base = await app.getUrl();
  class Browser {
    cookies = new Map<string, string>();
    async call(endpoint: string, method = 'GET', value?: unknown, csrf = true) {
      const response = await fetch(`${base}/api${endpoint}`, { method, headers: { Origin: 'http://127.0.0.1:3100', 'Content-Type': 'application/json', Cookie: [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '), 'X-CSRF-Token': csrf ? this.cookies.get('sg_csrf') || '' : 'wrong' }, body: value === undefined ? undefined : JSON.stringify(value) });
      for (const cookie of response.headers.getSetCookie()) { const [name, value] = cookie.split(';')[0].split('='); this.cookies.set(name, value); }
      return { status: response.status, data: await response.json() as any };
    }
  }
  async function account(email: string) {
    const client = new Browser(); assert.equal((await client.call('/auth/register', 'POST', { name: 'Firewall Tester', email, password: 'A long firewall testing password!', organization: 'Firewall Test' })).status, 201);
    const setup = await client.call('/auth/mfa/setup', 'POST', {}); assert.equal((await client.call('/auth/mfa/confirm', 'POST', { code: totp(setup.data.secret) })).status, 201);
    const me = (await client.call('/auth/me')).data; return { client, org: me.organizations[0].id as string, id: me.user.id as string };
  }
  const owner = await account('firewall-owner@example.test'); const outsider = await account('firewall-outsider@example.test');
  const root = `/organizations/${owner.org}`; const path = `${root}/firewall/policies`;
  const linux = (await owner.client.call(`${root}/servers`, 'POST', { hostname: 'firewall-linux', os: 'LINUX' })).data.serverId;
  const windows = (await owner.client.call(`${root}/servers`, 'POST', { hostname: 'firewall-windows', os: 'WINDOWS' })).data.serverId;
  const foreignServer = (await outsider.client.call(`/organizations/${outsider.org}/servers`, 'POST', { hostname: 'foreign', os: 'LINUX' })).data.serverId;
  const content = () => ({ target: { type: 'SERVER', id: linux }, rules: [rule()] });
  let draft: any; let saved: any;
  const versionPath = () => `${path}/${draft.policyId}/versions/${draft.versionId}`;
  try {
    await suite.test('draft creation is validated, tenant bound, role protected and CSRF protected', async () => {
      const initial = content();
      assert.equal((await owner.client.call(path, 'POST', { ...initial, name: 'Blocked by CSRF' }, false)).status, 403);
      assert.equal((await owner.client.call(path, 'POST', { ...initial, target: { type: 'SERVER', id: foreignServer }, name: 'Wrong target' })).status, 400);
      assert.equal((await owner.client.call(path, 'POST', { ...initial, rules: [rule({ cidr: '192.0.2.1/24' })], name: 'Invalid CIDR' })).status, 400);
      assert.equal((await owner.client.call(path, 'POST', { ...initial, rules: [rule({ expiresAt: new Date(0).toISOString() })], name: 'Expired rule' })).status, 400);
      const created = await owner.client.call(path, 'POST', { ...initial, name: 'Web protection' }); assert.equal(created.status, 201); draft = created.data; saved = initial;
      assert.match(draft.checksum, /^[a-f0-9]{64}$/);
      assert.equal((await outsider.client.call(path)).status, 404);
      assert.equal((await outsider.client.call(`${path}/${draft.policyId}`)).status, 404);
    });
    await suite.test('detail round trips canonical CIDRs, normalized timestamps and upper-case UUIDs', async () => {
      const future = new Date(Date.now() + 3600000).toISOString().replace('.000Z', 'Z');
      const body = { name: 'Normalized', target: { type: 'SERVER', id: linux.toUpperCase() }, rules: [rule({ id: randomUUID().toUpperCase(), cidr: '2001:0DB8::/64', expiresAt: future })] };
      const created = await owner.client.call(path, 'POST', body); assert.equal(created.status, 201);
      const detail = (await owner.client.call(`${path}/${created.data.policyId}`)).data.selected;
      assert.equal(detail.rules[0].cidr, '2001:db8::/64');
      assert.equal((await owner.client.call(`${path}/${created.data.policyId}/versions/${created.data.versionId}/submit`, 'POST', { expectedChecksum: created.data.checksum })).status, 201);
    });
    await suite.test('saved-content previews produce native artifacts, packet verdict and audit without mutation', async () => {
      const result = await owner.client.call(`${versionPath()}/preview`, 'POST', { expectedChecksum: draft.checksum, packet: { address: '192.0.2.10', direction: 'INBOUND', protocol: 'TCP', port: 8080 } });
      assert.equal(result.status, 201); assert.equal(result.data.applyEnabled, false); assert.equal(result.data.packet.managedVerdict, 'BLOCK'); assert.equal(result.data.plans[0].adapter, 'nftables');
      assert.equal((await owner.client.call(`${versionPath()}/preview`, 'POST', { expectedChecksum: draft.checksum, packet: { address: '::ffff:c000:201', direction: 'INBOUND', protocol: 'TCP', port: 8080 } })).status, 400);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM agent_jobs')).rows[0].count, 0);
      const events = await owner.client.call(`${path}/${draft.policyId}/history`); assert.equal(events.status, 200); assert.ok(events.data.items.some((event: any) => event.action === 'firewall.previewed'));
    });
    await suite.test('draft optimistic concurrency rejects stale writes, duplicate IDs and injected fields', async () => {
      saved = { ...saved, rules: [rule({ portStart: 8443, portEnd: 8443 })] };
      const previous = draft.checksum;
      const updated = await owner.client.call(versionPath(), 'PATCH', { ...saved, expectedChecksum: previous }); assert.equal(updated.status, 200); draft.checksum = updated.data.checksum;
      assert.equal((await owner.client.call(versionPath(), 'PATCH', { ...saved, expectedChecksum: previous })).status, 409);
      assert.equal((await owner.client.call(`${versionPath()}/preview`, 'POST', { expectedChecksum: previous })).status, 409);
      assert.equal((await owner.client.call(versionPath(), 'PATCH', { ...saved, expectedChecksum: draft.checksum, state: 'APPROVED' })).status, 400);
      assert.equal((await owner.client.call(versionPath(), 'PATCH', { ...saved, rules: [saved.rules[0], saved.rules[0]], expectedChecksum: draft.checksum })).status, 400);
      assert.equal((await owner.client.call(path, 'POST', { ...saved, name: 'ID collision' })).status, 409);
    });
    await suite.test('submission seals exact content and blocks subsequent edits at API and database', async () => {
      const result = await owner.client.call(`${versionPath()}/submit`, 'POST', { expectedChecksum: draft.checksum }); assert.equal(result.status, 201); assert.equal(result.data.state, 'PENDING_APPROVAL'); assert.equal(result.data.applyEnabled, false);
      assert.equal((await owner.client.call(versionPath(), 'PATCH', { ...saved, expectedChecksum: draft.checksum })).status, 409);
      assert.equal((await owner.client.call(`${versionPath()}/submit`, 'POST', { expectedChecksum: draft.checksum })).status, 409);
      await assert.rejects(db.query('UPDATE firewall_rules SET reason=$2 WHERE policy_version_id=$1', [draft.versionId, 'tampered']), /immutable/);
      await assert.rejects(db.query('UPDATE policy_versions SET target=$2::jsonb WHERE id=$1', [draft.versionId, '{}']), /immutable/);
    });
    await suite.test('revision leaves sealed history intact and preview compares semantic rule content', async () => {
      const revised = await owner.client.call(`${versionPath()}/revise`, 'POST', {}); assert.equal(revised.status, 201);
      const original = draft; draft = revised.data;
      const result = await owner.client.call(`${versionPath()}/preview`, 'POST', { expectedChecksum: draft.checksum, compareVersionId: original.versionId });
      assert.equal(result.status, 201); assert.deepEqual(result.data.comparison.added, []); assert.deepEqual(result.data.comparison.removed, []);
      const details = await owner.client.call(`${path}/${draft.policyId}`); assert.equal(details.data.versions[0].version, 2); assert.equal(details.data.versions[1].state, 'PENDING_APPROVAL');
    });
    await suite.test('management and control-plane-risk blocks cannot be submitted', async () => {
      for (const blocked of [rule({ portStart: 22, portEnd: 22 }), rule({ portStart: 3389, portEnd: 3389 }), rule({ direction: 'OUTBOUND', portStart: 443, portEnd: 443 })]) {
        const created = (await owner.client.call(path, 'POST', { ...content(), name: 'Unsafe protection', rules: [blocked] })).data;
        const endpoint = `${path}/${created.policyId}/versions/${created.versionId}`;
        const preview = await owner.client.call(`${endpoint}/preview`, 'POST', { expectedChecksum: created.checksum }); assert.equal(preview.data.classification.highImpact, true); assert.ok(preview.data.classification.blockers.length);
        assert.equal((await owner.client.call(`${endpoint}/submit`, 'POST', { expectedChecksum: created.checksum })).status, 400);
      }
    });
    await suite.test('group membership drift is visible and must be re-snapshotted before sealing', async () => {
      const group = (await owner.client.call(`${root}/groups`, 'POST', { name: 'Firewall cohort' })).data.id;
      await owner.client.call(`${root}/servers/${linux}/metadata`, 'PATCH', { labels: {}, groupIds: [group] });
      const body = { name: 'Group rules', target: { type: 'GROUP', id: group }, rules: [rule()] };
      const created = (await owner.client.call(path, 'POST', body)).data;
      const endpoint = `${path}/${created.policyId}/versions/${created.versionId}`;
      await owner.client.call(`${root}/servers/${windows}/metadata`, 'PATCH', { labels: {}, groupIds: [group] });
      const preview = await owner.client.call(`${endpoint}/preview`, 'POST', { expectedChecksum: created.checksum }); assert.equal(preview.data.targetDrift, true); assert.equal(preview.data.plans.length, 1); assert.equal(preview.data.snapshotTargets.length, 1); assert.equal(preview.data.currentTargets.length, 2);
      assert.equal((await owner.client.call(`${endpoint}/submit`, 'POST', { expectedChecksum: created.checksum })).status, 409);
      const updated = (await owner.client.call(endpoint, 'PATCH', { target: body.target, rules: body.rules, expectedChecksum: created.checksum })).data;
      assert.equal((await owner.client.call(`${endpoint}/submit`, 'POST', { expectedChecksum: updated.checksum })).status, 201);
      const selected = (await owner.client.call(`${path}/${created.policyId}`)).data.selected; assert.equal(selected.target.serverIds.length, 2);
      await owner.client.call(`${root}/servers/${windows}/metadata`, 'PATCH', { labels: {}, groupIds: [] });
      assert.equal((await owner.client.call(`${path}/${created.policyId}`)).data.selected.target.serverIds.length, 2);
      const sealedPreview = await owner.client.call(`${endpoint}/preview`, 'POST', { expectedChecksum: updated.checksum });
      assert.equal(sealedPreview.data.snapshotTargets.length, 2); assert.equal(sealedPreview.data.currentTargets.length, 1); assert.equal(sealedPreview.data.plans.length, 2);
      await owner.client.call(`${root}/servers/${linux}/metadata`, 'PATCH', { labels: {}, groupIds: [] });
      const emptyPreview = await owner.client.call(`${endpoint}/preview`, 'POST', { expectedChecksum: updated.checksum });
      assert.equal(emptyPreview.status, 201); assert.equal(emptyPreview.data.currentTargets.length, 0); assert.equal(emptyPreview.data.snapshotTargets.length, 2);
    });
    await suite.test('viewer can inspect but cannot create, edit, revise or submit', async () => {
      await db.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'VIEWER')", [owner.org, outsider.id]);
      assert.equal((await outsider.client.call(`${path}/${draft.policyId}`)).status, 200);
      assert.equal((await outsider.client.call(`${versionPath()}/preview`, 'POST', { expectedChecksum: draft.checksum })).status, 201);
      assert.equal((await outsider.client.call(path, 'POST', { ...content(), name: 'Viewer draft' })).status, 403);
      assert.equal((await outsider.client.call(versionPath(), 'PATCH', { ...content(), expectedChecksum: draft.checksum })).status, 403);
      assert.equal((await outsider.client.call(`${versionPath()}/revise`, 'POST', {})).status, 403);
      assert.equal((await outsider.client.call(`${versionPath()}/submit`, 'POST', { expectedChecksum: draft.checksum })).status, 403);
    });
    await suite.test('policy and append-only audit cursors paginate and reject foreign anchors', async () => {
      const first = (await owner.client.call(`${path}?limit=1`)).data; assert.ok(first.nextCursor);
      const next = (await owner.client.call(`${path}?limit=1&cursor=${first.nextCursor}`)).data; assert.notEqual(first.items[0].id, next.items[0].id);
      assert.equal((await owner.client.call(`${path}?cursor=${randomUUID()}`)).status, 400);
      const events = (await owner.client.call(`${path}/${draft.policyId}/history?limit=1`)).data; assert.ok(events.nextCursor);
      const older = (await owner.client.call(`${path}/${draft.policyId}/history?limit=1&cursor=${events.nextCursor}`)).data; assert.notEqual(events.items[0].id, older.items[0].id);
      assert.equal((await owner.client.call(`${path}/${draft.policyId}/history?cursor=${randomUUID()}`)).status, 400);
      await assert.rejects(db.query('DELETE FROM audit_logs WHERE id=$1', [events.items[0].id]), /append.only|immutable/i);
      assert.equal((await owner.client.call(`${versionPath()}/apply`, 'POST', {})).status, 404);
      assert.equal((await db.query('SELECT count(*)::int AS count FROM policy_deployments')).rows[0].count, 0);
    });
  } finally { await app.close(); await db.close(); }
});
