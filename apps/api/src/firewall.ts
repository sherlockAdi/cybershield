import { ConflictException, Inject, Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Database, Queryable, Row } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';
import { canonical, contentSchema, FirewallRule, nativePlan, packetSchema, PolicyContent, policyChecksum, risks, simulate } from './firewall-model';

const checksum = z.string().regex(/^[a-f0-9]{64}$/);
const writeSchema = contentSchema.safeExtend({ expectedChecksum: checksum });
type StoredVersion = Row & { id: string; state: string; sealed_at: Date | null; checksum: string; target: { type: 'SERVER' | 'GROUP'; id: string; serverIds: string[] }; rules: FirewallRule[] };

@Injectable()
export class FirewallService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}

  private async authorize(client: Queryable, actor: Actor, organizationId: string, write = false) {
    if (write) await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
    await this.control.membership(client, organizationId, actor, write ? ['OWNER', 'ADMIN'] : undefined);
  }
  private async targets(client: Queryable, organizationId: string, target: PolicyContent['target'], allowEmpty = false) {
    if (target.type === 'GROUP' && !(await client.query('SELECT id FROM server_groups WHERE organization_id=$1 AND id=$2', [organizationId, target.id])).rows.length) throw new NotFoundException('Target group not found');
    const records = await client.query(`SELECT id,hostname,os FROM servers WHERE organization_id=$1 AND decommissioned_at IS NULL AND ${target.type === 'SERVER' ? 'id=$2' : 'id IN (SELECT server_id FROM server_group_members WHERE organization_id=$1 AND group_id=$2)'} ORDER BY id LIMIT 101`, [organizationId, target.id]);
    if (!records.rows.length && !allowEmpty) throw new BadRequestException('Target must contain at least one active registered server');
    if (records.rows.length > 100) throw new BadRequestException('Preview target limit is 100 servers');
    return records.rows;
  }
  private validateTimes(content: PolicyContent) {
    if (content.rules.some(rule => rule.expiresAt && Date.parse(rule.expiresAt) < Date.now() + 60000)) throw new BadRequestException('New draft rules must expire at least one minute in the future');
  }
  private async version(client: Queryable, organizationId: string, policyId: string, versionId: string, lock = false): Promise<StoredVersion> {
    const result = await client.query(`SELECT * FROM policy_versions WHERE organization_id=$1 AND policy_id=$2 AND id=$3${lock ? ' FOR UPDATE' : ''}`, [organizationId, input(uuid, policyId), input(uuid, versionId)]);
    if (!result.rows.length) throw new NotFoundException('Policy version not found');
    const version = result.rows[0];
    const rows = await client.query('SELECT id,host(cidr) AS address,masklen(cidr) AS prefix,action,direction,protocol,port_start,port_end,expires_at,reason FROM firewall_rules WHERE organization_id=$1 AND policy_version_id=$2 ORDER BY id', [organizationId, versionId]);
    const rules: FirewallRule[] = rows.rows.map(rule => ({ id: rule.id, cidr: `${rule.address}/${rule.prefix}`, action: rule.action, direction: rule.direction, protocol: rule.protocol, portStart: rule.port_start, portEnd: rule.port_end, expiresAt: rule.expires_at ? new Date(rule.expires_at).toISOString() : null, reason: rule.reason }));
    return { ...version, rules } as StoredVersion;
  }
  private async persist(client: Queryable, organizationId: string, versionId: string, content: PolicyContent, servers: Row[]) {
    if ((await client.query('SELECT id FROM firewall_rules WHERE id=ANY($1::uuid[]) AND policy_version_id<>$2 LIMIT 1', [content.rules.map(rule => rule.id), versionId])).rows.length) throw new ConflictException('Rule IDs must be new to this version');
    await client.query('DELETE FROM firewall_rules WHERE organization_id=$1 AND policy_version_id=$2', [organizationId, versionId]);
    for (const rule of content.rules) await client.query('INSERT INTO firewall_rules (id,organization_id,policy_version_id,cidr,action,direction,protocol,port_start,port_end,expires_at,reason) VALUES ($1,$2,$3,$4::inet,$5,$6,$7,$8,$9,$10,$11)', [rule.id, organizationId, versionId, rule.cidr, rule.action, rule.direction, rule.protocol, rule.portStart, rule.portEnd, rule.expiresAt ? new Date(rule.expiresAt) : null, rule.reason]);
    const serverIds = servers.map(server => server.id);
    const hash = policyChecksum(content, serverIds);
    await client.query('UPDATE policy_versions SET target=$3::jsonb,checksum=$4 WHERE organization_id=$1 AND id=$2', [organizationId, versionId, JSON.stringify({ ...content.target, serverIds }), hash]);
    return hash;
  }
  async list(actor: Actor, organizationId: string, query: unknown) {
    const filter = input(z.object({ cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(30) }).strict(), query);
    await this.authorize(this.db, actor, organizationId);
    let anchor: Row | undefined;
    if (filter.cursor) {
      anchor = (await this.db.query('SELECT id,created_at FROM firewall_policies WHERE organization_id=$1 AND id=$2', [organizationId, filter.cursor])).rows[0];
      if (!anchor) throw new BadRequestException('Invalid policy cursor');
    }
    const rows = (await this.db.query(`SELECT firewall_policies.*,latest.id AS version_id,latest.version,latest.state,latest.checksum FROM firewall_policies LEFT JOIN LATERAL (SELECT id,version,state,checksum FROM policy_versions WHERE organization_id=firewall_policies.organization_id AND policy_id=firewall_policies.id ORDER BY version DESC LIMIT 1) latest ON true WHERE firewall_policies.organization_id=$1 AND ($2::timestamptz IS NULL OR (firewall_policies.created_at,firewall_policies.id)<($2::timestamptz,$3::uuid)) ORDER BY firewall_policies.created_at DESC,firewall_policies.id DESC LIMIT $4`, [organizationId, anchor?.created_at || null, anchor?.id || null, filter.limit + 1])).rows;
    return { items: rows.slice(0, filter.limit), nextCursor: rows.length > filter.limit ? rows[filter.limit - 1].id : null };
  }
  async create(actor: Actor, organizationId: string, body: unknown) {
    const data = input(contentSchema.safeExtend({ name: z.string().trim().min(2).max(120) }), body);
    this.validateTimes(data);
    return this.db.transaction(async client => {
      await this.authorize(client, actor, organizationId, true);
      const servers = await this.targets(client, organizationId, data.target);
      const policyId = randomUUID(); const versionId = randomUUID();
      await client.query('INSERT INTO firewall_policies (id,organization_id,name) VALUES ($1,$2,$3)', [policyId, organizationId, data.name]);
      await client.query('INSERT INTO policy_versions (id,organization_id,policy_id,version,target,created_by) VALUES ($1,$2,$3,1,$4::jsonb,$5)', [versionId, organizationId, policyId, JSON.stringify(data.target), actor.id]);
      const hash = await this.persist(client, organizationId, versionId, data, servers);
      await this.control.audit(client, organizationId, actor.id, 'firewall.draft_created', policyId, { versionId, checksum: hash, ruleCount: data.rules.length });
      return { policyId, versionId, checksum: hash };
    });
  }
  async detail(actor: Actor, organizationId: string, policyId: string, versionId?: string) {
    await this.authorize(this.db, actor, organizationId);
    const policy = (await this.db.query('SELECT * FROM firewall_policies WHERE organization_id=$1 AND id=$2', [organizationId, input(uuid, policyId)])).rows[0];
    if (!policy) throw new NotFoundException('Policy not found');
    const versions = (await this.db.query('SELECT id,version,state,checksum,created_at,sealed_at FROM policy_versions WHERE organization_id=$1 AND policy_id=$2 ORDER BY version DESC LIMIT 100', [organizationId, policyId])).rows;
    return { policy, versions, selected: await this.version(this.db, organizationId, policyId, versionId || versions[0].id) };
  }
  async save(actor: Actor, organizationId: string, policyId: string, versionId: string, body: unknown) {
    const data = input(writeSchema, body); this.validateTimes(data);
    return this.db.transaction(async client => {
      await this.authorize(client, actor, organizationId, true);
      const version = await this.version(client, organizationId, policyId, versionId, true);
      if (version.state !== 'DRAFT' || version.sealed_at || version.checksum !== data.expectedChecksum) throw new ConflictException('Draft changed or is sealed; reload before editing');
      const servers = await this.targets(client, organizationId, data.target);
      const hash = await this.persist(client, organizationId, versionId, data, servers);
      await this.control.audit(client, organizationId, actor.id, 'firewall.draft_updated', policyId, { versionId, previousChecksum: version.checksum, checksum: hash, ruleCount: data.rules.length });
      return { policyId, versionId, checksum: hash };
    });
  }
  async revise(actor: Actor, organizationId: string, policyId: string, sourceId: string) {
    return this.db.transaction(async client => {
      await this.authorize(client, actor, organizationId, true);
      const source = await this.version(client, organizationId, policyId, sourceId, true);
      const content = input(contentSchema, { target: { type: source.target.type, id: source.target.id }, rules: source.rules.map(rule => ({ ...rule, id: randomUUID() })) });
      const servers = await this.targets(client, organizationId, content.target);
      const versionId = randomUUID();
      const next = (await client.query('SELECT COALESCE(max(version),0)+1 AS version FROM policy_versions WHERE organization_id=$1 AND policy_id=$2', [organizationId, policyId])).rows[0].version;
      await client.query('INSERT INTO policy_versions (id,organization_id,policy_id,version,target,created_by) VALUES ($1,$2,$3,$4,$5::jsonb,$6)', [versionId, organizationId, policyId, next, JSON.stringify(content.target), actor.id]);
      const hash = await this.persist(client, organizationId, versionId, content, servers);
      await this.control.audit(client, organizationId, actor.id, 'firewall.draft_revised', policyId, { versionId, sourceVersionId: sourceId, checksum: hash });
      return { policyId, versionId, checksum: hash };
    });
  }
  async preview(actor: Actor, organizationId: string, policyId: string, versionId: string, body: unknown) {
    const data = input(z.object({ expectedChecksum: checksum, packet: packetSchema.optional(), compareVersionId: uuid.optional() }).strict(), body);
    return this.db.transaction(async client => {
      await this.authorize(client, actor, organizationId);
      const version = await this.version(client, organizationId, policyId, versionId, true);
      if (version.checksum !== data.expectedChecksum) throw new ConflictException('Version changed; reload before preview');
      const content = input(contentSchema, { target: { type: version.target.type, id: version.target.id }, rules: version.rules });
      const servers = await this.targets(client, organizationId, content.target, true);
      const snapshotTargets = (await client.query('SELECT id,hostname,os,decommissioned_at FROM servers WHERE organization_id=$1 AND id=ANY($2::uuid[]) ORDER BY id', [organizationId, version.target.serverIds])).rows;
      const targetDrift = canonical(servers.map(server => server.id)) !== canonical(version.target.serverIds);
      const classification = risks(content.rules, version.target.serverIds.length);
      let comparison: unknown = null;
      if (data.compareVersionId) {
        const previous = await this.version(client, organizationId, policyId, data.compareVersionId);
        const signatures = (rules: FirewallRule[]) => new Set(rules.map(({ id, ...rule }) => canonical(rule)));
        const before = signatures(previous.rules); const after = signatures(content.rules);
        comparison = { previousVersionId: previous.id, added: [...after].filter(rule => !before.has(rule)).map(rule => JSON.parse(rule)), removed: [...before].filter(rule => !after.has(rule)).map(rule => JSON.parse(rule)), targetChanged: canonical(previous.target) !== canonical(version.target) };
      }
      const plans = [...new Set(snapshotTargets.map(server => server.os))].map(os => nativePlan(versionId, os, content.rules));
      await this.control.audit(client, organizationId, actor.id, 'firewall.previewed', policyId, { versionId, checksum: version.checksum, targetDrift, highImpact: classification.highImpact });
      return { versionId, checksum: version.checksum, generatedAt: new Date().toISOString(), applyEnabled: false, targetDrift, snapshotServerIds: version.target.serverIds, snapshotTargets, currentTargets: servers, classification, plans, expiredRuleIds: content.rules.filter(rule => rule.expiresAt && Date.parse(rule.expiresAt) <= Date.now()).map(rule => rule.id), packet: data.packet ? simulate(content.rules, data.packet) : null, comparison };
    });
  }
  async submit(actor: Actor, organizationId: string, policyId: string, versionId: string, body: unknown) {
    const data = input(z.object({ expectedChecksum: checksum }).strict(), body);
    return this.db.transaction(async client => {
      await this.authorize(client, actor, organizationId, true);
      const version = await this.version(client, organizationId, policyId, versionId, true);
      if (version.state !== 'DRAFT' || version.sealed_at || version.checksum !== data.expectedChecksum) throw new ConflictException('Draft changed or is sealed');
      const content = input(contentSchema, { target: { type: version.target.type, id: version.target.id }, rules: version.rules });
      this.validateTimes(content);
      const servers = await this.targets(client, organizationId, content.target);
      if (policyChecksum(content, servers.map(server => server.id)) !== version.checksum) throw new ConflictException('Target membership changed; save and preview the draft again');
      const classification = risks(content.rules, servers.length);
      if (classification.blockers.length) throw new BadRequestException(classification.blockers.join('; '));
      await client.query("UPDATE policy_versions SET state='PENDING_APPROVAL',sealed_at=now() WHERE organization_id=$1 AND id=$2", [organizationId, versionId]);
      await this.control.audit(client, organizationId, actor.id, 'firewall.submitted', policyId, { versionId, checksum: version.checksum, targetCount: servers.length, ...classification });
      return { versionId, state: 'PENDING_APPROVAL', checksum: version.checksum, applyEnabled: false };
    });
  }
  async history(actor: Actor, organizationId: string, policyId: string, query: unknown) {
    await this.authorize(this.db, actor, organizationId);
    if (!(await this.db.query('SELECT id FROM firewall_policies WHERE organization_id=$1 AND id=$2', [organizationId, input(uuid, policyId)])).rows.length) throw new NotFoundException('Policy not found');
    const data = input(z.object({ cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(30) }).strict(), query);
    let anchor: Row | undefined;
    if (data.cursor) {
      anchor = (await this.db.query("SELECT id,created_at FROM audit_logs WHERE organization_id=$1 AND resource_id=$2 AND action LIKE 'firewall.%' AND id=$3", [organizationId, policyId, data.cursor])).rows[0];
      if (!anchor) throw new BadRequestException('Invalid history cursor');
    }
    const rows = (await this.db.query("SELECT audit_logs.id,action,metadata,audit_logs.created_at,users.name AS actor_name FROM audit_logs LEFT JOIN users ON users.id=audit_logs.actor_id WHERE organization_id=$1 AND resource_id=$2 AND action LIKE 'firewall.%' AND ($3::timestamptz IS NULL OR (audit_logs.created_at,audit_logs.id)<($3::timestamptz,$4::uuid)) ORDER BY audit_logs.created_at DESC,audit_logs.id DESC LIMIT $5", [organizationId, policyId, anchor?.created_at || null, anchor?.id || null, data.limit + 1])).rows;
    return { items: rows.slice(0, data.limit), nextCursor: rows.length > data.limit ? rows[data.limit - 1].id : null };
  }
}
