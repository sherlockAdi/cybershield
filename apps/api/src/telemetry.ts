import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Database, Queryable, Row } from './database';
import { AgentRequest, AgentService, agentStatus } from './agents';
import { Actor, ControlService } from './service';
import { input, name, uuid } from './input';
import { eventHash, eventKinds, eventSchema, healthSummary, severities } from './telemetry-model';
import { detectEvent } from './detection-model';

const querySchema = z.object({ q: z.string().trim().max(100).optional(), os: z.enum(['LINUX', 'WINDOWS']).optional(), status: z.enum(['ONLINE', 'STALE', 'UNKNOWN', 'PENDING_ENROLLMENT', 'AWAITING_HEARTBEAT', 'REVOKED_OR_EXPIRED', 'DECOMMISSIONED']).optional(), groupId: uuid.optional(), cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(50) }).strict();
const eventsQuerySchema = z.object({ serverId: uuid.optional(), severity: z.enum(severities).optional(), kind: z.enum(eventKinds).optional(), hours: z.coerce.number().int().min(1).max(720).default(24), cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(50) }).strict();
const batchSchema = z.object({ schemaVersion: z.literal(1), serverId: uuid, credentialId: uuid, sequence: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER), events: z.array(eventSchema).min(1).max(100) }).strict();

@Injectable()
export class TelemetryService {
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService, @Inject(AgentService) private readonly agents: AgentService) {}

  async ingest(request: AgentRequest) {
    const data = input(batchSchema, request.body);
    const now = Date.now();
    for (const event of data.events) if (Date.parse(event.occurredAt) > now + 5 * 60000 || Date.parse(event.occurredAt) < now - 30 * 86400000) throw new BadRequestException('Events must be within retention and clock-skew limits');
    return this.db.transaction(async client => {
      const { server } = await this.agents.authorizeReport(client, request, data, '/api/agent/v1/events');
      let acceptedCount = 0;
      let duplicateCount = 0;
      for (const item of data.events) {
        const event = { ...item, occurredAt: new Date(item.occurredAt).toISOString() };
        const hash = eventHash(event);
        const previous = await client.query('SELECT event_hash FROM security_events WHERE organization_id=$1 AND server_id=$2 AND source_event_id=$3', [server.organization_id, data.serverId, event.sourceEventId]);
        if (previous.rows.length) {
          if (previous.rows[0].event_hash !== hash) throw new ConflictException('Source event ID was reused with different content');
          duplicateCount++; continue;
        }
        const eventId = randomUUID();
        await client.query('INSERT INTO security_events (id,organization_id,server_id,source_event_id,kind,severity,occurred_at,payload,event_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)', [eventId, server.organization_id, data.serverId, event.sourceEventId, event.kind, event.severity, new Date(event.occurredAt), JSON.stringify(event.payload), hash]);
        await detectEvent(client, server.organization_id, data.serverId, eventId, event);
        acceptedCount++;
      }
      await client.query('UPDATE agent_credentials SET last_sequence=$2 WHERE id=$1', [data.credentialId, data.sequence]);
      return { accepted: true, serverId: data.serverId, acceptedSequence: data.sequence, acceptedCount, duplicateCount };
    });
  }

  private async serverAccess(client: Queryable, actor: Actor, organizationId: string, serverId: string) {
    await this.control.membership(client, organizationId, actor);
    const server = await client.query('SELECT id FROM servers WHERE organization_id=$1 AND id=$2', [organizationId, input(uuid, serverId)]);
    if (!server.rows.length) throw new NotFoundException('Server not found');
  }

  async inventory(actor: Actor, organizationId: string, query: unknown) {
    const filter = input(querySchema, query);
    await this.control.membership(this.db, organizationId, actor);
    let anchor: Row | undefined;
    if (filter.cursor) {
      anchor = (await this.db.query('SELECT id,created_at FROM servers WHERE organization_id=$1 AND id=$2', [organizationId, filter.cursor])).rows[0];
      if (!anchor) throw new BadRequestException('Invalid inventory cursor');
    }
    const result = await this.db.query(`SELECT servers.*,active.id AS credential_id,active.expires_at AS credential_expires_at,
      EXISTS(SELECT 1 FROM agent_credentials history WHERE history.organization_id=servers.organization_id AND history.server_id=servers.id) AS had_credentials,
      (SELECT row_to_json(sample) FROM (SELECT * FROM metric_samples WHERE organization_id=servers.organization_id AND server_id=servers.id AND credential_id=active.id ORDER BY received_at DESC,id DESC LIMIT 1) sample) AS latest_metrics,
      COALESCE((SELECT json_agg(json_build_object('id',server_groups.id,'name',server_groups.name) ORDER BY server_groups.name) FROM server_group_members JOIN server_groups ON server_groups.organization_id=server_group_members.organization_id AND server_groups.id=server_group_members.group_id WHERE server_group_members.organization_id=servers.organization_id AND server_group_members.server_id=servers.id),'[]'::json) AS groups
      FROM servers LEFT JOIN LATERAL (SELECT id,expires_at FROM agent_credentials WHERE organization_id=servers.organization_id AND server_id=servers.id AND revoked_at IS NULL AND expires_at>now() ORDER BY created_at DESC LIMIT 1) active ON true
      WHERE servers.organization_id=$1 AND ($2::text IS NULL OR position(lower($2) in lower(servers.hostname || ' ' || COALESCE(servers.os_version,'') || ' ' || servers.labels::text))>0)
      AND ($3::text IS NULL OR servers.os::text=$3) AND ($4::uuid IS NULL OR EXISTS(SELECT 1 FROM server_group_members WHERE organization_id=servers.organization_id AND server_id=servers.id AND group_id=$4))
      AND ($5::timestamptz IS NULL OR (servers.created_at,servers.id)<($5::timestamptz,$6::uuid))
      AND ($7::text IS NULL OR CASE WHEN servers.decommissioned_at IS NOT NULL THEN 'DECOMMISSIONED' WHEN active.id IS NULL THEN CASE WHEN EXISTS(SELECT 1 FROM agent_credentials history WHERE history.organization_id=servers.organization_id AND history.server_id=servers.id) THEN 'REVOKED_OR_EXPIRED' ELSE 'PENDING_ENROLLMENT' END WHEN servers.last_heartbeat_at IS NULL THEN 'AWAITING_HEARTBEAT' WHEN servers.last_heartbeat_at>=now()-interval '90 seconds' THEN 'ONLINE' WHEN servers.last_heartbeat_at>=now()-interval '5 minutes' THEN 'STALE' ELSE 'UNKNOWN' END=$7)
      ORDER BY servers.created_at DESC,servers.id DESC LIMIT $8`, [organizationId, filter.q || null, filter.os || null, filter.groupId || null, anchor?.created_at || null, anchor?.id || null, filter.status || null, filter.limit + 1]);
    const items = result.rows.slice(0, filter.limit).map(server => ({ ...server, uptime_seconds: server.uptime_seconds == null ? null : String(server.uptime_seconds), status: agentStatus(server), health: healthSummary(agentStatus(server), server.latest_metrics) }));
    return { items, nextCursor: result.rows.length > filter.limit ? result.rows[filter.limit - 1].id : null };
  }

  async groups(actor: Actor, organizationId: string) {
    await this.control.membership(this.db, organizationId, actor);
    return (await this.db.query('SELECT id,name FROM server_groups WHERE organization_id=$1 ORDER BY name,id LIMIT 500', [organizationId])).rows;
  }
  async createGroup(actor: Actor, organizationId: string, body: unknown) {
    const data = input(z.object({ name }).strict(), body);
    return this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      if ((await client.query('SELECT id FROM server_groups WHERE organization_id=$1 AND name=$2', [organizationId, data.name])).rows.length) throw new ConflictException('Group name already exists');
      const id = randomUUID();
      await client.query('INSERT INTO server_groups (id,organization_id,name) VALUES ($1,$2,$3)', [id, organizationId, data.name]);
      await this.control.audit(client, organizationId, actor.id, 'server_group.created', id);
      return { id, name: data.name };
    });
  }
  async updateMetadata(actor: Actor, organizationId: string, serverId: string, body: unknown) {
    const data = input(z.object({ labels: z.record(z.string().regex(/^[A-Za-z0-9_-]{1,32}$/), z.string().max(120)).refine(labels => Object.keys(labels).length <= 16), groupIds: z.array(uuid).max(20).refine(ids => new Set(ids).size === ids.length) }).strict(), body);
    await this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      await this.serverAccess(client, actor, organizationId, serverId);
      if (data.groupIds.length) {
        const groups = await client.query('SELECT id FROM server_groups WHERE organization_id=$1 AND id=ANY($2::uuid[])', [organizationId, data.groupIds]);
        if (groups.rows.length !== data.groupIds.length) throw new NotFoundException('One or more groups were not found');
      }
      await client.query('UPDATE servers SET labels=$3::jsonb WHERE organization_id=$1 AND id=$2', [organizationId, serverId, JSON.stringify(data.labels)]);
      await client.query('DELETE FROM server_group_members WHERE organization_id=$1 AND server_id=$2', [organizationId, serverId]);
      for (const groupId of data.groupIds) await client.query('INSERT INTO server_group_members (organization_id,group_id,server_id) VALUES ($1,$2,$3)', [organizationId, groupId, serverId]);
      await this.control.audit(client, organizationId, actor.id, 'server.metadata_updated', serverId, { groupCount: data.groupIds.length });
    });
    return { ok: true };
  }

  async history(actor: Actor, organizationId: string, serverId: string, query: unknown) {
    const filter = input(z.object({ hours: z.coerce.number().refine(value => [1, 24, 168].includes(value)).default(24) }).strict(), query);
    await this.serverAccess(this.db, actor, organizationId, serverId);
    const seconds = filter.hours === 1 ? 30 : filter.hours === 24 ? 600 : 3600;
    const result = await this.db.query(`SELECT date_bin(($4::text || ' seconds')::interval,received_at,'2000-01-01'::timestamptz) AS time,
      AVG(cpu_percent)::double precision AS cpu_percent,AVG(memory_used_bytes::double precision / NULLIF(memory_total_bytes,0)*100)::double precision AS memory_percent,
      AVG(disk_used_bytes::double precision / NULLIF(disk_total_bytes,0)*100)::double precision AS disk_percent,count(*)::int AS samples
      FROM metric_samples WHERE organization_id=$1 AND server_id=$2 AND received_at>=now()-($3::text || ' hours')::interval
      GROUP BY time ORDER BY time LIMIT 242`, [organizationId, serverId, filter.hours, seconds]);
    return { windowHours: filter.hours, bucketSeconds: seconds, points: result.rows };
  }

  async events(actor: Actor, organizationId: string, query: unknown) {
    const filter = input(eventsQuerySchema, query);
    await this.control.membership(this.db, organizationId, actor);
    if (filter.serverId) await this.serverAccess(this.db, actor, organizationId, filter.serverId);
    let anchor: Row | undefined;
    if (filter.cursor) {
      anchor = (await this.db.query('SELECT id,received_at FROM security_events WHERE organization_id=$1 AND id=$2', [organizationId, filter.cursor])).rows[0];
      if (!anchor) throw new BadRequestException('Invalid event cursor');
    }
    const result = await this.db.query(`SELECT security_events.id,security_events.server_id,security_events.source_event_id,security_events.kind,security_events.severity,
      security_events.occurred_at,security_events.received_at,security_events.payload,servers.hostname FROM security_events
      JOIN servers ON servers.organization_id=security_events.organization_id AND servers.id=security_events.server_id
      WHERE security_events.organization_id=$1 AND ($2::uuid IS NULL OR server_id=$2) AND ($3::text IS NULL OR severity::text=$3) AND ($4::text IS NULL OR kind=$4)
      AND received_at>=now()-($5::text || ' hours')::interval AND ($6::timestamptz IS NULL OR (received_at,security_events.id)<($6::timestamptz,$7::uuid))
      ORDER BY received_at DESC,security_events.id DESC LIMIT $8`, [organizationId, filter.serverId || null, filter.severity || null, filter.kind || null, filter.hours, anchor?.received_at || null, anchor?.id || null, filter.limit + 1]);
    const items = result.rows.slice(0, filter.limit);
    return { items, nextCursor: result.rows.length > filter.limit ? items[items.length - 1].id : null };
  }
}
