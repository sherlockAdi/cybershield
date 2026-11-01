import { ConflictException, Inject, Injectable, NotFoundException, OnModuleDestroy } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Database, Row } from './database';
import { Actor, ControlService } from './service';
import { input, uuid } from './input';
import { configuration, detectionConfig } from './detection-model';
import { severities } from './telemetry-model';

@Injectable()
export class DetectionService implements OnModuleDestroy {
  private timer?: ReturnType<typeof setInterval>;
  private task?: Promise<void>;
  private running = false;
  constructor(@Inject(Database) private readonly db: Database, @Inject(ControlService) private readonly control: ControlService) {}
  start() {
    if (this.timer) return;
    const run = () => { if (!this.running) this.task = this.deliver().catch(() => console.error('Notification relay deferred; durable outbox retained')); };
    this.timer = setInterval(run, 5000); this.timer.unref(); run();
  }
  async onModuleDestroy() { if (this.timer) clearInterval(this.timer); await this.task; }
  async deliver() {
    if (this.running) return;
    this.running = true;
    try {
      const pending = (await this.db.query("SELECT id,organization_id FROM outbox_events WHERE topic='security.incident_created' AND published_at IS NULL AND attempts<5 AND (next_attempt_at IS NULL OR next_attempt_at<=now()) ORDER BY created_at,id LIMIT 50")).rows;
      for (const item of pending) {
        try {
          await this.db.transaction(async client => {
            await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [item.organization_id]);
            const result = await client.query("SELECT * FROM outbox_events WHERE id=$1 AND organization_id=$2 AND topic='security.incident_created' AND published_at IS NULL AND attempts<5 AND (next_attempt_at IS NULL OR next_attempt_at<=now()) FOR UPDATE SKIP LOCKED", [item.id, item.organization_id]);
            if (!result.rows.length) return;
            const outbox = result.rows[0];
            const payload = input(z.object({ incidentId: uuid }).strict(), outbox.payload);
            const incident = (await client.query('SELECT id,title,severity,rule_key,server_id FROM incidents WHERE organization_id=$1 AND id=$2', [item.organization_id, payload.incidentId])).rows[0];
            if (!incident) throw new Error('Incident reference unavailable');
            const config = configuration((await client.query('SELECT detection_config FROM organizations WHERE id=$1', [item.organization_id])).rows[0].detection_config);
            if (config.inAppNotifications) await client.query("INSERT INTO notifications (id,organization_id,deduplication_key,channel,destination_ref,state,attempts,payload,sent_at) VALUES ($1,$2,$3,'IN_APP',$4,'SENT',1,$5::jsonb,now()) ON CONFLICT(deduplication_key) DO NOTHING", [randomUUID(), item.organization_id, `incident:${incident.id}:in-app`, `organization:${item.organization_id}`, JSON.stringify({ incidentId: incident.id, title: incident.title, severity: incident.severity, ruleKey: incident.rule_key, serverId: incident.server_id })]);
            await client.query('UPDATE outbox_events SET published_at=now(),attempts=attempts+1,next_attempt_at=NULL,last_error=$2 WHERE id=$1', [item.id, config.inAppNotifications ? null : 'DISABLED_BY_SETTINGS']);
          });
        } catch {
          await this.db.query("UPDATE outbox_events SET attempts=attempts+1,last_error='IN_APP_DELIVERY_FAILED',next_attempt_at=now()+LEAST(900,power(2,attempts+1)::int*30)*interval '1 second' WHERE id=$1 AND organization_id=$2 AND published_at IS NULL", [item.id, item.organization_id]);
        }
      }
    } finally { this.running = false; }
  }
  async config(actor: Actor, organizationId: string) {
    await this.control.membership(this.db, organizationId, actor);
    return { ...configuration((await this.db.query('SELECT detection_config FROM organizations WHERE id=$1', [organizationId])).rows[0].detection_config), authWindowSeconds: 300, cooldownSeconds: 300, channels: ['IN_APP'], coverage: 'REQUIRES_SIGNED_AUTH_AND_PROCESS_OBSERVATIONS_NO_AUTOMATIC_OS_COLLECTION' };
  }
  async updateConfig(actor: Actor, organizationId: string, body: unknown) {
    const data = input(detectionConfig, body);
    return this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      await client.query('UPDATE organizations SET detection_config=$2::jsonb WHERE id=$1', [organizationId, JSON.stringify(data)]);
      await this.control.audit(client, organizationId, actor.id, 'detection.settings_updated', organizationId, data);
      return data;
    });
  }
  async incidents(actor: Actor, organizationId: string, query: unknown) {
    const filter = input(z.object({ state: z.enum(['OPEN', 'INVESTIGATING', 'RESOLVED']).optional(), severity: z.enum(severities).optional(), cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(30) }).strict(), query);
    await this.control.membership(this.db, organizationId, actor);
    let anchor: Row | undefined;
    if (filter.cursor) {
      anchor = (await this.db.query('SELECT id,created_at FROM incidents WHERE organization_id=$1 AND id=$2', [organizationId, filter.cursor])).rows[0];
      if (!anchor) throw new ConflictException('Invalid incident cursor');
    }
    const rows = (await this.db.query('SELECT incidents.*,servers.hostname FROM incidents LEFT JOIN servers ON servers.organization_id=incidents.organization_id AND servers.id=incidents.server_id WHERE incidents.organization_id=$1 AND ($2::text IS NULL OR incidents.state::text=$2) AND ($3::text IS NULL OR incidents.severity::text=$3) AND ($4::timestamptz IS NULL OR (incidents.created_at,incidents.id)<($4::timestamptz,$5::uuid)) ORDER BY incidents.created_at DESC,incidents.id DESC LIMIT $6', [organizationId, filter.state || null, filter.severity || null, anchor?.created_at || null, anchor?.id || null, filter.limit + 1])).rows;
    return { items: rows.slice(0, filter.limit), nextCursor: rows.length > filter.limit ? rows[filter.limit - 1].id : null };
  }
  async incident(actor: Actor, organizationId: string, incidentId: string) {
    await this.control.membership(this.db, organizationId, actor);
    const incident = (await this.db.query('SELECT incidents.*,servers.hostname FROM incidents LEFT JOIN servers ON servers.organization_id=incidents.organization_id AND servers.id=incidents.server_id WHERE incidents.organization_id=$1 AND incidents.id=$2', [organizationId, input(uuid, incidentId)])).rows[0];
    if (!incident) throw new NotFoundException('Incident not found');
    const ids = z.array(uuid).max(10).safeParse(incident.evidence.eventIds);
    const events = ids.success ? (await this.db.query('SELECT id,kind,severity,occurred_at,received_at,payload FROM security_events WHERE organization_id=$1 AND server_id=$2 AND id=ANY($3::uuid[]) ORDER BY occurred_at,id', [organizationId, incident.server_id, ids.data])).rows : [];
    return { incident, events };
  }
  async updateIncident(actor: Actor, organizationId: string, incidentId: string, body: unknown) {
    const data = input(z.object({ state: z.enum(['OPEN', 'INVESTIGATING', 'RESOLVED']), reason: z.string().trim().min(3).max(1000) }).strict(), body);
    return this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN', 'OPERATOR']);
      const current = (await client.query('SELECT state FROM incidents WHERE organization_id=$1 AND id=$2 FOR UPDATE', [organizationId, input(uuid, incidentId)])).rows[0];
      if (!current) throw new NotFoundException('Incident not found');
      await client.query('UPDATE incidents SET state=$3::"IncidentState",resolved_at=CASE WHEN $3::text=\'RESOLVED\' THEN now() ELSE NULL END WHERE organization_id=$1 AND id=$2', [organizationId, incidentId, data.state]);
      await this.control.audit(client, organizationId, actor.id, 'incident.state_changed', incidentId, { previousState: current.state, ...data });
      return { ok: true, state: data.state };
    });
  }
  async inbox(actor: Actor, organizationId: string, query: unknown) {
    const filter = input(z.object({ cursor: uuid.optional(), limit: z.coerce.number().int().min(1).max(100).default(30), unread: z.enum(['true', 'false']).optional() }).strict(), query);
    await this.control.membership(this.db, organizationId, actor);
    let anchor: Row | undefined;
    if (filter.cursor) {
      anchor = (await this.db.query("SELECT id,created_at FROM notifications WHERE organization_id=$1 AND id=$2 AND channel='IN_APP' AND state='SENT'", [organizationId, filter.cursor])).rows[0];
      if (!anchor) throw new ConflictException('Invalid notification cursor');
    }
    const items = (await this.db.query("SELECT id,payload,created_at,sent_at,$2=ANY(read_by) AS read FROM notifications WHERE organization_id=$1 AND channel='IN_APP' AND state='SENT' AND ($3::boolean=false OR NOT($2=ANY(read_by))) AND ($4::timestamptz IS NULL OR (created_at,id)<($4::timestamptz,$5::uuid)) ORDER BY created_at DESC,id DESC LIMIT $6", [organizationId, actor.id, filter.unread === 'true', anchor?.created_at || null, anchor?.id || null, filter.limit + 1])).rows;
    const unreadCount = (await this.db.query("SELECT count(*)::int AS count FROM notifications WHERE organization_id=$1 AND channel='IN_APP' AND state='SENT' AND NOT($2=ANY(read_by))", [organizationId, actor.id])).rows[0].count;
    return { items: items.slice(0, filter.limit), nextCursor: items.length > filter.limit ? items[filter.limit - 1].id : null, unreadCount };
  }
  async read(actor: Actor, organizationId: string, notificationId: string, body: unknown) {
    input(z.object({}).strict(), body);
    await this.control.membership(this.db, organizationId, actor);
    const result = await this.db.query("UPDATE notifications SET read_by=CASE WHEN $3=ANY(read_by) THEN read_by ELSE array_append(read_by,$3::uuid) END WHERE organization_id=$1 AND id=$2 AND channel='IN_APP' AND state='SENT' RETURNING id", [organizationId, input(uuid, notificationId), actor.id]);
    if (!result.rows.length) throw new NotFoundException('Notification not found');
    return { read: true };
  }
  async deliveries(actor: Actor, organizationId: string) {
    await this.control.membership(this.db, organizationId, actor, ['OWNER', 'ADMIN']);
    return { channel: 'IN_APP', externalDeliveryConfigured: false, items: (await this.db.query("SELECT id,created_at,published_at,attempts,next_attempt_at,last_error,payload FROM outbox_events WHERE organization_id=$1 AND topic='security.incident_created' ORDER BY created_at DESC,id DESC LIMIT 100", [organizationId])).rows };
  }
  async retry(actor: Actor, organizationId: string, outboxId: string, body: unknown) {
    input(z.object({}).strict(), body);
    return this.db.transaction(async client => {
      await client.query('SELECT id FROM organizations WHERE id=$1 FOR UPDATE', [input(uuid, organizationId)]);
      await this.control.membership(client, organizationId, actor, ['OWNER', 'ADMIN']);
      const row = (await client.query("SELECT published_at,attempts FROM outbox_events WHERE organization_id=$1 AND id=$2 AND topic='security.incident_created' FOR UPDATE", [organizationId, input(uuid, outboxId)])).rows[0];
      if (!row) throw new NotFoundException('Delivery not found');
      if (row.published_at || row.attempts < 5) throw new ConflictException('Only exhausted unpublished deliveries may be retried');
      await client.query('UPDATE outbox_events SET attempts=0,next_attempt_at=now(),last_error=NULL WHERE organization_id=$1 AND id=$2', [organizationId, outboxId]);
      await this.control.audit(client, organizationId, actor.id, 'notification.retry_requested', outboxId);
      return { queued: true };
    });
  }
}
