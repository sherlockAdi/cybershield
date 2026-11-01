import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Queryable, Row } from './database';
import { AgentEvent } from './telemetry-model';

export const detectionConfig = z.object({ enabled: z.boolean(), authFailureThreshold: z.number().int().min(3).max(50), processWatchlist: z.array(z.string().min(1).max(120).regex(/^[A-Za-z0-9_. -]+$/).transform(value => value.toLowerCase())).max(32).refine(names => new Set(names).size === names.length), inAppNotifications: z.boolean() }).strict();
export const defaultDetectionConfig = { enabled: true, authFailureThreshold: 5, processWatchlist: ['mimikatz', 'mimikatz.exe'], inAppNotifications: true };
export function configuration(value: unknown) { const result = detectionConfig.safeParse(value); return result.success ? result.data : { ...defaultDetectionConfig }; }

export async function detectEvent(client: Queryable, organizationId: string, serverId: string, eventId: string, event: AgentEvent) {
  if (!['AUTH_FAILURE', 'AUTH_SUCCESS', 'PROCESS_START'].includes(event.kind)) return;
  const time = Date.parse(event.occurredAt); const now = Date.now();
  if (time < now - 300000 || time > now + 60000) return;
  const config = configuration((await client.query('SELECT detection_config FROM organizations WHERE id=$1', [organizationId])).rows[0].detection_config);
  if (!config.enabled) return;
  let ruleKey: string; let group: string; let title: string; let severity: string; let evidence: Row;
  if (event.kind === 'PROCESS_START') {
    if (!event.payload.processName || !config.processWatchlist.includes(event.payload.processName)) return;
    ruleKey = 'PROCESS_WATCHLIST'; group = event.payload.processName; severity = 'MEDIUM'; title = 'Process name matches configured watchlist';
    evidence = { serverId, processName: event.payload.processName, processId: event.payload.processId, eventIds: [eventId], caveat: 'Name-based indicator only; not a malware verdict. No command line collected.' };
  } else {
    if (!event.payload.service || !event.payload.sourceIp) return;
    const failures = (await client.query(`SELECT id FROM security_events WHERE organization_id=$1 AND server_id=$2 AND kind='AUTH_FAILURE' AND payload->>'service'=$3 AND payload->>'sourceIp'=$4 AND received_at>=now()-interval '5 minutes' AND occurred_at>=now()-interval '5 minutes' AND occurred_at<=now()+interval '60 seconds' ORDER BY occurred_at DESC,id DESC LIMIT 50`, [organizationId, serverId, event.payload.service, event.payload.sourceIp])).rows;
    if (failures.length < config.authFailureThreshold) return;
    ruleKey = event.kind === 'AUTH_SUCCESS' ? `${event.payload.service}_SUCCESS_AFTER_FAILURES` : `${event.payload.service}_FAILURE_BURST`;
    group = `${event.payload.service}:${event.payload.sourceIp}`;
    severity = event.kind === 'AUTH_SUCCESS' ? 'HIGH' : 'MEDIUM';
    title = event.kind === 'AUTH_SUCCESS' ? `${event.payload.service} success after repeated failures` : `${event.payload.service} repeated authentication failures`;
    evidence = { serverId, service: event.payload.service, sourceIp: event.payload.sourceIp, failureCountAtDetection: failures.length, threshold: config.authFailureThreshold, windowSeconds: 300, eventIds: [...new Set([eventId, ...failures.slice(0, 9).map(row => row.id)])], caveat: event.kind === 'AUTH_SUCCESS' ? 'Same source IP/service, not proof that the same account was compromised.' : 'Repeated failures may include benign misconfiguration; investigate before responding.' };
  }
  const correlationKey = createHash('sha256').update(`${organizationId}:${serverId}:${ruleKey}:${group}`).digest('hex');
  if ((await client.query("SELECT id FROM incidents WHERE organization_id=$1 AND server_id=$2 AND rule_key=$3 AND evidence->>'correlationKey'=$4 AND created_at>=now()-interval '5 minutes' LIMIT 1", [organizationId, serverId, ruleKey, correlationKey])).rows.length) return;
  const dedupe = createHash('sha256').update(`${correlationKey}:${Math.floor(now / 300000)}`).digest('hex');
  const id = randomUUID();
  const created = await client.query('INSERT INTO incidents (id,organization_id,server_id,title,severity,evidence,rule_key,deduplication_key) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8) ON CONFLICT(organization_id,deduplication_key) DO NOTHING RETURNING id', [id, organizationId, serverId, title, severity, JSON.stringify({ ...evidence, correlationKey, schemaVersion: 1, provenance: 'ENROLLED_AGENT_CLAIM', notificationRequested: config.inAppNotifications }), ruleKey, dedupe]);
  if (!created.rows.length) return;
  if (config.inAppNotifications) await client.query("INSERT INTO outbox_events (id,organization_id,topic,payload) VALUES ($1,$2,'security.incident_created',$3::jsonb)", [randomUUID(), organizationId, JSON.stringify({ incidentId: id })]);
}
