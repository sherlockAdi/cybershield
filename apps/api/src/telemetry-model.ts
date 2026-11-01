import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { Queryable, Row } from './database';
import { isIP } from 'node:net';

const bytes = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable();
export const metricsSchema = z.object({
  sampledAt: z.iso.datetime(), cpuPercent: z.number().min(0).max(100).nullable(),
  memoryTotalBytes: bytes, memoryUsedBytes: bytes, diskTotalBytes: bytes, diskUsedBytes: bytes,
}).strict().refine(value => {
  return [[value.memoryTotalBytes, value.memoryUsedBytes], [value.diskTotalBytes, value.diskUsedBytes]].every(([total, used]) => {
    return total === null && used === null || total !== null && used !== null && total > 0 && used <= total;
  });
});
export type Metrics = z.infer<typeof metricsSchema>;
export const inventorySchema = z.object({ architecture: z.string().regex(/^[A-Za-z0-9_-]{1,32}$/), logicalCpuCount: z.number().int().min(1).max(65536) }).strict();
export const eventKinds = ['AGENT_STARTED', 'HEALTH_THRESHOLD', 'AUTH_FAILURE', 'AUTH_SUCCESS', 'PROCESS_START', 'FILE_CHANGE', 'SYSTEM_EVENT', 'NETWORK_CONNECTION', 'ICMP_ECHO', 'TELEMETRY_STATUS'] as const;
export const sourceIp = z.string().max(45).refine(value => isIP(value) !== 0 && !value.includes('%'), 'Expected a plain IP address').transform(value => isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value);
export const severities = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
const positiveCount = z.string().regex(/^[1-9][0-9]{0,8}$/);
const portText = z.string().regex(/^[0-9]{1,5}$/).refine(value => Number(value) <= 65535);
const activityPayload = { peerIp: sourceIp.optional(), direction: z.enum(['INBOUND', 'OUTBOUND', 'UNKNOWN']).optional(), transport: z.enum(['TCP', 'UDP', 'ICMP', 'ICMPV6']).optional(), localPort: portText.optional(), peerPort: portText.optional(), requestCount: positiveCount.optional(), collector: z.enum(['AUTH', 'NETWORK', 'ICMP']).optional(), collectorState: z.enum(['RUNNING', 'BACKFILLING', 'ERROR']).optional(), coverageFrom: z.iso.datetime().optional(), coverageThrough: z.iso.datetime().optional() };
export const eventSchema = z.object({
  sourceEventId: z.string().min(1).max(128).regex(/^[A-Za-z0-9_.:-]+$/).refine(value => !value.startsWith('sg:')),
  kind: z.enum(eventKinds), severity: z.enum(severities), occurredAt: z.iso.datetime(),
  payload: z.object({ ...activityPayload, source: z.string().min(1).max(80), message: z.string().max(500).optional(), code: z.string().max(80).optional(), metric: z.enum(['CPU', 'MEMORY', 'DISK']).optional(), level: z.enum(['NORMAL', 'WARNING', 'CRITICAL']).optional(), valuePercent: z.number().min(0).max(100).optional(), service: z.enum(['SSH', 'RDP']).optional(), sourceIp: sourceIp.optional(), account: z.string().min(1).max(128).optional(), processName: z.string().min(1).max(120).regex(/^[A-Za-z0-9_. -]+$/).transform(value => value.toLowerCase()).optional(), processId: z.string().regex(/^[1-9][0-9]{0,9}$/).refine(value => Number(value) <= 4294967295).optional(), imagePath: z.string().max(512).optional(), parentProcessName: z.string().max(120).optional() }).strict(),
}).strict().superRefine((event, context) => {
  if (event.kind === 'HEALTH_THRESHOLD' && (event.payload.metric === undefined || event.payload.level === undefined || event.payload.valuePercent === undefined)) context.addIssue({ code: 'custom', message: 'Health events require metric, level and value' });
  if ((event.kind === 'AUTH_SUCCESS' || event.payload.service !== undefined || event.payload.sourceIp !== undefined) && (!['AUTH_SUCCESS', 'AUTH_FAILURE'].includes(event.kind) || !event.payload.service || !event.payload.sourceIp)) context.addIssue({ code: 'custom', message: 'Authentication observations require service and sourceIp' });
  if (event.kind === 'PROCESS_START' && (!event.payload.processName || !event.payload.processId)) context.addIssue({ code: 'custom', message: 'Process observations require processName and processId' });
  if (event.kind === 'NETWORK_CONNECTION' && (!event.payload.peerIp || !event.payload.direction || !['TCP', 'UDP'].includes(event.payload.transport || ''))) context.addIssue({ code: 'custom', message: 'Connection observations require peerIp, direction and TCP/UDP transport' });
  if (event.kind === 'ICMP_ECHO' && (!event.payload.peerIp || event.payload.direction !== 'INBOUND' || !['ICMP', 'ICMPV6'].includes(event.payload.transport || '') || !event.payload.requestCount)) context.addIssue({ code: 'custom', message: 'Ping observations require an inbound echo-request peer and count' });
  if (event.kind === 'TELEMETRY_STATUS' && (!event.payload.collector || !event.payload.collectorState || !event.payload.coverageFrom || !event.payload.coverageThrough || Date.parse(event.payload.coverageThrough) < Date.parse(event.payload.coverageFrom))) context.addIssue({ code: 'custom', message: 'Collector status requires a valid coverage interval' });
});
export type AgentEvent = z.infer<typeof eventSchema>;

export function eventHash(event: unknown) {
  function ordered(value: any): any {
    if (Array.isArray(value)) return value.map(ordered);
    if (value !== null && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])]));
    return value;
  }
  return createHash('sha256').update(JSON.stringify(ordered(event))).digest('hex');
}

export function metricPercentages(sample: Row | null) {
  return {
    CPU: sample?.cpu_percent == null ? null : Number(sample.cpu_percent),
    MEMORY: sample?.memory_total_bytes == null ? null : Number(sample.memory_used_bytes) / Number(sample.memory_total_bytes) * 100,
    DISK: sample?.disk_total_bytes == null ? null : Number(sample.disk_used_bytes) / Number(sample.disk_total_bytes) * 100,
  };
}
export function resourceLevel(metric: string, percent: number | null) {
  if (percent === null) return 'NO_DATA';
  return percent >= 95 ? 'CRITICAL' : percent >= (metric === 'CPU' ? 80 : 85) ? 'WARNING' : 'NORMAL';
}
export function healthSummary(liveness: string, latest: Row | null, now = Date.now()) {
  if (liveness !== 'ONLINE') return { state: liveness, resources: metricPercentages(latest) };
  if (!latest) return { state: 'NO_DATA', resources: metricPercentages(null) };
  if (now - new Date(latest.received_at).getTime() > 90000) return { state: 'STALE', resources: metricPercentages(latest) };
  const percentages = metricPercentages(latest);
  const levels = Object.entries(percentages).map(([metric, percent]) => resourceLevel(metric, percent));
  return { state: levels.includes('CRITICAL') ? 'CRITICAL' : levels.includes('WARNING') ? 'WARNING' : levels.every(level => level === 'NO_DATA') ? 'NO_DATA' : 'NORMAL', resources: percentages };
}

export async function recordMetrics(client: Queryable, organizationId: string, serverId: string, credentialId: string, sequence: number, metrics: Metrics) {
  const prior = await client.query('SELECT * FROM metric_samples WHERE organization_id=$1 AND server_id=$2 AND credential_id=$3 ORDER BY received_at DESC,id DESC LIMIT 1', [organizationId, serverId, credentialId]);
  const inserted = await client.query(`INSERT INTO metric_samples (id,organization_id,server_id,credential_id,sequence,cpu_percent,memory_total_bytes,memory_used_bytes,disk_total_bytes,disk_used_bytes,sampled_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`, [randomUUID(), organizationId, serverId, credentialId, sequence, metrics.cpuPercent, metrics.memoryTotalBytes, metrics.memoryUsedBytes, metrics.diskTotalBytes, metrics.diskUsedBytes, new Date(metrics.sampledAt)]);
  const before = metricPercentages(prior.rows[0] || null);
  const after = metricPercentages(inserted.rows[0]);
  for (const [metric, percent] of Object.entries(after)) {
    const level = resourceLevel(metric, percent);
    const previous = resourceLevel(metric, before[metric as keyof typeof before]);
    if (level === 'NO_DATA' || level === previous || previous === 'NO_DATA' && level === 'NORMAL') continue;
    const event = { sourceEventId: `sg:health:${credentialId}:${sequence}:${metric}`, kind: 'HEALTH_THRESHOLD', severity: level === 'CRITICAL' ? 'HIGH' : level === 'WARNING' ? 'MEDIUM' : 'INFO', occurredAt: new Date(metrics.sampledAt).toISOString(), payload: { source: 'serverguard-health', metric, level, valuePercent: percent } };
    await client.query('INSERT INTO security_events (id,organization_id,server_id,source_event_id,kind,severity,occurred_at,payload,event_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)', [randomUUID(), organizationId, serverId, event.sourceEventId, event.kind, event.severity, new Date(event.occurredAt), JSON.stringify(event.payload), eventHash(event)]);
  }
}
