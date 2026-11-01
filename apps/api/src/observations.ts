import { createHash } from 'node:crypto';
import { z } from 'zod';
import { AgentEvent, eventSchema } from './telemetry-model';

const text = z.string().max(4096);
const journal = z.object({ __CURSOR: text.min(1), __REALTIME_TIMESTAMP: z.string().regex(/^\d{1,17}$/), _COMM: text, MESSAGE: text });
const windows = z.object({ provider: z.literal('Microsoft-Windows-Security-Auditing'), channel: z.literal('Security'), computer: z.string().max(253), recordId: z.string().regex(/^\d{1,20}$/), eventId: z.number().int(), timeCreated: z.iso.datetime(), data: z.record(z.string(), z.string().max(1024)) });
const identity = (value: string) => createHash('sha256').update(value).digest('hex');
export function normalizeJournal(value: unknown): AgentEvent | null {
  const parsed = journal.safeParse(value); if (!parsed.success) return null;
  const record = parsed.data;
  if (!['sshd', 'sshd-session'].includes(record._COMM)) return null;
  const match = /^(Failed (?:password|publickey)|Accepted (?:password|publickey)) for (?:invalid user )?(\S+) from (\S+) port \d+(?: |$)/.exec(record.MESSAGE);
  if (!match) return null;
  const milliseconds = Number(BigInt(record.__REALTIME_TIMESTAMP) / 1000n);
  if (!Number.isSafeInteger(milliseconds) || milliseconds > 8640000000000000) return null;
  const result = eventSchema.safeParse({ sourceEventId: `journal:${identity(record.__CURSOR)}`, occurredAt: new Date(milliseconds).toISOString(), kind: match[1].startsWith('Failed') ? 'AUTH_FAILURE' : 'AUTH_SUCCESS', severity: 'INFO', payload: { source: 'linux-journal-sshd', service: 'SSH', sourceIp: match[3], account: match[2] } });
  return result.success ? result.data : null;
}
export function normalizeWindows(value: unknown): AgentEvent | null {
  const parsed = windows.safeParse(value); if (!parsed.success) return null;
  const record = parsed.data; const data = record.data;
  const event = { sourceEventId: `winsec:${identity(`${record.computer}:${record.channel}:${record.recordId}:${record.timeCreated}:${record.eventId}`)}`, occurredAt: record.timeCreated, severity: 'INFO' };
  let result;
  if ([4624, 4625].includes(record.eventId) && data.LogonType === '10') {
    result = eventSchema.safeParse({ ...event, kind: record.eventId === 4625 ? 'AUTH_FAILURE' : 'AUTH_SUCCESS', payload: { source: 'windows-security', service: 'RDP', sourceIp: data.IpAddress, ...(data.TargetUserName && data.TargetUserName !== '-' ? { account: data.TargetUserName } : {}) } });
  } else if (record.eventId === 4688) {
    const processId = /^0x[0-9a-f]+$/i.test(data.NewProcessId || '') ? Number.parseInt(data.NewProcessId, 16) : Number(data.NewProcessId);
    const processName = data.NewProcessName?.split(/[\\/]/).pop();
    result = eventSchema.safeParse({ ...event, kind: 'PROCESS_START', payload: { source: 'windows-security-4688', processName, processId: String(processId), imagePath: data.NewProcessName, ...(data.ParentProcessName ? { parentProcessName: data.ParentProcessName.split(/[\\/]/).pop() } : {}) } });
  }
  return result?.success ? result.data : null;
}
