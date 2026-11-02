'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Activity, RefreshCw, X } from 'lucide-react';
import { api } from '../lib/api';
import ServerActivity from './server-activity';
import HostManagement from './host-management';

export type Group = { id: string; name: string };
export type InventoryRecord = {
  id: string; hostname: string; os: string; os_version: string | null; agent_version: string | null; status: string; last_heartbeat_at: string | null;
  uptime_seconds: string | null; credential_expires_at: string | null; decommissioned_at: string | null; architecture: string | null; logical_cpu_count: number | null;
  labels: Record<string, string>; groups: Group[];
  latest_metrics: { cpu_percent: number | null; memory_total_bytes: number | null; memory_used_bytes: number | null; disk_total_bytes: number | null; disk_used_bytes: number | null; sampled_at: string; received_at: string } | null;
  health: { state: string; resources: { CPU: number | null; MEMORY: number | null; DISK: number | null } };
};
type MetricPoint = { time: string; cpu_percent: number | null; memory_percent: number | null; disk_percent: number | null; samples: number };
type MetricHistory = { windowHours: number; bucketSeconds: number; points: MetricPoint[] };
type EventRecord = { id: string; hostname: string; kind: string; severity: string; occurred_at: string; received_at: string; payload: { source: string; message?: string; metric?: string; level?: string; valuePercent?: number; code?: string; service?: string; sourceIp?: string; processName?: string; processId?: string } };
type EventPage = { items: EventRecord[]; nextCursor: string | null };
const date = (value: string) => new Date(value).toLocaleString();
export const percent = (value: number | null | undefined) => value == null ? 'Unavailable' : `${value.toFixed(1)}%`;
const size = (value: number | null | undefined) => value == null ? 'Unavailable' : `${(Number(value) / 1073741824).toFixed(1)} GiB`;

function EventTable({ items }: { items: EventRecord[] }) {
  return items.length ? <div className="table-wrap"><table><thead><tr><th>Event / server</th><th>Severity</th><th>Details</th><th>Occurred</th><th>Received</th></tr></thead><tbody>{items.map(event => <tr key={event.id}><td><strong>{event.kind.replaceAll('_', ' ')}</strong><div className="muted">{event.hostname}</div></td><td><span className={`badge ${['CRITICAL', 'HIGH'].includes(event.severity) ? 'red' : event.severity === 'MEDIUM' ? 'amber' : 'green'}`}>{event.severity}</span></td><td className="event-detail"><span>{event.payload.message || [event.payload.metric, event.payload.level, event.payload.valuePercent == null ? null : percent(event.payload.valuePercent)].filter(Boolean).join(' · ') || [event.payload.service, event.payload.sourceIp, event.payload.processName, event.payload.processId ? `PID ${event.payload.processId}` : null].filter(Boolean).join(' · ') || event.payload.code || 'Event received'}</span><small>{event.payload.source}</small></td><td className="muted">{date(event.occurred_at)}</td><td className="muted">{date(event.received_at)}</td></tr>)}</tbody></table></div> : <div className="empty"><Activity size={27} /><h3>No events in this window</h3><p>Agent startup and resource-state events appear after ingestion.</p></div>;
}

function HistoryChart({ history }: { history: MetricHistory }) {
  const resources = [{ key: 'cpu_percent' as const, label: 'CPU', color: '#b5f36a' }, { key: 'memory_percent' as const, label: 'Memory', color: '#7ab8ff' }, { key: 'disk_percent' as const, label: 'System disk', color: '#d5a6ff' }];
  const end = Date.now();
  const start = end - history.windowHours * 3600000;
  const horizontal = (time: string) => 35 + Math.max(0, Math.min(1, (Date.parse(time) - start) / (end - start))) * 670;
  function line(key: typeof resources[number]['key']) {
    let path = '';
    let connected = false;
    let priorTime = 0;
    for (const point of history.points) {
      if (point[key] === null) { connected = false; continue; }
      const time = Date.parse(point.time);
      const join = connected && time - priorTime <= history.bucketSeconds * 1500;
      path += `${join ? 'L' : 'M'}${horizontal(point.time).toFixed(2)},${(175 - point[key]! * 1.5).toFixed(2)} `;
      connected = true; priorTime = time;
    }
    return path;
  }
  return <><div className="chart-legend">{resources.map(resource => <span key={resource.key}><i style={{ background: resource.color }} />{resource.label}</span>)}</div><svg className="metric-chart" viewBox="0 0 720 205" role="img" aria-label={`Average CPU, memory and system disk usage over ${history.windowHours} hours. Gaps indicate missing samples.`}>
    {[0, 50, 100].map(value => <g key={value}><line x1="35" x2="705" y1={175 - value * 1.5} y2={175 - value * 1.5} stroke="#2a3441" /><text x="2" y={179 - value * 1.5} fill="#8190a3" fontSize="10">{value}%</text></g>)}
    {resources.map(resource => <g key={resource.key}><path d={line(resource.key)} fill="none" stroke={resource.color} strokeWidth="2" />{history.points.filter(point => point[resource.key] !== null).map(point => <circle key={point.time} cx={horizontal(point.time)} cy={175 - point[resource.key]! * 1.5} r="2.6" fill={resource.color}><title>{date(point.time)} · {resource.label}: {percent(point[resource.key])} · {point.samples} samples</title></circle>)}</g>)}
    <text x="35" y="200" fill="#8190a3" fontSize="10">{new Date(start).toLocaleString()}</text><text x="705" y="200" textAnchor="end" fill="#8190a3" fontSize="10">Now</text>
  </svg><p className="muted chart-note">{history.bucketSeconds}-second averages · {history.points.reduce((sum, point) => sum + point.samples, 0)} reports · gaps remain unavailable</p></>;
}

export function ServerTelemetry({ organizationId, server, groups, canManage, onClose, onUpdated, onError }: { organizationId: string; server: InventoryRecord; groups: Group[]; canManage: boolean; onClose: () => void; onUpdated: () => Promise<void>; onError: (error: unknown) => void }) {
  const [hours, setHours] = useState('24');
  const [history, setHistory] = useState<MetricHistory | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const callbacks = useRef({ onError, onUpdated }); callbacks.current = { onError, onUpdated };
  useEffect(() => {
    let alive = true;
    setLoading(true); setHistory(null); setEvents([]);
    async function load() {
      try {
        const [nextHistory, nextEvents] = await Promise.all([api<MetricHistory>(`/organizations/${organizationId}/servers/${server.id}/metrics?hours=${hours}`), api<EventPage>(`/organizations/${organizationId}/events?serverId=${server.id}&hours=${hours}&limit=20`)]);
        if (alive) { setHistory(nextHistory); setEvents(nextEvents.items); }
      } catch (error) { if (alive) callbacks.current.onError(error); }
      finally { if (alive) setLoading(false); }
    }
    void load(); const timer = setInterval(() => { if (!document.hidden) void load(); }, 10000);
    return () => { alive = false; clearInterval(timer); };
  }, [organizationId, server.id, hours]);

  async function metadata(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget); setBusy(true);
    try {
      const labels = JSON.parse(String(form.get('labels') || '{}'));
      await api(`/organizations/${organizationId}/servers/${server.id}/metadata`, 'PATCH', { labels, groupIds: form.getAll('groupId') });
      await callbacks.current.onUpdated();
    } catch (error) { callbacks.current.onError(error); } finally { setBusy(false); }
  }
  return <section className="panel section-gap server-telemetry"><div className="panel-heading"><div><h2>{server.hostname} · health & history</h2><p>{server.os_version || server.os} · {server.architecture || 'Architecture unavailable'} · {server.logical_cpu_count ?? 'Unknown'} logical CPUs · {server.health.state.replaceAll('_', ' ')}</p></div><button className="text-button" aria-label="Close server details" onClick={onClose}><X size={20} /></button></div>
    <HostManagement organizationId={organizationId} serverId={server.id} os={server.os} canManage={canManage} onError={onError} />
    <ServerActivity organizationId={organizationId} serverId={server.id} onError={onError} />
    <div className="metrics-grid">{[{ label: 'CPU use', value: percent(server.health.resources.CPU), total: 'Aggregate sample interval' }, { label: 'Memory use', value: percent(server.health.resources.MEMORY), total: `${size(server.latest_metrics?.memory_used_bytes)} / ${size(server.latest_metrics?.memory_total_bytes)}` }, { label: 'System disk use', value: percent(server.health.resources.DISK), total: `${size(server.latest_metrics?.disk_used_bytes)} / ${size(server.latest_metrics?.disk_total_bytes)}` }].map(metric => <div key={metric.label}><span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.total}</small></div>)}</div>
    <div className="telemetry-toolbar"><span className="muted">Latest report: {server.latest_metrics ? date(server.latest_metrics.received_at) : 'Not received'}. Values remain last-known if health is stale.</span><select aria-label="Metric history window" value={hours} onChange={event => setHours(event.target.value)}><option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option></select></div>
    {loading ? <div className="empty"><span className="spinner" /></div> : history?.points.length ? <div className="chart-container"><HistoryChart history={history} /></div> : <div className="empty"><Activity size={27} /><p>No metric samples in this window.</p></div>}
    <div className="panel-heading"><div><h2>Recent host events</h2><p>Latest 20 received events in the selected window</p></div></div><EventTable items={events} />
    {canManage && <form className="metadata-editor" onSubmit={metadata}><h3>Inventory labels & groups</h3><label className="field"><span>Labels as a JSON object (up to 16)</span><textarea name="labels" defaultValue={JSON.stringify(server.labels, null, 2)} rows={3} required maxLength={3000} /></label><div className="group-checkboxes">{groups.map(group => <label key={group.id}><input name="groupId" type="checkbox" value={group.id} defaultChecked={server.groups.some(item => item.id === group.id)} />{group.name}</label>)}</div><button className="button primary compact" disabled={busy}>{busy ? 'Saving…' : 'Save inventory metadata'}</button></form>}
  </section>;
}

export function Events({ organizationId, onError }: { organizationId: string; onError: (error: unknown) => void }) {
  const [severity, setSeverity] = useState('');
  const [kind, setKind] = useState('');
  const [hours, setHours] = useState('24');
  const [items, setItems] = useState<EventRecord[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const alive = useRef(true);
  const sequence = useRef(0);
  const pages = useRef(1);
  const errorCallback = useRef(onError); errorCallback.current = onError;
  async function load(append = false) {
    const request = ++sequence.current; setLoading(true);
    if (!append) pages.current = 1; else pages.current++;
    const query = new URLSearchParams({ hours, limit: '50' });
    if (severity) query.set('severity', severity); if (kind) query.set('kind', kind); if (append && cursor) query.set('cursor', cursor);
    try {
      const result = await api<EventPage>(`/organizations/${organizationId}/events?${query}`);
      if (alive.current && request === sequence.current) { setItems(previous => append ? [...previous, ...result.items] : result.items); setCursor(result.nextCursor); }
    } catch (error) { if (alive.current && request === sequence.current) { setItems([]); errorCallback.current(error); } }
    finally { if (alive.current && request === sequence.current) setLoading(false); }
  }
  useEffect(() => {
    alive.current = true; setItems([]); setCursor(null); void load();
    const timer = setInterval(() => { if (!document.hidden && pages.current === 1) void load(); }, 10000);
    return () => { alive.current = false; sequence.current++; clearInterval(timer); };
  }, [organizationId, severity, kind, hours]);
  return <section className="panel"><div className="panel-heading"><div><h2>Normalized event stream</h2><p>Tenant-isolated events with source-time and receipt-time visibility</p></div><button className="button secondary compact" disabled={loading} onClick={() => void load()}><RefreshCw size={15} /> Refresh</button></div><div className="inventory-filters"><label>Severity<select value={severity} onChange={event => setSeverity(event.target.value)}><option value="">All severities</option>{['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(value => <option key={value}>{value}</option>)}</select></label><label>Kind<select value={kind} onChange={event => setKind(event.target.value)}><option value="">All event kinds</option>{['AGENT_STARTED', 'HEALTH_THRESHOLD', 'AUTH_FAILURE', 'AUTH_SUCCESS', 'PROCESS_START', 'FILE_CHANGE', 'SYSTEM_EVENT', 'NETWORK_CONNECTION', 'ICMP_ECHO', 'TELEMETRY_STATUS'].map(value => <option key={value}>{value}</option>)}</select></label><label>Time window<select value={hours} onChange={event => setHours(event.target.value)}><option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option></select></label></div><EventTable items={items} />{loading && <p className="list-note" role="status">Loading events…</p>}{cursor && <div className="pagination-bar"><button className="button secondary compact" disabled={loading} onClick={() => void load(true)}>Load older events</button><span>Automatic refresh pauses while viewing older pages.</span></div>}</section>;
}
