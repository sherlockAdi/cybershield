'use client';
import { useEffect, useRef, useState } from 'react';
import { api } from '../lib/api';

type Activity = {
  window: { date: string; timeZone: string; start: string; end: string };
  summary: { successful_logins: number; failed_logins: number; unique_observed_ips: number; connection_observations: number; unique_ping_ips: number; ping_requests: string; process_starts: number };
  peers: { ip: string; successful_logins: number; failed_logins: number; connections: number; ping_requests: string; first_seen: string; last_seen: string }[];
  logins: { id: string; kind: string; occurred_at: string; account: string | null; source_ip: string | null; service: string | null }[];
  connections: { id: string; occurred_at: string; peer_ip: string; direction: string; transport: string; local_port: string | null; peer_port: string | null }[];
  collectors: { collector: string; collectorState: string; coverageFrom: string; coverageThrough: string; stale: boolean; message?: string }[];
  scope: string; nextLoginCursor: string | null;
};
const today = () => new Date(Date.now() + 19800000).toISOString().slice(0, 10);
const date = (value: string) => new Date(value).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
export default function ServerActivity({ organizationId, serverId, onError }: { organizationId: string; serverId: string; onError: (error: unknown) => void }) {
  const [day, setDay] = useState(today); const [report, setReport] = useState<Activity | null>(null); const [error, setError] = useState('');
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [before, setBefore] = useState<string | null>(null);
  const cursor = cursors[cursors.length - 1];
  const callback = useRef(onError); callback.current = onError;
  useEffect(() => {
    let active = true; let sequence = 0; setReport(null); setError('');
    async function load() { const request = ++sequence; try { const next = await api<Activity>(`/organizations/${organizationId}/servers/${serverId}/activity?date=${day}${cursor ? `&loginCursor=${cursor}` : ''}${before ? `&before=${encodeURIComponent(before)}` : ''}`); if (active && request === sequence) { setReport(next); setError(''); } } catch (error) { if (active) { setError(error instanceof Error ? error.message : 'Activity unavailable'); callback.current(error); } } }
    void load(); const timer = setInterval(() => { if (!document.hidden) void load(); }, 10000);
    return () => { active = false; sequence++; clearInterval(timer); };
  }, [organizationId, serverId, day, cursor, before]);
  function value(count: number | string, channel?: string) { return Number(count) > 0 || report?.collectors.some(item => (!channel || item.collector === channel) && item.collectorState !== 'ERROR' && !item.stale && Date.parse(item.coverageFrom) < Date.parse(report.window.end) && Date.parse(item.coverageThrough) >= Date.parse(report.window.start)) ? count : 'Unavailable'; }
  return <section className="section-gap"><div className="panel-heading"><div><h2>Daily server activity · India time</h2><p>From 00:00 IST · login attempts are not necessarily unique human sessions · refreshes every 10 seconds</p></div><input aria-label="Activity date" type="date" value={day} max={today()} onChange={event => { if (event.target.value) { setDay(event.target.value); setCursors([null]); setBefore(null); } }} /></div>{error && <div className="message error">{error}</div>}
    {!report ? <div className="empty"><p>Loading recorded activity…</p></div> : <><div className="metrics-grid activity-cards">{[{ label: 'Successful logins', count: report.summary.successful_logins, channel: 'AUTH' }, { label: 'Failed logins', count: report.summary.failed_logins, channel: 'AUTH' }, { label: 'Unique observed IPs', count: report.summary.unique_observed_ips }, { label: 'New TCP connection observations', count: report.summary.connection_observations, channel: 'NETWORK' }, { label: 'Received ping requests', count: report.summary.ping_requests, channel: 'ICMP' }, { label: 'Unique IPs sending pings', count: report.summary.unique_ping_ips, channel: 'ICMP' }].map(card => <div key={card.label}><span>{card.label}</span><strong>{value(card.count, card.channel)}</strong><small>Recorded in the selected day, not guaranteed complete history</small></div>)}</div>
    <div className="firewall-editor"><p className="muted">{report.scope}</p>{!report.collectors.length && <p className="message error">No collector coverage reported. Missing records must not be interpreted as no logins or traffic.</p>}{report.collectors.map(collector => <p className="list-note" key={collector.collector}><span className={`badge ${collector.stale || collector.collectorState === 'ERROR' ? 'amber' : 'green'}`}>{collector.collector} · {collector.stale ? 'STALE' : collector.collectorState}</span> Reported coverage {date(collector.coverageFrom)} – {date(collector.coverageThrough)} IST. {collector.message}</p>)}</div>
    <div className="panel-heading"><h2>Observed IP addresses · top 100</h2></div><div className="table-wrap"><table><thead><tr><th>IP address</th><th>Logins</th><th>Failures</th><th>Connections</th><th>Ping requests</th><th>First / last seen (IST)</th></tr></thead><tbody>{report.peers.map(peer => <tr key={peer.ip}><td><code>{peer.ip}</code></td><td>{peer.successful_logins}</td><td>{peer.failed_logins}</td><td>{peer.connections}</td><td>{peer.ping_requests}</td><td>{date(peer.first_seen)}<br />{date(peer.last_seen)}</td></tr>)}</tbody></table></div>{!report.peers.length && <p className="list-note">No IP observations available for this day.</p>}
    <div className="panel-heading"><h2>Login history · 10 per page</h2></div><div className="table-wrap"><table><thead><tr><th>Time (IST)</th><th>Account</th><th>Service</th><th>Source IP</th><th>Result</th></tr></thead><tbody>{report.logins.map(login => <tr key={login.id}><td>{date(login.occurred_at)}</td><td>{login.account || 'Not reported'}</td><td>{login.service || 'Unclassified'}</td><td>{login.source_ip || 'Not reported'}</td><td><span className={`badge ${login.kind === 'AUTH_SUCCESS' ? 'green' : 'amber'}`}>{login.kind === 'AUTH_SUCCESS' ? 'Success' : 'Failure'}</span></td></tr>)}</tbody></table></div>
    <div className="pagination-bar"><span>Login page {cursors.length} · {report.logins.length} records</span><div className="button-row"><button className="button secondary" disabled={cursors.length === 1} onClick={() => setCursors(value => value.slice(0, -1))}>Previous</button><button className="button secondary" disabled={!report.nextLoginCursor} onClick={() => { setBefore(report.window.end); setCursors(value => [...value, report.nextLoginCursor]); }}>Next 10</button><button className="button secondary" onClick={() => { setBefore(null); setCursors([null]); }}>Latest</button></div></div>
    <div className="panel-heading"><h2>Connection observations · latest 100</h2></div><div className="table-wrap"><table><thead><tr><th>Observed (IST)</th><th>Peer IP</th><th>Direction</th><th>Protocol</th><th>Local / peer port</th></tr></thead><tbody>{report.connections.map(connection => <tr key={connection.id}><td>{date(connection.occurred_at)}</td><td>{connection.peer_ip}</td><td>{connection.direction}</td><td>{connection.transport}</td><td>{connection.local_port || '—'} / {connection.peer_port || '—'}</td></tr>)}</tbody></table></div></>}
  </section>;
}
