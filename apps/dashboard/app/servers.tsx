'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Server, Plus, Copy, X, RefreshCw, ShieldCheck, KeyRound } from 'lucide-react';
import { api, ApiError } from '../lib/api';
import { type InventoryRecord, type Group, percent } from './telemetry';
import ServerDrawer from './server-drawer';

type ServerRecord = InventoryRecord;
type Enrollment = { serverId: string; enrollmentToken: string; expiresAt: string };
const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'Not reported';
const uptime = (value: string | null) => value === null ? '—' : `${Math.floor(Number(value) / 86400)}d ${Math.floor(Number(value) % 86400 / 3600)}h`;

export default function Servers({ organizationId, canManage, onChanged, onSessionExpired }: { organizationId: string; canManage: boolean; onChanged: () => void; onSessionExpired: () => void }) {
  const [servers, setServers] = useState<ServerRecord[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [query, setQuery] = useState('');
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const cursor = cursors[cursors.length - 1];
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [create, setCreate] = useState(false);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const alive = useRef(true);
  const callbacks = useRef({ onChanged, onSessionExpired });
  callbacks.current = { onChanged, onSessionExpired };
  const requestNumber = useRef(0);

  function failure(error: unknown) {
    if (!alive.current) return;
    setError(error instanceof Error ? error.message : 'Unable to load server data');
    if (error instanceof ApiError && [403, 404].includes(error.status)) { setServers([]); setEnrollment(null); setCreate(false); }
    if (error instanceof ApiError && error.status === 401) callbacks.current.onSessionExpired();
  }
  async function reload() {
    const current = ++requestNumber.current;
    try {
      const [records, groupRecords] = await Promise.all([api<{ items: ServerRecord[]; nextCursor: string | null }>(`/organizations/${organizationId}/inventory?limit=10&${query}${cursor ? `&cursor=${cursor}` : ''}`), api<Group[]>(`/organizations/${organizationId}/groups`)]);
      if (alive.current && current === requestNumber.current) { setServers(records.items); setNextCursor(records.nextCursor); setGroups(groupRecords); }
    } catch (error) { if (current === requestNumber.current) failure(error); }
    finally { if (alive.current && current === requestNumber.current) setLoading(false); }
  }
  useEffect(() => {
    alive.current = true;

    setLoading(true);
    void reload();
    const timer = setInterval(() => { if (!document.hidden) void reload(); }, 10000);
    return () => { alive.current = false; requestNumber.current++; clearInterval(timer); };
  }, [organizationId, query, cursor]);

  async function action(work: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await work(); } catch (error) { failure(error); } finally { if (alive.current) setBusy(false); }
  }
  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await action(async () => {
      const response = await api<Enrollment>(`/organizations/${organizationId}/servers`, 'POST', { hostname: form.get('hostname'), os: form.get('os') });
      if (!alive.current) return;
      setEnrollment(response); setCreate(false);
      await reload(); callbacks.current.onChanged();
    });
  }
  async function issue(server: ServerRecord) {
    await action(async () => {
      const response = await api<Enrollment>(`/organizations/${organizationId}/servers/${server.id}/enrollment`, 'POST', {});
      if (!alive.current) return;
      setEnrollment(response); callbacks.current.onChanged();
    });
  }
  async function revoke(server: ServerRecord, decommission = false) {
    if (!confirm(decommission ? `Decommission ${server.hostname}? Agent access will end and new enrollment will be disabled. This does not uninstall the host service.` : `Revoke agent access for ${server.hostname}? Heartbeats and outstanding enrollment tokens will stop being accepted.`)) return;
    await action(async () => {
      await api(`/organizations/${organizationId}/servers/${server.id}/${decommission ? 'decommission' : 'revoke'}`, 'POST', {});
      await reload(); callbacks.current.onChanged();
      if (alive.current) setNotice(decommission ? 'Server decommissioned' : 'Agent access revoked');
    });
  }

  return <>
    <form className="inventory-filters" onSubmit={event => { event.preventDefault(); const form = new FormData(event.currentTarget); setSelected(null); setCursors([null]); setQuery(new URLSearchParams(Array.from(form.entries()).filter(([, value]) => !!value) as [string, string][]).toString()); }}>
      <input name="q" placeholder="Search hostnames" aria-label="Search hostnames" maxLength={100} /><select name="os" aria-label="Operating system"><option value="">All operating systems</option><option>LINUX</option><option>WINDOWS</option></select><select name="status" aria-label="Agent status"><option value="">All statuses</option>{['ONLINE', 'STALE', 'UNKNOWN', 'PENDING_ENROLLMENT', 'AWAITING_HEARTBEAT', 'REVOKED_OR_EXPIRED', 'DECOMMISSIONED'].map(status => <option key={status}>{status}</option>)}</select><select name="groupId" aria-label="Server group"><option value="">All groups</option>{groups.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</select><button className="button secondary">Apply filters</button>
    </form>
    {canManage && <form className="inventory-filters" onSubmit={event => { event.preventDefault(); const formElement = event.currentTarget; const name = new FormData(formElement).get('name'); void action(async () => { await api(`/organizations/${organizationId}/groups`, 'POST', { name }); formElement.reset(); await reload(); }); }}><input name="name" required maxLength={80} placeholder="New server group" aria-label="New server group name" /><button className="button secondary" disabled={busy}>Create group</button></form>}
    {selected && servers.find(server => server.id === selected) && <ServerDrawer key={selected} organizationId={organizationId} server={servers.find(server => server.id === selected)!} groups={groups} canManage={canManage} onClose={() => setSelected(null)} onUpdated={() => reload()} onError={failure} />}
    {error && <div className="message error" role="alert">{error}<button aria-label="Dismiss server error" onClick={() => setError('')}><X size={16} /></button></div>}
    {notice && <div className="message success" role="status">{notice}</div>}
    <section className="panel"><div className="panel-heading"><div><h2>Registered servers · this page <span className="count">{servers.filter(server => !server.decommissioned_at).length}</span></h2><p>Signed heartbeats every 30 seconds · view refreshes every 10 seconds · paginated inventory</p></div><div className="button-row"><button className="button secondary compact" disabled={busy} onClick={() => action(() => reload())} aria-label="Refresh servers"><RefreshCw size={15} /></button>{canManage && <button className="button primary compact" disabled={busy} onClick={() => { setCreate(true); setError(''); }}><Plus size={16} /> Register server</button>}</div></div>
      {loading ? <div className="empty"><span className="spinner" /><p>Loading server inventory…</p></div> : servers.length ? <div className="table-wrap"><table><thead><tr><th>Server</th><th>Health / resources</th><th>Agent status</th><th>Last heartbeat</th><th>Uptime</th><th>Credential expires</th>{canManage && <th>Actions</th>}</tr></thead><tbody>{servers.map(server => <tr key={server.id} className="clickable-server-row" tabIndex={0} aria-label={"View details for " + server.hostname} onClick={event => { if (!(event.target as HTMLElement).closest("button,a,input,select")) setSelected(server.id); }} onKeyDown={event => { if (event.target === event.currentTarget && ["Enter", " "].includes(event.key)) { event.preventDefault(); setSelected(server.id); } }}><td><div className="member-cell"><span className="avatar"><Server size={17} /></span><div><button className="text-button" onClick={() => setSelected(server.id)}>{server.hostname}</button><span>{server.architecture || 'Architecture unavailable'} · {server.logical_cpu_count ?? '?'} CPUs</span><span>{server.groups.map(group => group.name).join(', ')}</span><span>{server.os} · {server.agent_version || 'Not enrolled'}</span>{server.os_version && <span>{server.os_version}</span>}</div></div></td><td><span className={`badge ${server.health.state === 'CRITICAL' ? 'red' : server.health.state === 'WARNING' ? 'amber' : server.health.state === 'HEALTHY' ? 'green' : ''}`}>{server.health.state.replaceAll('_', ' ')}</span><div className="muted">CPU {percent(server.health.resources.CPU)} · RAM {percent(server.health.resources.MEMORY)} · Disk {percent(server.health.resources.DISK)}</div></td><td><span className={`badge ${server.status === 'ONLINE' ? 'green' : server.status === 'STALE' ? 'amber' : ''}`}>{server.status.replaceAll('_', ' ')}</span></td><td className="muted">{date(server.last_heartbeat_at)}</td><td className="muted">{uptime(server.uptime_seconds)}</td><td className="muted">{server.credential_expires_at ? date(server.credential_expires_at) : 'No active credential'}</td>{canManage && <td>{!server.decommissioned_at && <div className="agent-actions"><button className="text-button" disabled={busy} onClick={() => issue(server)}>New enrollment</button><button className="text-button danger" disabled={busy} onClick={() => revoke(server)}>Revoke access</button><button className="text-button danger" disabled={busy} onClick={() => revoke(server, true)}>Decommission</button></div>}</td>}</tr>)}</tbody></table></div> : <div className="empty"><Server size={32} /><h3>Connect your first server</h3><p>Register a Linux or Windows host, then enroll its native agent.</p>{canManage && <button className="button primary" disabled={busy} onClick={() => setCreate(true)}><Plus size={15} /> Register server</button>}</div>}
    </section>
    <div className="pagination-bar"><span>Page {cursors.length} · {servers.length} hosts · 10 per page</span><div className="button-row"><button className="button secondary" disabled={busy || loading || cursors.length === 1} onClick={() => { setSelected(null); setCursors(value => value.slice(0, -1)); }}>Previous</button><button className="button secondary" disabled={busy || loading || !nextCursor} onClick={() => { setSelected(null); setCursors(value => [...value, nextCursor]); }}>Next 10</button></div></div>
    <div className="info-note"><ShieldCheck size={18} /><p>Prototype agents report inventory, resource metrics and startup events. Host management requires an upgraded agent and explicit host configuration. ONLINE means a recent authenticated report, not an independent host security attestation.</p></div>
    <section className="panel agent-guide section-gap"><h2>Enrollment and health</h2><div><p><strong>1. Register</strong><span>An Owner or Administrator creates a server and receives a ten-minute enrollment token.</span></p><p><strong>2. Start the agent</strong><span>Save the token in a protected file. The native agent generates and stores its own signing key.</span></p><p><strong>3. Verify heartbeat</strong><span>ONLINE within 90 seconds; STALE after 90 seconds; UNKNOWN after five minutes without a report.</span></p></div><p className="muted">Issuing a replacement token revokes older tokens. The old signing credential remains active until a fresh key successfully enrolls. Thirty-day credentials require administrator-assisted re-enrollment in this prototype.</p></section>
    {(create || enrollment) && <div className="modal-overlay"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="agent-modal-title"><button className="modal-close" aria-label="Close agent dialog" disabled={busy} onClick={() => { setCreate(false); setEnrollment(null); }}><X size={20} /></button><span className="feature-icon"><KeyRound size={24} /></span><h2 id="agent-modal-title">{enrollment ? 'Enroll your agent' : 'Register a server'}</h2>
      {error && <div className="message error" role="alert">{error}</div>}
      {enrollment ? <><p className="muted">Copy this token now. It is shown once and expires at {date(enrollment.expiresAt)}. Share it only with the intended host.</p><label className="field"><span>Server ID</span><code className="secret">{enrollment.serverId}</code></label><label className="field"><span>Enrollment token</span><code className="secret">{enrollment.enrollmentToken}</code></label><button className="button primary wide" onClick={() => action(async () => { await navigator.clipboard.writeText(enrollment.enrollmentToken); setNotice('Enrollment token copied. Save it in a private token file.'); })}><Copy size={15} /> Copy enrollment token</button><p className="agent-token-note">Use the instructions in <code>docs/agent-installation.md</code>. On Linux, use file mode 0600 and a 0700 state directory. On Windows, restrict token-file ACLs to the service identity, SYSTEM and Administrators. Never put the token in a command-line argument.</p></> : <form onSubmit={register}><p className="muted agent-form-note">Choose the host operating system. No inbound agent port is required.</p><label className="field"><span>Hostname</span><input name="hostname" required minLength={1} maxLength={253} placeholder="production-web-01" autoFocus /></label><label className="field"><span>Operating system</span><select name="os" defaultValue="LINUX"><option value="LINUX">Linux</option><option value="WINDOWS">Windows Server</option></select></label><button className="button primary wide" disabled={busy}>{busy ? 'Registering…' : 'Register & create enrollment token'}<Plus size={15} /></button></form>}
    </section></div>}
  </>;
}
