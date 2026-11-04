'use client';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api } from '../lib/api';

type Application = { id: string; name: string; kind: string; state: string; instance: string; details: string; stoppable: boolean };
type Rule = { id: string; ip: string; scope: string; ports: number[] };
type Report = { snapshot: { applications: Application[]; rules: Rule[]; firewall: boolean; errors: string[]; truncated: boolean } | null; receivedAt: string | null; stale: boolean; commands: { id: string; operation: string; state: string; message: string | null; created_at: string }[] };
function Pages({ page, count, change }: { page: number; count: number; change: (page: number) => void }) { return <div className="pagination-bar"><span>Page {page + 1} · {count} records · 10 per page</span><div className="button-row"><button className="button secondary" disabled={!page} onClick={() => change(page - 1)}>Previous</button><button className="button secondary" disabled={(page + 1) * 10 >= count} onClick={() => change(page + 1)}>Next 10</button></div></div>; }
export default function HostManagement({ organizationId, serverId, os, canManage, onError, view = 'applications' }: { organizationId: string; serverId: string; os: string; canManage: boolean; onError: (error: unknown) => void; view?: 'applications' | 'access' | 'history' }) {
  const [report, setReport] = useState<Report | null>(null), [busy, setBusy] = useState(false), [message, setMessage] = useState('');
  const [page, setPage] = useState(0), [rulePage, setRulePage] = useState(0), [commandPage, setCommandPage] = useState(0), [scope, setScope] = useState('LOGIN');
  const ref = useRef(onError); ref.current = onError;
  const endpoint = `/organizations/${organizationId}/servers/${serverId}`;
  const generation = useRef(0);
  useEffect(() => {
    let active = true; const current = ++generation.current;
    async function load() { try { const next = await api<Report>(`${endpoint}/management`); if (active && generation.current === current) { setReport(next); setPage(p => Math.min(p, Math.max(0, Math.ceil((next.snapshot?.applications.length || 0) / 10) - 1))); setRulePage(p => Math.min(p, Math.max(0, Math.ceil((next.snapshot?.rules.length || 0) / 10) - 1))); } } catch (error) { if (active) ref.current(error); } }
    setReport(null); void load(); const timer = setInterval(() => { if (!document.hidden) void load(); }, 10000);
    return () => { active = false; generation.current++; clearInterval(timer); };
  }, [endpoint]);
  const pending = report?.commands.some(item => ['PENDING','DISPATCHED'].includes(item.state));
  const disabled = busy || !!pending || !report || report.stale;
  async function command(body: object, confirmation: string) {
    if (!confirm(confirmation)) return;
    const current = generation.current; setBusy(true); setMessage('');
    try { await api(`${endpoint}/commands`, 'POST', body); if (current !== generation.current) return; setMessage('Action queued. Waiting for the server to confirm the result.'); setReport(await api<Report>(`${endpoint}/management`)); }
    catch (error) { if (current === generation.current) ref.current(error); }
    finally { if (current === generation.current) setBusy(false); }
  }
  function block(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget), ip = String(form.get('ip')).trim();
    const ports = String(form.get('ports') || '').split(',').filter(value => value.trim()).map(Number);
    if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535) || ports.length > 16 || scope === 'LOGIN' && !ports.length) { setMessage('Enter up to 16 valid ports, separated by commas. Login blocking requires SSH/RDP ports.'); return; }
    void command({ operation: 'BLOCK_IP', ip, scope, ports }, `Block inbound ${scope === 'LOGIN' ? 'login-port' : 'TCP'} traffic from ${ip}${ports.length ? ' on ports ' + ports.join(', ') : ' on all TCP ports'}? This can disconnect matching sessions.`);
  }
  const snapshot = report?.snapshot;
  return <section className="section-gap"><div className="panel-heading"><div><h2>{view === 'applications' ? 'Applications' : view === 'access' ? 'IP access' : 'Action history'}</h2><p>{report?.receivedAt ? `Last host report: ${new Date(report.receivedAt).toLocaleString()}${report.stale ? ' · STALE' : ''}` : 'Waiting for a management-enabled agent'}</p></div></div>
    {message && <p role="status" className="message success">{message}</p>}
    {!snapshot ? <p className="list-note">Upgrade the host agent and configure its management helper to report applications and enable host actions.</p> : <>
      {snapshot.errors.map((error, index) => <p className="message error" key={index}>{error}</p>)}
      {view === 'applications' && <><h3>Applications · {snapshot.applications.filter(app => ['running','active','started'].includes(app.state.toLowerCase())).length} running / {snapshot.applications.length} reported</h3><p className="muted">Services, containers and IIS sites/pools are separate managed resources. {snapshot.truncated ? 'Inventory is truncated at 200 resources; the count is a lower bound.' : ''}</p>
      <div className="table-wrap"><table><thead><tr><th>Application</th><th>Type</th><th>Status</th><th>Details</th><th>Action</th></tr></thead><tbody>{snapshot.applications.slice(page * 10, page * 10 + 10).map(app => <tr key={app.id}><td><strong>{app.name}</strong><br /><small>{app.id}</small></td><td>{app.kind.replaceAll('_',' ')}</td><td>{app.state}</td><td>{app.details || 'Not reported'}</td><td>{canManage && <button className="text-button danger" disabled={disabled || !app.stoppable} title={app.stoppable ? 'Stop this application' : 'Stopping is not enabled for this application on the host'} onClick={() => command({ operation: 'STOP_APPLICATION', applicationId: app.id, instance: app.instance }, `Stop ${app.name}? Its users may lose access. Restart policies may start it again.`)}>Stop</button>}</td></tr>)}</tbody></table></div>
      <Pages page={page} count={snapshot.applications.length} change={setPage} /></>}
      {view === 'access' && <><h3>IP blocks</h3><p className="muted">Login blocks apply to the selected SSH/RDP TCP ports on this server. TCP blocks apply to selected ports, or all TCP ports when left blank. Unblock removes only rules created here.</p>
      {canManage && <form className="inventory-filters" onSubmit={block}><input name="ip" required placeholder="IPv4 or IPv6 address" aria-label="IP address to block" /><select aria-label="Block scope" value={scope} onChange={event => setScope(event.target.value)}><option value="LOGIN">Login (SSH/RDP ports)</option><option value="TCP">TCP connections</option></select><input key={scope} name="ports" aria-label="TCP ports, comma separated" placeholder="Ports, e.g. 80,443; blank = all TCP" defaultValue={scope === 'LOGIN' ? os === 'WINDOWS' ? '3389' : '22' : ''} /><button className="button primary" disabled={disabled || !snapshot.firewall}>Block IP</button></form>}
      <div className="table-wrap"><table><thead><tr><th>IP</th><th>Scope</th><th>Ports</th><th>Action</th></tr></thead><tbody>{snapshot.rules.slice(rulePage * 10, rulePage * 10 + 10).map(rule => <tr key={rule.id}><td>{rule.ip}</td><td>{rule.scope}</td><td>{rule.ports.join(', ') || 'All TCP'}</td><td>{canManage && <button className="text-button" disabled={disabled || !snapshot.firewall} onClick={() => command({ operation: 'UNBLOCK_IP', ruleId: rule.id }, `Unblock ${rule.ip} for this rule?`)}>Unblock</button>}</td></tr>)}</tbody></table></div><Pages page={rulePage} count={snapshot.rules.length} change={setRulePage} /></>}
    </>}
    {view === 'history' && !!report?.commands.length && <><h3>Action history · latest 100</h3><div className="table-wrap"><table><thead><tr><th>Requested</th><th>Action</th><th>Status</th><th>Result</th></tr></thead><tbody>{report.commands.slice(commandPage * 10, commandPage * 10 + 10).map(item => <tr key={item.id}><td>{new Date(item.created_at).toLocaleString()}</td><td>{item.operation.replaceAll('_',' ')}</td><td>{item.state}</td><td>{item.message || 'Awaiting agent acknowledgement'}</td></tr>)}</tbody></table></div><Pages page={commandPage} count={report.commands.length} change={setCommandPage} /></>}
    {view === 'history' && report && !report.commands.length && <div className="empty"><h3>No actions yet</h3><p>Requested host actions and their results will appear here.</p></div>}
  </section>;
}
