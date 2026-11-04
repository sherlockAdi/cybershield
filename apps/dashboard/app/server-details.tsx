'use client';
import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, Server, LayoutDashboard, Boxes, Shield, Activity, ChartNoAxesCombined, History } from 'lucide-react';
import { ServerTelemetry, percent, type InventoryRecord, type Group } from './telemetry';
import HostManagement from './host-management';
import ServerActivity from './server-activity';

const tabs = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'applications', label: 'Applications', icon: Boxes },
  { id: 'access', label: 'IP access', icon: Shield },
  { id: 'activity', label: 'Login & network activity', icon: Activity },
  { id: 'metrics', label: 'Metrics & events', icon: ChartNoAxesCombined },
  { id: 'history', label: 'Action history', icon: History },
] as const;
type Tab = typeof tabs[number]['id'];
export default function ServerDetails(props: { organizationId: string; server: InventoryRecord; groups: Group[]; canManage: boolean; onClose: () => void; onUpdated: () => Promise<void>; onError: (error: unknown) => void }) {
  const { server, onClose } = props;
  const [tab, setTab] = useState<Tab>('overview');
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); window.scrollTo({ top: 0 }); }, []);
  const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'Not reported';
  const seconds = Number(server.uptime_seconds || 0);
  const facts = [['Operating system', server.os_version || server.os], ['Architecture', server.architecture || 'Not reported'], ['Logical CPUs', String(server.logical_cpu_count ?? 'Not reported')], ['Agent version', server.agent_version || 'Not enrolled'], ['Last heartbeat', date(server.last_heartbeat_at)], ['Uptime', server.uptime_seconds == null ? 'Unavailable' : `${Math.floor(seconds / 86400)}d ${Math.floor(seconds % 86400 / 3600)}h`], ['Credential expires', date(server.credential_expires_at)], ['Server ID', server.id]];
  return <section className="server-details-page">
    <button className="text-button server-back" onClick={onClose}><ArrowLeft size={17} /> Back to servers</button>
    <header className="server-details-hero"><div className="server-identity"><span className="feature-icon"><Server size={28} /></span><div><span className="eyebrow">SERVER WORKSPACE</span><h2 ref={heading} tabIndex={-1}>{server.hostname}</h2><p>{server.os_version || server.os} · {server.architecture || 'Architecture unavailable'}</p></div></div><div className="server-status"><span className={`badge ${server.status === 'ONLINE' ? 'green' : 'amber'}`}>{server.status.replaceAll('_', ' ')}</span><small>Refreshes every 10 seconds</small></div></header>
    <div className="server-tabs" role="tablist" aria-label="Server sections">{tabs.map((item, index) => <button key={item.id} id={`server-tab-${item.id}`} role="tab" aria-selected={tab === item.id} aria-controls="server-tab-panel" tabIndex={tab === item.id ? 0 : -1} onClick={() => setTab(item.id)} onKeyDown={event => { let next = index; if (event.key === 'ArrowRight') next = (index + 1) % tabs.length; else if (event.key === 'ArrowLeft') next = (index + tabs.length - 1) % tabs.length; else if (event.key === 'Home') next = 0; else if (event.key === 'End') next = tabs.length - 1; else return; event.preventDefault(); setTab(tabs[next].id); document.getElementById(`server-tab-${tabs[next].id}`)?.focus(); }}><item.icon size={17} />{item.label}</button>)}</div>
    <div id="server-tab-panel" role="tabpanel" aria-labelledby={`server-tab-${tab}`} className="server-tab-panel">
      {tab === 'overview' && <><div className="server-resource-cards">{[['CPU usage', server.health.resources.CPU], ['Memory usage', server.health.resources.MEMORY], ['Disk usage', server.health.resources.DISK]].map(([label, value]) => <article key={String(label)}><span>{label}</span><strong>{percent(value as number | null)}</strong><progress max={100} value={typeof value === 'number' ? value : 0} aria-label={String(label)} /><small>{server.health.state.replaceAll('_', ' ')}</small></article>)}</div><section className="panel"><div className="panel-heading"><div><h2>Server information</h2><p>Host identity, enrollment and latest heartbeat</p></div></div><dl className="server-details-facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></section><div className="server-quick-links"><button onClick={() => setTab('applications')}><Boxes size={22} /><strong>Manage applications</strong><span>View services, containers and available actions</span></button><button onClick={() => setTab('access')}><Shield size={22} /><strong>Manage IP access</strong><span>Review blocks and control inbound access</span></button><button onClick={() => setTab('activity')}><Activity size={22} /><strong>Review server activity</strong><span>Inspect logins and network observations</span></button></div></>}
      {(tab === 'applications' || tab === 'access' || tab === 'history') && <HostManagement key={tab} organizationId={props.organizationId} serverId={server.id} os={server.os} canManage={props.canManage} onError={props.onError} view={tab} />}
      {tab === 'activity' && <ServerActivity organizationId={props.organizationId} serverId={server.id} onError={props.onError} />}
      {tab === 'metrics' && <ServerTelemetry {...props} />}
    </div>
  </section>;
}
