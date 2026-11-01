'use client';
import { useEffect, useRef } from 'react';
import { Server, X } from 'lucide-react';
import { ServerTelemetry, type InventoryRecord, type Group } from './telemetry';

export default function ServerDrawer({ organizationId, server, groups, canManage, onClose, onUpdated, onError }: { organizationId: string; server: InventoryRecord; groups: Group[]; canManage: boolean; onClose: () => void; onUpdated: () => Promise<void>; onError: (error: unknown) => void }) {
  const dialog = useRef<HTMLElement>(null); const close = useRef(onClose); close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null; const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden'; dialog.current?.querySelector<HTMLButtonElement>('[data-drawer-close]')?.focus();
    function keyboard(event: KeyboardEvent) {
      if (event.key === 'Escape') { event.preventDefault(); close.current(); return; }
      if (event.key !== 'Tab') return;
      const elements = Array.from(dialog.current?.querySelectorAll<HTMLElement>('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),summary,[tabindex]:not([tabindex="-1"])') || []).filter(element => element.getClientRects().length);
      const first = elements[0], last = elements[elements.length - 1];
      if (!first) { event.preventDefault(); dialog.current?.focus(); }
      else if (event.shiftKey && (document.activeElement === first || !dialog.current?.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !dialog.current?.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
    }
    document.addEventListener('keydown', keyboard);
    return () => { document.body.style.overflow = overflow; document.removeEventListener('keydown', keyboard); if (previous?.isConnected) previous.focus(); };
  }, []);
  const date = (value: string | null) => value ? new Date(value).toLocaleString() : 'Not reported';
  const seconds = Number(server.uptime_seconds || 0);
  const facts = [['Operating system', server.os_version || server.os], ['Agent version', server.agent_version || 'Not enrolled'], ['Agent status', server.status.replaceAll('_', ' ')], ['Health', server.health.state.replaceAll('_', ' ')], ['Last heartbeat', date(server.last_heartbeat_at)], ['Uptime', server.uptime_seconds == null ? 'Unavailable' : Math.floor(seconds / 86400) + ' days ' + Math.floor(seconds % 86400 / 3600) + ' hours'], ['Credential expires', date(server.credential_expires_at)], ['Server ID', server.id]];
  return <div className="server-drawer-overlay"><button type="button" tabIndex={-1} className="server-drawer-backdrop" aria-label="Close server details" onClick={onClose} /><aside ref={dialog} className="server-drawer" role="dialog" aria-modal="true" aria-labelledby="server-drawer-title" tabIndex={-1}>
    <header className="server-drawer-header"><span className="feature-icon"><Server size={22} /></span><div><span className="eyebrow">SERVER DETAILS</span><h2 id="server-drawer-title">{server.hostname}</h2><p>Activity, network observations and host health</p></div><button type="button" data-drawer-close className="server-drawer-close" aria-label="Close server details" onClick={onClose}><X size={23} /></button></header>
    <div className="server-drawer-scroll"><section className="server-drawer-overview"><dl className="server-facts">{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></section><ServerTelemetry organizationId={organizationId} server={server} groups={groups} canManage={canManage} onClose={onClose} onUpdated={onUpdated} onError={onError} /></div>
  </aside></div>;
}
