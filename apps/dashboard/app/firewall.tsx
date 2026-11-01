'use client';

import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Shield, Plus, RefreshCw } from 'lucide-react';
import { api } from '../lib/api'; import { RolloutRequest } from './rollouts';

type Policy = { id: string; name: string; version_id: string; version: number; state: string };
type Rule = { id: string; action: string; direction: string; cidr: string; protocol: string; portStart: number | null; portEnd: number | null; expiresAt: string | null; reason: string };
type Version = { id: string; version: number; state: string; checksum: string; sealed_at: string | null; target: { type: string; id: string; serverIds: string[] }; rules: Rule[] };
type Detail = { policy: Policy; versions: Version[]; selected: Version };
type Page<T> = { items: T[]; nextCursor: string | null };
type Audit = { id: string; action: string; actor_name: string | null; created_at: string; metadata: Record<string, unknown> };
type Preview = { checksum: string; generatedAt: string; targetDrift: boolean; currentTargets: { id: string; hostname: string; os: string }[]; snapshotTargets: { id: string; hostname: string; os: string; decommissioned_at: string | null }[]; classification: { highImpact: boolean; reasons: string[]; blockers: string[] }; plans: { adapter: string; namespace: string; warnings: string[]; artifact?: string; commands?: unknown; inspection: string[] }[]; packet: { managedVerdict: string; matchedRuleIds: string[]; scope: string } | null; expiredRuleIds: string[]; comparison: unknown };

export default function Firewall({ organizationId, canManage, onError }: { organizationId: string; canManage: boolean; onError: (error: unknown) => void }) {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [targets, setTargets] = useState<{ id: string; hostname: string }[]>([]);
  const [groups, setGroups] = useState<{ id: string; name: string }[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [target, setTarget] = useState('');
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [preview, setPreview] = useState<Preview | null>(null);
  const [history, setHistory] = useState<Audit[]>([]);
  const [historyCursor, setHistoryCursor] = useState<string | null>(null);
  const alive = useRef(true); const selection = useRef(0);
  const callback = useRef(onError); callback.current = onError;
  const base = `/organizations/${organizationId}/firewall/policies`;
  const editable = canManage && (creating || detail?.selected.state === 'DRAFT');
  function failure(error: unknown) { if (alive.current) { setError(error instanceof Error ? error.message : 'Firewall request failed'); callback.current(error); } }
  async function list(append = false) {
    const page = await api<Page<Policy>>(`${base}${append && cursor ? `?cursor=${cursor}` : ''}`);
    if (alive.current) { setPolicies(previous => append ? [...previous, ...page.items] : page.items); setCursor(page.nextCursor); }
  }
  async function select(policyId: string, versionId?: string) {
    const request = ++selection.current;
    const [next, events] = await Promise.all([api<Detail>(`${base}/${policyId}${versionId ? `?versionId=${versionId}` : ''}`), api<Page<Audit>>(`${base}/${policyId}/history`)]);
    if (!alive.current || request !== selection.current) return;
    setDetail(next); setRules(next.selected.rules); setTarget(`${next.selected.target.type}:${next.selected.target.id}`); setHistory(events.items); setHistoryCursor(events.nextCursor); setPreview(null); setCreating(false);
  }
  useEffect(() => {
    alive.current = true;
    void Promise.all([list(), api<Page<{ id: string; hostname: string }>>(`/organizations/${organizationId}/inventory?limit=100`), api<{ id: string; name: string }[]>(`/organizations/${organizationId}/groups`)]).then(([, servers, groups]) => { if (alive.current) { setTargets(servers.items); setGroups(groups); } }).catch(failure);
    return () => { alive.current = false; selection.current++; };
  }, [organizationId]);
  async function work(task: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('');
    try { await task(); } catch (error) { failure(error); } finally { if (alive.current) setBusy(false); }
  }
  function update(index: number, patch: Partial<Rule>) { setRules(previous => previous.map((rule, position) => position === index ? { ...rule, ...patch } : rule)); setPreview(null); }
  function addRule() { setRules(previous => [...previous, { id: crypto.randomUUID(), cidr: '192.0.2.0/24', action: 'BLOCK', direction: 'INBOUND', protocol: 'TCP', portStart: 8080, portEnd: 8080, expiresAt: null, reason: '' }]); setPreview(null); }
  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget); const [type, id] = target.split(':');
    await work(async () => {
      const body = { target: { type, id }, rules };
      const result = creating ? await api<{ policyId: string; versionId: string }>(base, 'POST', { ...body, name: form.get('name') }) : await api<{ policyId: string; versionId: string }>(`${base}/${detail!.policy.id}/versions/${detail!.selected.id}`, 'PATCH', { ...body, expectedChecksum: detail!.selected.checksum });
      await list(); await select(result.policyId, result.versionId); setNotice('Draft saved. Preview the saved version before submission.');
    });
  }
  async function loadPreview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    await work(async () => {
      const address = String(form.get('address') || ''); const protocol = String(form.get('protocol'));
      const compareVersionId = String(form.get('compareVersionId') || '');
      const result = await api<Preview>(`${base}/${detail!.policy.id}/versions/${detail!.selected.id}/preview`, 'POST', { expectedChecksum: detail!.selected.checksum, ...(address ? { packet: { address, protocol, direction: form.get('direction'), port: protocol === 'ICMP' ? null : Number(form.get('port')) } } : {}), ...(compareVersionId ? { compareVersionId } : {}) });
      if (alive.current) { setPreview(result); const events = await api<Page<Audit>>(`${base}/${detail!.policy.id}/history`); if (alive.current) { setHistory(events.items); setHistoryCursor(events.nextCursor); } }
    });
  }
  const dirty = detail && (JSON.stringify(rules) !== JSON.stringify(detail.selected.rules) || target !== `${detail.selected.target.type}:${detail.selected.target.id}`);
  return <>
    <div className="info-note"><Shield size={22} /><p>Planning only. Native adapters compile nftables and Windows NetSecurity plans; they do not change host firewalls. Submission seals a version for future distinct-person approval. External policies can still deny allowed traffic.</p></div>
    {error && <div className="message error" role="alert">{error}</div>}{notice && <div className="message success" role="status">{notice}</div>}
    <section className="panel section-gap"><div className="panel-heading"><div><h2>Firewall policies</h2><p>Versioned drafts · BLOCK precedence · immutable submitted content</p></div><div className="button-row"><button className="button secondary compact" disabled={busy} onClick={() => work(() => list())}><RefreshCw size={15} />Refresh</button>{canManage && <button className="button primary compact" disabled={busy} onClick={() => { selection.current++; setCreating(true); setDetail(null); setRules([]); setTarget(''); setPreview(null); setHistory([]); }}><Plus size={15} />New policy</button>}</div></div>
      <div className="table-wrap"><table><thead><tr><th>Policy</th><th>Version</th><th>State</th></tr></thead><tbody>{policies.map(policy => <tr key={policy.id}><td><button className="text-button" disabled={busy} onClick={() => work(() => select(policy.id))}>{policy.name}</button></td><td>v{policy.version}</td><td><span className={`badge ${policy.state === 'DRAFT' ? 'amber' : ''}`}>{policy.state.replaceAll('_', ' ')}</span></td></tr>)}</tbody></table></div>{!policies.length && <div className="empty"><p>No firewall policies yet. Create a targeted draft to get started.</p></div>}{cursor && <div className="pagination-bar"><button className="button secondary" disabled={busy} onClick={() => work(() => list(true))}>Load more policies</button></div>}
    </section>
    {(creating || detail) && <section className="panel section-gap"><div className="panel-heading"><div><h2>{creating ? 'Create a firewall policy' : detail!.policy.name}</h2><p>{creating ? 'Rules apply to one server or one group' : `Version ${detail!.selected.version} · ${detail!.selected.state}`}</p></div>{detail && <select aria-label="Policy version" value={detail.selected.id} disabled={busy} onChange={event => work(() => select(detail.policy.id, event.target.value))}>{detail.versions.map(version => <option key={version.id} value={version.id}>v{version.version} · {version.state}</option>)}</select>}</div>
      <form className="firewall-editor" onSubmit={save}>
        {creating && <label className="field"><span>Policy name</span><input name="name" required minLength={2} maxLength={120} /></label>}
        <label className="field"><span>Target (inventory selector shows first 100 hosts)</span><select required value={target} disabled={!editable || busy} onChange={event => { setTarget(event.target.value); setPreview(null); }}><option value="">Choose one target</option>{detail && !targets.some(server => `SERVER:${server.id}` === target) && !groups.some(group => `GROUP:${group.id}` === target) && <option value={target}>Saved target {target}</option>}<optgroup label="Servers">{targets.map(server => <option key={server.id} value={`SERVER:${server.id}`}>{server.hostname}</option>)}</optgroup><optgroup label="Groups">{groups.map(group => <option key={group.id} value={`GROUP:${group.id}`}>{group.name}</option>)}</optgroup></select></label>
        <p className="muted">Remote CIDR is source for inbound and destination for outbound. Ports are destination ports. ICMP has no ports. Non-network CIDRs, hostnames and ambiguous addresses are rejected.</p>
        {rules.map((rule, index) => <fieldset className="firewall-rule" key={rule.id} disabled={!editable || busy}><legend>Rule {index + 1}</legend><div className="firewall-fields"><label className="field"><span>Action</span><select value={rule.action} onChange={event => update(index, { action: event.target.value })}><option>BLOCK</option><option>ALLOW</option></select></label><label className="field"><span>Direction</span><select value={rule.direction} onChange={event => update(index, { direction: event.target.value })}><option>INBOUND</option><option>OUTBOUND</option></select></label><label className="field"><span>Remote CIDR</span><input required maxLength={64} value={rule.cidr} onChange={event => update(index, { cidr: event.target.value })} /></label><label className="field"><span>Protocol</span><select value={rule.protocol} onChange={event => update(index, { protocol: event.target.value, portStart: event.target.value === 'ICMP' ? null : 443, portEnd: event.target.value === 'ICMP' ? null : 443 })}><option>TCP</option><option>UDP</option><option>ICMP</option></select></label>{rule.protocol !== 'ICMP' && <><label className="field"><span>Port start</span><input type="number" min={1} max={65535} required value={rule.portStart ?? ''} onChange={event => update(index, { portStart: Number(event.target.value) })} /></label><label className="field"><span>Port end</span><input type="number" min={1} max={65535} required value={rule.portEnd ?? ''} onChange={event => update(index, { portEnd: Number(event.target.value) })} /></label></>}</div><label className="field"><span>Expiration (UTC ISO timestamp; blank means none)</span><input placeholder="2026-10-30T12:00:00.000Z" value={rule.expiresAt || ''} onChange={event => update(index, { expiresAt: event.target.value || null })} /></label><label className="field"><span>Reason</span><input required minLength={3} maxLength={1000} value={rule.reason} onChange={event => update(index, { reason: event.target.value })} /></label>{editable && <button type="button" className="text-button danger" onClick={() => { setRules(previous => previous.filter((_, position) => position !== index)); setPreview(null); }}>Remove rule</button>}</fieldset>)}
        {editable && <div className="button-row"><button type="button" className="button secondary" disabled={busy || rules.length >= 50} onClick={addRule}><Plus size={15} />Add rule</button><button className="button primary" disabled={busy || !rules.length}>{creating ? 'Create draft' : 'Save draft'}</button></div>}
      </form>
      {detail && <div className="firewall-editor"><code className="secret">SHA-256 {detail.selected.checksum}</code>{dirty && <p className="message error">Unsaved changes. Save before preview or submission.</p>}<form className="inventory-filters" onSubmit={loadPreview}><input name="address" placeholder="Packet IP (optional)" aria-label="Packet remote IP" /><select name="direction" aria-label="Packet direction"><option>INBOUND</option><option>OUTBOUND</option></select><select name="protocol" aria-label="Packet protocol"><option>TCP</option><option>UDP</option><option>ICMP</option></select><input name="port" type="number" defaultValue={8080} min={1} max={65535} aria-label="Packet destination port" /><select name="compareVersionId" aria-label="Compare with version"><option value="">No version comparison</option>{detail.versions.filter(version => version.id !== detail.selected.id).map(version => <option key={version.id} value={version.id}>Compare v{version.version}</option>)}</select><button className="button secondary" disabled={busy || !!dirty}>Preview saved version</button></form>
        {canManage && <div className="button-row"><button className="button secondary" disabled={busy || !!dirty} onClick={() => work(async () => { const next = await api<{ versionId: string }>(`${base}/${detail.policy.id}/versions/${detail.selected.id}/revise`, 'POST', {}); await list(); await select(detail.policy.id, next.versionId); })}>Create new draft version</button>{detail.selected.state === 'DRAFT' && <button className="button primary" disabled={busy || !!dirty || !preview || preview.targetDrift || !!preview.classification.blockers.length} onClick={() => { if (confirm('Seal this exact version for future approval? Submitted rules cannot be edited. No firewall changes will run.')) void work(async () => { await api(`${base}/${detail.policy.id}/versions/${detail.selected.id}/submit`, 'POST', { expectedChecksum: detail.selected.checksum }); await list(); await select(detail.policy.id, detail.selected.id); setNotice('Version sealed as pending approval. Live deployment remains disabled.'); }); }}>Seal & submit for approval</button>}</div>}
      </div>}
    </section>}
    {detail && canManage && ['PENDING_APPROVAL', 'APPROVED'].includes(detail.selected.state) && <RolloutRequest key={detail.selected.id} organizationId={organizationId} versionId={detail.selected.id} checksum={detail.selected.checksum} serverIds={detail.selected.target.serverIds} onError={failure} />}{preview && <section className="panel section-gap"><div className="panel-heading"><div><h2>Native adapter preview · not executable</h2><p>{new Date(preview.generatedAt).toLocaleString()} · {preview.snapshotTargets.length} saved targets · {preview.classification.highImpact ? 'HIGH IMPACT' : 'Standard impact'}</p></div><span className="badge amber">APPLY DISABLED</span></div><div className="firewall-editor">{preview.targetDrift && <div className="message error">Target membership changed. Save and preview a new draft before submission.</div>}{[...preview.classification.reasons, ...preview.classification.blockers].map(message => <p key={message} className="list-note">{message}</p>)}<p className="muted">Saved snapshot: {preview.snapshotTargets.map(server => `${server.hostname} (${server.os}${server.decommissioned_at ? ', decommissioned' : ''})`).join(', ')} · Current target membership: {preview.currentTargets.length}</p>{preview.packet && <div className="info-note"><p><strong>Managed verdict: {preview.packet.managedVerdict}</strong><br />{preview.packet.scope}<br />Matched rules: {preview.packet.matchedRuleIds.join(', ') || 'None'}</p></div>}{preview.expiredRuleIds.length > 0 && <p>Expired and excluded: {preview.expiredRuleIds.join(', ')}</p>}{preview.plans.map(plan => <div key={plan.adapter}><h3>{plan.adapter}</h3><ul>{plan.warnings.map(warning => <li key={warning}>{warning}</li>)}</ul><pre className="native-preview">{plan.artifact || JSON.stringify(plan.commands, null, 2)}</pre><h4>Required inspection gates</h4><ul>{plan.inspection.map(check => <li key={check}>{check}</li>)}</ul></div>)}{preview.comparison != null && <><h3>Version diff (rule content, excluding IDs)</h3><pre className="native-preview">{JSON.stringify(preview.comparison, null, 2)}</pre></>}</div></section>}
    {detail && <section className="panel section-gap"><div className="panel-heading"><div><h2>Policy audit history</h2><p>Append-only actor, version and checksum records</p></div></div><div className="table-wrap"><table><thead><tr><th>Action</th><th>Actor</th><th>Time</th><th>Version / checksum</th></tr></thead><tbody>{history.map(event => <tr key={event.id}><td>{event.action}</td><td>{event.actor_name || 'System'}</td><td>{new Date(event.created_at).toLocaleString()}</td><td><code>{String(event.metadata.versionId || '')}<br />{String(event.metadata.checksum || '')}</code></td></tr>)}</tbody></table></div>{historyCursor && <div className="pagination-bar"><button className="button secondary" disabled={busy} onClick={() => work(async () => { const next = await api<Page<Audit>>(`${base}/${detail.policy.id}/history?cursor=${historyCursor}`); if (alive.current) { setHistory(previous => [...previous, ...next.items]); setHistoryCursor(next.nextCursor); } })}>Older history</button></div>}</section>}
  </>;
}
